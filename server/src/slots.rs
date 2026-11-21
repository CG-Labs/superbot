//! Run slots (ADR 0073): how many Bot runs one computer runs at once. Each computer is
//! a pool: a user's machine (capped by its owner's tier, `concurrentRuns`), or this
//! server (capped by `MAX_CONCURRENT_RUNS`). A run past the cap waits its turn, first
//! come first served. Each Bot runs one task at a time, so a Bot waits in a pool at most
//! once, and a Bot that has just run goes behind the Bots already waiting.
//!
//! Slots live only in memory and are held by values that give them back when dropped,
//! on every way a run ends, so none can leak; a restarted botd starts with none held,
//! which is what is running then (machines stop a job when botd's stream to it ends).

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::watch;

/// The pool of runs on this server itself.
pub const SERVER: &str = "server";

/// This server's cap when `MAX_CONCURRENT_RUNS` isn't set, and a machine's when its
/// owner's tier sets none: what a 4 GiB computer holds of the heaviest harness
/// (Hermes Agent, ADR 0070), with room to spare.
pub const DEFAULT_CAP: u32 = 8;

/// `MAX_CONCURRENT_RUNS`: a number of runs at once, or `0`/`off` for no cap.
pub fn parse_cap(v: &str) -> Result<Option<u32>, String> {
    match v.trim() {
        "" => Ok(Some(DEFAULT_CAP)),
        "0" | "off" | "none" => Ok(None),
        n => n.parse::<u32>().map(Some).map_err(|_| format!("MAX_CONCURRENT_RUNS must be a number of runs, or off (got {n:?})")),
    }
}

/// Where a waiting run is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Turn {
    /// `position` 1 is next. `running` runs hold slots now, of `limit`.
    Waiting { position: usize, running: usize, limit: u32 },
    /// It has a slot.
    Go,
}

#[derive(Default)]
pub struct Slots {
    pools: Mutex<HashMap<String, Pool>>,
    next: AtomicU64,
}

#[derive(Default)]
struct Pool {
    /// None: no cap.
    cap: Option<u32>,
    held: Vec<Held>,
    waiting: VecDeque<Waiter>,
}

struct Held {
    ticket: u64,
    bot: String,
}

struct Waiter {
    ticket: u64,
    bot: String,
    turn: watch::Sender<Turn>,
}

impl Pool {
    fn fits(&self) -> bool {
        self.cap.is_none_or(|c| self.held.len() < c as usize)
    }

    /// Lets waiting runs in, oldest first, while they fit, and tells the rest where they are.
    fn pump(&mut self) {
        while self.fits() {
            let Some(w) = self.waiting.pop_front() else { break };
            self.held.push(Held { ticket: w.ticket, bot: w.bot });
            w.turn.send_replace(Turn::Go);
        }
        let (running, limit) = (self.held.len(), self.cap.unwrap_or(u32::MAX));
        for (i, w) in self.waiting.iter().enumerate() {
            let now = Turn::Waiting { position: i + 1, running, limit };
            w.turn.send_if_modified(|t| std::mem::replace(t, now) != now);
        }
    }
}

/// A run's place in a pool. Dropping it gives the slot back and lets the next run in.
#[must_use]
pub struct Slot {
    slots: Arc<Slots>,
    pool: String,
    ticket: u64,
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.slots.leave(&self.pool, self.ticket);
    }
}

/// A run waiting for a slot. Dropping it leaves the line, or gives back a slot it was
/// handed but never took, so a stopped or cancelled wait never holds one.
#[must_use]
pub struct Queued {
    slots: Arc<Slots>,
    pool: String,
    ticket: u64,
    turn: watch::Receiver<Turn>,
    taken: bool,
}

impl std::fmt::Debug for Queued {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Queued({}, {:?})", self.pool, self.turn())
    }
}

impl std::fmt::Debug for Slot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Slot({})", self.pool)
    }
}

impl Queued {
    pub fn turn(&self) -> Turn {
        *self.turn.borrow()
    }

    /// Waits until its place changes, and says where it is then.
    pub async fn changed(&mut self) -> Turn {
        // The sender lives in the pool until this leaves it, so this only ends on a change.
        let _ = self.turn.changed().await;
        self.turn()
    }

    /// Its slot, once its turn is `Go`.
    pub fn slot(mut self) -> Option<Slot> {
        (self.turn() == Turn::Go).then(|| {
            self.taken = true;
            Slot { slots: self.slots.clone(), pool: self.pool.clone(), ticket: self.ticket }
        })
    }

    /// Its slot now, over the cap (`botctl ask`, as `take`'s `lend`), keeping the pool's cap.
    pub fn borrow(mut self) -> Slot {
        let mut pools = self.slots.lock();
        let p = pools.entry(self.pool.clone()).or_default();
        if let Some(i) = p.waiting.iter().position(|w| w.ticket == self.ticket) {
            let w = p.waiting.remove(i).expect("in line");
            p.held.push(Held { ticket: w.ticket, bot: w.bot });
            p.pump();
        }
        drop(pools);
        self.taken = true;
        Slot { slots: self.slots.clone(), pool: self.pool.clone(), ticket: self.ticket }
    }
}

impl Drop for Queued {
    fn drop(&mut self) {
        if !self.taken {
            self.slots.leave(&self.pool, self.ticket);
        }
    }
}

impl Slots {
    /// A slot in `pool` for `bot`'s run, capped at `cap` (None: no cap), or its place in
    /// line. The cap is the pool's from now on, so a tier change applies at the next run.
    /// `lend`: the run is for a Bot whose run in this pool is waiting on it (`botctl ask`),
    /// so it goes in over the cap rather than wait on a slot its asker holds.
    pub fn take(self: &Arc<Self>, pool: &str, cap: Option<u32>, bot: &str, lend: bool) -> Result<Slot, Queued> {
        let ticket = self.next.fetch_add(1, Ordering::Relaxed);
        let mut pools = self.lock();
        let p = pools.entry(pool.to_string()).or_default();
        p.cap = cap;
        if lend || (p.waiting.is_empty() && p.fits()) {
            p.held.push(Held { ticket, bot: bot.to_string() });
            return Ok(Slot { slots: self.clone(), pool: pool.to_string(), ticket });
        }
        let (tx, mut rx) = watch::channel(Turn::Go);
        p.waiting.push_back(Waiter { ticket, bot: bot.to_string(), turn: tx });
        p.pump();
        rx.mark_unchanged();
        let queued = Queued { slots: self.clone(), pool: pool.to_string(), ticket, turn: rx, taken: false };
        drop(pools);
        match queued.turn() {
            Turn::Go => Ok(queued.slot().expect("its turn")),
            Turn::Waiting { .. } => Err(queued),
        }
    }

    fn leave(&self, pool: &str, ticket: u64) {
        let mut pools = self.lock();
        let Some(p) = pools.get_mut(pool) else { return };
        p.held.retain(|h| h.ticket != ticket);
        p.waiting.retain(|w| w.ticket != ticket);
        p.pump();
        if p.held.is_empty() && p.waiting.is_empty() {
            pools.remove(pool);
        }
    }

    /// Whether `bot` holds a slot in `pool` now.
    pub fn holds(&self, pool: &str, bot: &str) -> bool {
        self.lock().get(pool).is_some_and(|p| p.held.iter().any(|h| h.bot == bot))
    }

    /// Runs holding slots in `pool`, and runs waiting there.
    #[cfg(test)]
    pub fn load(&self, pool: &str) -> (usize, usize) {
        self.lock().get(pool).map_or((0, 0), |p| (p.held.len(), p.waiting.len()))
    }

    /// Runs holding slots and runs waiting, across every pool.
    pub fn totals(&self) -> (usize, usize) {
        self.lock().values().fold((0, 0), |(h, w), p| (h + p.held.len(), w + p.waiting.len()))
    }

    /// Where `bot` waits, if it does: its pool and place.
    pub fn waiting(&self, bot: &str) -> Option<(String, Turn)> {
        let pools = self.lock();
        pools.iter().find_map(|(name, p)| p.waiting.iter().find(|w| w.bot == bot).map(|w| (name.clone(), *w.turn.borrow())))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Pool>> {
        self.pools.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slots() -> Arc<Slots> {
        Arc::new(Slots::default())
    }

    fn queued(r: Result<Slot, Queued>) -> Queued {
        match r {
            Ok(_) => panic!("got a slot"),
            Err(q) => q,
        }
    }

    #[test]
    fn the_cap_is_parsed_with_a_default_and_an_off() {
        assert_eq!(parse_cap(""), Ok(Some(DEFAULT_CAP)));
        assert_eq!(parse_cap(" 3 "), Ok(Some(3)));
        assert_eq!(parse_cap("0"), Ok(None));
        assert_eq!(parse_cap("off"), Ok(None));
        assert!(parse_cap("lots").unwrap_err().contains("MAX_CONCURRENT_RUNS"));
        assert!(parse_cap("-1").is_err());
    }

    #[test]
    fn runs_past_the_cap_wait_and_go_in_order() {
        let s = slots();
        let a = s.take("m1", Some(2), "a", false).unwrap();
        let b = s.take("m1", Some(2), "b", false).unwrap();
        let c = queued(s.take("m1", Some(2), "c", false));
        let d = queued(s.take("m1", Some(2), "d", false));
        assert_eq!(c.turn(), Turn::Waiting { position: 1, running: 2, limit: 2 });
        assert_eq!(d.turn(), Turn::Waiting { position: 2, running: 2, limit: 2 });
        assert_eq!(s.load("m1"), (2, 2));
        assert_eq!(s.waiting("d").map(|(p, _)| p).as_deref(), Some("m1"));
        // Another computer's pool is its own.
        let _other = s.take("m2", Some(2), "x", false).unwrap();
        drop(b);
        assert_eq!(c.turn(), Turn::Go);
        assert_eq!(d.turn(), Turn::Waiting { position: 1, running: 2, limit: 2 });
        let c = c.slot().unwrap();
        // A new run goes behind the one waiting, even with a slot about to free up.
        let e = queued(s.take("m1", Some(2), "e", false));
        drop(a);
        assert_eq!(d.turn(), Turn::Go);
        assert_eq!(e.turn(), Turn::Waiting { position: 1, running: 2, limit: 2 });
        let d = d.slot().unwrap();
        drop(c);
        assert_eq!(e.turn(), Turn::Go);
        let e = e.slot().unwrap();
        assert!(s.holds("m1", "d") && s.holds("m1", "e") && !s.holds("m1", "c"));
        drop((d, e));
        assert_eq!(s.load("m1"), (0, 0));
        assert!(s.lock().get("m1").is_none(), "an idle pool is forgotten");
    }

    #[tokio::test]
    async fn a_waiting_run_hears_when_its_place_changes() {
        let s = slots();
        let a = s.take(SERVER, Some(1), "a", false).unwrap();
        let mut b = queued(s.take(SERVER, Some(1), "b", false));
        let mut c = queued(s.take(SERVER, Some(1), "c", false));
        let moved = tokio::spawn(async move { (c.changed().await, c) });
        tokio::task::yield_now().await;
        drop(a);
        assert_eq!(b.changed().await, Turn::Go);
        let (turn, c) = moved.await.unwrap();
        assert_eq!(turn, Turn::Waiting { position: 1, running: 1, limit: 1 });
        drop(b.slot().unwrap());
        assert_eq!(c.turn(), Turn::Go);
    }

    #[test]
    fn leaving_the_line_or_a_handed_slot_never_holds_one() {
        let s = slots();
        let a = s.take("m1", Some(1), "a", false).unwrap();
        let b = queued(s.take("m1", Some(1), "b", false));
        let c = queued(s.take("m1", Some(1), "c", false));
        // Stopped while waiting: it leaves, and the one behind moves up.
        drop(b);
        assert_eq!(c.turn(), Turn::Waiting { position: 1, running: 1, limit: 1 });
        // Handed the slot, then dropped before taking it (stopped as it was let in).
        drop(a);
        assert_eq!(c.turn(), Turn::Go);
        drop(c);
        assert_eq!(s.load("m1"), (0, 0));
        assert!(s.take("m1", Some(1), "d", false).is_ok());
    }

    #[test]
    fn a_slot_is_given_back_when_its_run_panics() {
        let s = slots();
        let held = s.clone();
        let r = std::thread::spawn(move || {
            let _slot = held.take("m1", Some(1), "a", false).unwrap();
            panic!("the run crashed");
        })
        .join();
        assert!(r.is_err());
        assert_eq!(s.load("m1"), (0, 0));
        assert!(s.take("m1", Some(1), "b", false).is_ok());
    }

    #[test]
    fn a_bigger_cap_lets_waiting_runs_in_and_none_means_no_cap() {
        let s = slots();
        let _a = s.take("m1", Some(1), "a", false).unwrap();
        let b = queued(s.take("m1", Some(1), "b", false));
        // The owner moved to a bigger plan: the next run brings the new cap, oldest first.
        let c = s.take("m1", Some(3), "c", false).unwrap();
        assert_eq!(b.turn(), Turn::Go);
        assert_eq!(s.load("m1"), (3, 0));
        drop((b, c));
        let held: Vec<Slot> = (0..50).map(|i| s.take(SERVER, None, &format!("b{i}"), false).unwrap()).collect();
        assert_eq!(s.load(SERVER), (50, 0));
        drop(held);
    }

    #[test]
    fn an_asked_bot_borrows_past_the_cap_so_asks_never_deadlock() {
        let s = slots();
        let asker = s.take("m1", Some(1), "a", false).unwrap();
        // Bot a waits in `botctl ask` on Bot b: b goes in over the cap.
        let b = s.take("m1", Some(1), "b", true).unwrap();
        assert_eq!(s.load("m1"), (2, 0));
        // Others still wait until the pool is back under its cap.
        let c = queued(s.take("m1", Some(1), "c", false));
        drop(b);
        assert!(matches!(c.turn(), Turn::Waiting { .. }));
        drop(asker);
        assert_eq!(c.turn(), Turn::Go);
    }

    #[test]
    fn a_waiting_run_borrows_without_changing_the_cap() {
        let s = slots();
        let _a = s.take("m1", Some(2), "a", false).unwrap();
        let _b = s.take("m1", Some(2), "b", false).unwrap();
        let c = queued(s.take("m1", Some(2), "c", false));
        let d = queued(s.take("m1", Some(1), "d", false));
        let c = c.borrow();
        assert_eq!(s.load("m1"), (3, 1));
        assert_eq!(d.turn(), Turn::Waiting { position: 1, running: 3, limit: 1 });
        drop(c);
        assert!(matches!(d.turn(), Turn::Waiting { .. }), "the cap is still 1");
    }
}
