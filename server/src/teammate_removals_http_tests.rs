//! Removing leaving teammates' accounts on one server (ADR 0066), on the real router.
//! Without root no account can be made or removed here, so a fake `sudo` stands in for
//! `superbot-userctl`: it edits a fake password file and moves folders the way the helper
//! does, and logs every call. What the helper does to real accounts and processes is
//! the OS test's (accounts_os_tests, deploy/test-isolation.sh).

use crate::acl::{SharedBots, Visibility};
use crate::machines::offboard::{Files, Settings};
use crate::tests::{audit_list, call, serve_app};
use crate::users_http_tests::{parse, user_with};
use crate::*;
use std::path::PathBuf;

const FAKE_SUDO: &str = r#"#!/bin/sh
# fake sudo: -n <userctl> <command> ...
R="$(dirname "$0")"
shift 2
echo "$*" >> "$R/calls.log"
case "$1" in
  ensure) exit 0 ;;
  remove)
    o=$2 t=$3 id=$4 mode=$5 name=$6
    if [ -e "$R/fail-remove" ]; then echo "superbot-userctl: $(cat "$R/fail-remove")" >&2; exit 2; fi
    pair="$R/$o-$t"
    if grep -qF ":$pair/home:" "$R/passwd"; then
      grep -vF ":$pair/home:" "$R/passwd" > "$R/passwd.new"; mv "$R/passwd.new" "$R/passwd"; echo account=removed
    else
      echo account=absent
    fi
    echo processes=1; echo temp=0
    if [ -d "$pair/workspace" ] && [ -n "$(ls -A "$pair/workspace")" ]; then
      case $mode in
        hold) mkdir -p "$R/.left"; mv "$pair/workspace" "$R/.left/$id"; echo work=held; echo "path=$R/.left/$id" ;;
        delete) echo work=deleted ;;
        archive) mkdir -p "$R/$o/workspace/from-teammates"; mv "$pair/workspace" "$R/$o/workspace/from-teammates/$name"; echo work=archived; echo "path=$R/$o/workspace/from-teammates/$name" ;;
      esac
    else
      echo work=none
    fi
    rm -rf "$pair" ;;
  purge)
    if [ -e "$R/.left/$2" ]; then rm -rf "$R/.left/$2"; echo purged=yes; else echo purged=no; fi ;;
  *) exit 2 ;;
esac
"#;

struct World {
    port: u16,
    app: AppState,
    admin: String,
    root: PathBuf,
    a_id: String,
    a: String,
    b_id: String,
    b: String,
    c_id: String,
    team: crate::db::Bot,
}

/// Ada shares a Bot with Bea and Cy; each has an account for it here, with work in it.
/// So has Ada her own, which no removal may touch.
async fn world(files: Settings) -> World {
    use std::os::unix::fs::PermissionsExt;
    let (port, app, admin, _) = serve_app().await;
    let root = app.cfg.data_dir.parent().unwrap().join(format!("iso-{}", short_id()));
    std::fs::create_dir_all(&root).unwrap();
    let sudo = root.join("sudo");
    std::fs::write(&sudo, FAKE_SUDO).unwrap();
    std::fs::set_permissions(&sudo, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mut iso = accounts::for_tests(&root, sudo.to_str().unwrap());
    iso.teammates = true;
    iso.offboard = files;
    let _ = app.isolation.set(Arc::new(iso));
    app.shared_bots.set(SharedBots::Isolated).unwrap();
    let (a_id, a) = user_with(port, &admin, "ada@example.com", "member").await;
    let (b_id, b) = user_with(port, &admin, "bea@example.com", "member").await;
    let (c_id, _) = user_with(port, &admin, "cy@example.com", "member").await;
    let team = app.db.create_bot_owned("Team", "#fff", "waddle", "claude", None, false, &a_id, Visibility::Private);
    for t in [&b_id, &c_id] {
        app.db.set_grant(&team.id, t, crate::acl::Grant::Operator, &a_id);
    }
    let r = root.display();
    let mut passwd = format!("root:x:0:0:root:/root:/bin/bash\nsb-u-{a_id}:x:990:990::{r}/{a_id}/home:/usr/sbin/nologin\n");
    for (uid, t) in [(991, &b_id), (992, &c_id)] {
        let name = accounts::teammate_account(&a_id, t).unwrap();
        passwd += &format!("{name}:x:{uid}:{uid}::{r}/{a_id}-{t}/home:/usr/sbin/nologin\n");
        std::fs::create_dir_all(root.join(format!("{a_id}-{t}/workspace"))).unwrap();
        std::fs::write(root.join(format!("{a_id}-{t}/workspace/notes.txt")), format!("{t}'s notes")).unwrap();
    }
    // Not a teammate account: the name isn't the one its home's pair gets.
    passwd += &format!("sb-t-ffffffffffffffffffffffff:x:993:993::{r}/{a_id}-{c_id}/home:/usr/sbin/nologin\n");
    std::fs::write(root.join("passwd"), passwd).unwrap();
    std::fs::create_dir_all(root.join(format!("{a_id}/workspace"))).unwrap();
    std::fs::write(root.join(format!("{a_id}/workspace/mine.txt")), "ada's").unwrap();
    World { port, app, admin, root, a_id, a, b_id, b, c_id, team }
}

fn delete_after(days: u32) -> Settings {
    Settings { files: Files::Delete, grace_days: days }
}

async fn events(w: &World, action: &str) -> Vec<Value> {
    let (code, body) = call(w.port, "GET", &format!("/api/audit?action={action}&limit=200"), &w.admin, "").await;
    assert_eq!(code, 200, "{body}");
    audit_list(&body)
}

fn calls(w: &World) -> Vec<String> {
    std::fs::read_to_string(w.root.join("calls.log")).unwrap_or_default().lines().map(String::from).collect()
}

fn passwd(w: &World) -> String {
    std::fs::read_to_string(w.root.join("passwd")).unwrap()
}

async fn settled(w: &World) {
    crate::teammate_removals::settled(&w.app).await;
}

/// Ada's own account and Cy's for her Bots, with their work, are as they were.
fn others_untouched(w: &World) {
    let p = passwd(w);
    assert!(p.contains(&format!("sb-u-{}:", w.a_id)), "Ada's own account is gone");
    assert!(p.contains(&accounts::teammate_account(&w.a_id, &w.c_id).unwrap()), "Cy's account is gone");
    assert!(p.contains("sb-t-ffffffffffffffffffffffff"), "the forged entry is gone");
    assert_eq!(std::fs::read_to_string(w.root.join(format!("{}/workspace/mine.txt", w.a_id))).unwrap(), "ada's");
    assert_eq!(std::fs::read_to_string(w.root.join(format!("{}-{}/workspace/notes.txt", w.a_id, w.c_id))).unwrap(), format!("{}'s notes", w.c_id));
    for c in calls(w) {
        assert!(!c.contains(&w.c_id), "{c}");
        assert!(!c.starts_with("remove") || c.split(' ').nth(1) != c.split(' ').nth(2), "{c}");
    }
}

#[tokio::test]
async fn teammate_accounts_are_found_in_the_password_file_and_nothing_else_is() {
    let w = world(Settings::default()).await;
    let iso = w.app.isolation().unwrap();
    let mut want = vec![(w.a_id.clone(), w.b_id.clone()), (w.a_id.clone(), w.c_id.clone())];
    want.sort();
    assert_eq!(iso.teammate_pairs(), want);

    let (code, v) = call(w.port, "GET", &format!("/api/users/{}/teammate-accounts", w.a_id), &w.admin, "").await;
    assert_eq!(code, 200, "{v}");
    let v = parse(&v);
    assert_eq!(v["accounts"].as_array().unwrap().len(), 2, "{v}");
    assert!(v["accounts"].as_array().unwrap().iter().all(|a| a["wanted"] == true && a["removal"].is_null()), "{v}");
    let (code, v) = call(w.port, "GET", &format!("/api/users/{}/teammate-accounts", w.b_id), &w.admin, "").await;
    assert_eq!((code, parse(&v)["accounts"][0]["owner"]["email"].as_str()), (200, Some("ada@example.com")), "{v}");
    // Admins only.
    let (code, _) = call(w.port, "GET", &format!("/api/users/{}/teammate-accounts", w.a_id), &w.a, "").await;
    assert_eq!(code, 403);
    let (code, _) = call(w.port, "GET", "/api/isolation/teammate-removals", &w.b, "").await;
    assert_eq!(code, 403);
    // Nothing goes while everyone still may use the Bot.
    crate::teammate_removals::follow_up(&w.app);
    settled(&w).await;
    assert!(calls(&w).is_empty(), "{:?}", calls(&w));
}

#[tokio::test]
async fn a_disabled_teammate_loses_their_account_once_and_their_held_work_is_purged_later() {
    let w = world(delete_after(7)).await;
    let (code, _) = call(w.port, "PATCH", &format!("/api/users/{}", w.b_id), &w.admin, r#"{"status":"disabled"}"#).await;
    assert_eq!(code, 200);
    settled(&w).await;

    let removed = events(&w, "isolation.teammate_removed").await;
    assert_eq!(removed.len(), 1, "{removed:?}");
    let (e, d) = (&removed[0], &removed[0]["details"]);
    assert_eq!(e["targetId"], w.a_id.as_str());
    assert_eq!((d["forUser"].as_str(), d["reason"].as_str(), d["work"].as_str()), (Some(w.b_id.as_str()), Some("disabled"), Some("held")), "{d}");
    assert_eq!((d["accountRemoved"].as_bool(), d["processesStopped"].as_i64()), (Some(true), Some(1)), "{d}");
    assert_eq!(d["account"], accounts::teammate_account(&w.a_id, &w.b_id).unwrap().as_str());
    assert!(d["purgeAt"].as_i64().unwrap() > db::now() + 6 * 86_400_000, "{d}");
    assert_eq!(events(&w, "isolation.teammate_removal_queued").await.len(), 1);
    assert!(!passwd(&w).contains(&accounts::teammate_account(&w.a_id, &w.b_id).unwrap()));
    assert!(!w.root.join(format!("{}-{}", w.a_id, w.b_id)).exists());
    let id = d["cleanupId"].as_str().unwrap().to_string();
    assert_eq!(std::fs::read_to_string(w.root.join(format!(".left/{id}/notes.txt"))).unwrap(), format!("{}'s notes", w.b_id));
    assert_eq!(calls(&w), [format!("remove {} {} {id} hold", w.a_id, w.b_id)]);
    others_untouched(&w);

    // Again changes nothing: no second removal, however often asked.
    for _ in 0..2 {
        crate::teammate_removals::left(&w.app, &crate::audit::Who::system("test"), &w.b_id, "disabled");
        crate::teammate_removals::follow_up(&w.app);
        settled(&w).await;
    }
    assert_eq!(events(&w, "isolation.teammate_removed").await.len(), 1);
    assert_eq!(events(&w, "isolation.teammate_removal_queued").await.len(), 1);
    assert_eq!(calls(&w).len(), 1);

    let (code, v) = call(w.port, "GET", "/api/isolation/teammate-removals?state=held", &w.admin, "").await;
    let v = parse(&v);
    assert_eq!((code, v["files"].as_str(), v["graceDays"].as_i64()), (200, Some("delete"), Some(7)), "{v}");
    assert_eq!(v["removals"][0]["teammate"]["email"], "bea@example.com");
    assert_eq!(call(w.port, "GET", "/api/isolation/teammate-removals?state=soon", &w.admin, "").await.0, 400);

    // Its days up, the held work goes, once.
    w.app.db.account_removal_due_now(&id);
    crate::teammate_removals::follow_up(&w.app);
    settled(&w).await;
    let purged = events(&w, "isolation.teammate_files_purged").await;
    assert_eq!((purged.len(), purged[0]["details"]["purged"].as_bool()), (1, Some(true)), "{purged:?}");
    assert!(!w.root.join(format!(".left/{id}")).exists());
    assert_eq!(w.app.db.account_removal(&id).unwrap().state, "done");
    crate::teammate_removals::follow_up(&w.app);
    settled(&w).await;
    assert_eq!(calls(&w).len(), 2);
    others_untouched(&w);
}

#[tokio::test]
async fn a_revoked_grant_removes_the_account_and_a_returning_teammate_is_never_removed_unasked() {
    let w = world(delete_after(0)).await;
    // A removal queued while Bea still may use the Bot, never tried: cancelled.
    let row = w
        .app
        .db
        .account_removal_queue(&db::NewAccountRemoval {
            owner_id: &w.a_id,
            user_id: &w.b_id,
            account: &accounts::teammate_account(&w.a_id, &w.b_id).unwrap(),
            reason: "access_lost",
            files: "delete",
            grace_days: 0,
            created_by: None,
        })
        .unwrap()
        .0;
    crate::teammate_removals::follow_up(&w.app);
    settled(&w).await;
    assert_eq!(w.app.db.account_removal(&row.id).unwrap().state, "cancelled");
    let cancelled = events(&w, "isolation.teammate_removal_cancelled").await;
    assert_eq!(cancelled[0]["details"]["why"], "access_back", "{cancelled:?}");
    assert!(calls(&w).is_empty());

    let (code, res) = call(w.port, "DELETE", &format!("/api/bots/{}/grants/{}", w.team.id, w.b_id), &w.a, "").await;
    assert_eq!(code, 200, "{res}");
    settled(&w).await;
    let removed = events(&w, "isolation.teammate_removed").await;
    assert_eq!(removed.len(), 1, "{removed:?}");
    assert_eq!((removed[0]["details"]["reason"].as_str(), removed[0]["details"]["work"].as_str()), (Some("access_lost"), Some("deleted")));
    assert!(removed[0]["details"]["purgeAt"].is_null());
    assert!(!w.root.join(".left").exists());
    others_untouched(&w);

    // Bea's own Bots, and runs of others' Bots, are hers to keep: still a member.
    assert!(w.app.db.user(&w.b_id).unwrap().active());
    let _ = &w.b;
}

#[tokio::test]
async fn a_failing_removal_is_retried_audited_once_and_admins_can_force_one() {
    let w = world(delete_after(0)).await;
    std::fs::write(w.root.join("fail-remove"), "boom").unwrap();
    let path = format!("/api/users/{}/teammate-accounts/{}/remove", w.a_id, w.b_id);
    let (code, res) = call(w.port, "POST", &path, &w.admin, "").await;
    assert_eq!(code, 202, "{res}");
    let v = parse(&res);
    assert!(v["error"].as_str().unwrap().contains("boom"), "{v}");
    assert_eq!((v["removal"]["state"].as_str(), v["removal"]["reason"].as_str()), (Some("pending"), Some("admin")), "{v}");
    let id = v["removal"]["id"].as_str().unwrap().to_string();
    // Bea still may use the Bot, but an admin asked: it stays pending, tried again.
    for _ in 0..2 {
        crate::teammate_removals::follow_up(&w.app);
        settled(&w).await;
    }
    let r = w.app.db.account_removal(&id).unwrap();
    assert_eq!((r.state.as_str(), r.attempts), ("pending", 3));
    assert_eq!(events(&w, "isolation.teammate_removal_failed").await.len(), 1, "one failure in the log per reason");

    std::fs::remove_file(w.root.join("fail-remove")).unwrap();
    let (code, res) = call(w.port, "POST", &path, &w.admin, "").await;
    assert_eq!(code, 200, "{res}");
    let v = parse(&res);
    assert_eq!((v["removal"]["state"].as_str(), v["removed"]["accountRemoved"].as_bool()), (Some("done"), Some(true)), "{v}");
    assert_eq!(v["removal"]["id"], id.as_str(), "the same removal");
    // Once more: nothing's left, and it says so.
    let (code, res) = call(w.port, "POST", &path, &w.admin, "").await;
    assert_eq!((code, parse(&res)["removed"]["accountRemoved"].as_bool()), (200, Some(false)), "{res}");
    others_untouched(&w);

    // Never a user's own account, never a name that isn't a user id, never a member.
    for (who, t, want) in [(&w.admin, w.a_id.clone(), 400), (&w.admin, "a.b".to_string(), 400), (&w.a, w.b_id.clone(), 403)] {
        let (code, res) = call(w.port, "POST", &format!("/api/users/{}/teammate-accounts/{t}/remove", w.a_id), who, "").await;
        assert_eq!(code, want, "{t}: {res}");
    }
    let (code, _) = call(w.port, "POST", &format!("/api/users/nobody/teammate-accounts/{}/remove", w.b_id), &w.admin, "").await;
    assert_eq!(code, 404);
}

#[tokio::test]
async fn work_with_no_owner_account_to_go_to_is_held_not_lost() {
    let w = world(Settings::default()).await;
    let (code, _) = call(w.port, "PATCH", &format!("/api/users/{}", w.b_id), &w.admin, r#"{"status":"disabled"}"#).await;
    assert_eq!(code, 200);
    settled(&w).await;
    let removed = events(&w, "isolation.teammate_removed").await;
    assert_eq!(removed.len(), 1, "{removed:?}");
    let d = &removed[0]["details"];
    assert_eq!((d["files"].as_str(), d["work"].as_str()), (Some("archive"), Some("held")), "{d}");
    assert!(d["notArchived"].as_str().unwrap().contains("owner's account"), "{d}");
    assert!(d["purgeAt"].as_i64().unwrap() > db::now() + 29 * 86_400_000, "{d}");
    let id = d["cleanupId"].as_str().unwrap();
    assert!(w.root.join(format!(".left/{id}/notes.txt")).is_file());
    // botd asked for Ada's own account first, so the work could be hers.
    assert_eq!(calls(&w)[0], format!("ensure {}", w.a_id));
    others_untouched(&w);
}

#[tokio::test]
async fn a_recreated_containers_folders_are_still_cleaned_up() {
    let w = world(delete_after(0)).await;
    // The container came back: Bea's account isn't in its password file, her folder is.
    // botd made it, and remembers.
    let bea = accounts::teammate_account(&w.a_id, &w.b_id).unwrap();
    let p: String = passwd(&w).lines().filter(|l| !l.starts_with(&bea)).map(|l| format!("{l}\n")).collect();
    std::fs::write(w.root.join("passwd"), p).unwrap();
    w.app.db.teammate_space_made(&w.a_id, &w.b_id);
    let (code, v) = call(w.port, "GET", &format!("/api/users/{}/teammate-accounts", w.b_id), &w.admin, "").await;
    assert_eq!((code, parse(&v)["accounts"].as_array().map(Vec::len)), (200, Some(1)), "{v}");

    let (code, _) = call(w.port, "PATCH", &format!("/api/users/{}", w.b_id), &w.admin, r#"{"status":"disabled"}"#).await;
    assert_eq!(code, 200);
    settled(&w).await;
    let removed = events(&w, "isolation.teammate_removed").await;
    assert_eq!(removed.len(), 1, "{removed:?}");
    assert_eq!((removed[0]["details"]["accountRemoved"].as_bool(), removed[0]["details"]["work"].as_str()), (Some(false), Some("deleted")));
    assert!(!w.root.join(format!("{}-{}", w.a_id, w.b_id)).exists());
    assert!(w.app.db.teammate_spaces().iter().all(|(_, t)| *t != w.b_id), "forgotten once removed");
    // Once gone, it's never queued again.
    crate::teammate_removals::follow_up(&w.app);
    settled(&w).await;
    assert_eq!(calls(&w).len(), 1, "{:?}", calls(&w));
    others_untouched(&w);
}

#[tokio::test]
async fn without_per_user_accounts_there_is_nothing_to_remove() {
    let (port, _app, admin, _) = serve_app().await;
    let (a_id, _) = user_with(port, &admin, "ada@example.com", "member").await;
    let (code, _) = call(port, "GET", "/api/isolation/teammate-removals", &admin, "").await;
    assert_eq!(code, 409);
    let (code, _) = call(port, "POST", &format!("/api/users/{a_id}/teammate-accounts/x1/remove"), &admin, "").await;
    assert_eq!(code, 409);
}

#[tokio::test]
async fn nothing_starts_in_an_account_being_removed_and_the_removal_waits_for_its_runs() {
    let w = world(delete_after(0)).await;
    // A removal of Bea's account that keeps failing stays pending: no run or login of
    // hers starts in it meanwhile. Cy's account is another matter.
    std::fs::write(w.root.join("fail-remove"), "boom").unwrap();
    let (code, res) = call(w.port, "POST", &format!("/api/users/{}/teammate-accounts/{}/remove", w.a_id, w.b_id), &w.admin, "").await;
    assert_eq!(code, 202, "{res}");
    assert!(crate::teammate_removals::enter(&w.app, &w.a_id, &w.b_id).is_none());
    assert!(crate::teammate_removals::enter(&w.app, &w.a_id, &w.c_id).is_some());
    let (code, res) = call(w.port, "POST", &format!("/api/machine/teammate/{}/harness-login", w.a_id), &w.b, r#"{"harness":"claude"}"#).await;
    assert_eq!(code, 409, "{res}");
    assert!(res.contains("being removed"), "{res}");
    settled(&w).await;
    std::fs::remove_file(w.root.join("fail-remove")).unwrap();

    // Cy has a run going in his account: an admin's removal stops it, waits for it to
    // end (it saves its memory then), and only then runs the helper.
    let app = w.app.clone();
    let (a_id, c_id) = (w.a_id.clone(), w.c_id.clone());
    let run = tokio::spawn(async move {
        let _in_use = crate::teammate_removals::enter(&app, &a_id, &c_id).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        std::fs::read_to_string(app.isolation().unwrap().root.join("calls.log")).unwrap_or_default()
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let (code, res) = call(w.port, "POST", &format!("/api/users/{}/teammate-accounts/{}/remove", w.a_id, w.c_id), &w.admin, "").await;
    assert_eq!(code, 200, "{res}");
    let seen_by_run = run.await.unwrap();
    assert!(!seen_by_run.contains(&format!("remove {} {}", w.a_id, w.c_id)), "the helper ran while the run was going: {seen_by_run}");
    assert!(calls(&w).iter().any(|c| c.starts_with(&format!("remove {} {}", w.a_id, w.c_id))), "{:?}", calls(&w));
    assert!(crate::teammate_removals::enter(&w.app, &w.a_id, &w.c_id).is_some(), "open again once it's done");
}

#[tokio::test]
async fn a_removal_the_helper_started_on_is_finished_even_if_access_comes_back() {
    let w = world(delete_after(0)).await;
    // botd stopped while the helper ran for Bea, before it heard back; she may use the
    // Bot again by the next pass. The helper may have moved her work: it finishes.
    let row = w
        .app
        .db
        .account_removal_queue(&db::NewAccountRemoval {
            owner_id: &w.a_id,
            user_id: &w.b_id,
            account: &accounts::teammate_account(&w.a_id, &w.b_id).unwrap(),
            reason: "access_lost",
            files: "delete",
            grace_days: 0,
            created_by: None,
        })
        .unwrap()
        .0;
    assert!(w.app.db.account_removal_tried(&row.id, "pending"));
    crate::teammate_removals::follow_up(&w.app);
    settled(&w).await;
    let r = w.app.db.account_removal(&row.id).unwrap();
    assert_eq!((r.state.as_str(), r.attempts), ("done", 2), "{:?}", r.last_error);
    assert!(events(&w, "isolation.teammate_removal_cancelled").await.is_empty());
    others_untouched(&w);
}
