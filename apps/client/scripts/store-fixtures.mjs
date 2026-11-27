// Made-up demo data for the store screenshots (docs/store/screenshots.md). The people,
// company and Bots are invented; no real server, account or customer is shown.

const MIN = 60_000;

/** Chats read as a weekday morning (shown in UTC); approvals count down from `now`. */
const MORNING = Date.parse("2026-11-24T10:45:00Z");

export function demoData(now = Date.now()) {
  const ago = (m) => MORNING - m * MIN;
  const me = { id: "u_demo", name: "Sam Rivera", email: "sam@example.com", role: "admin", session: true };
  const owner = { id: me.id, name: me.name };
  const bot = (id, name, color, shape, extra = {}) => ({
    id,
    name,
    color,
    shape,
    harness: "hermes",
    model: null,
    effort: null,
    primary: false,
    hidden: false,
    unread: false,
    working: false,
    policy: "ask",
    policyOverride: false,
    owner,
    visibility: "private",
    access: "manage",
    ...extra,
  });
  const bots = [
    bot("b_ledger", "Ledger", "#4cc06a", "waddle", {
      primary: true,
      preview: "All 214 payouts match. Two refunds need a look.",
    }),
    bot("b_scout", "Scout", "#3b82f6", "cloud", {
      unread: true,
      preview: "Your Monday competitor digest is ready.",
      visibility: "shared",
    }),
    bot("b_atlas", "Atlas", "#8b5cf6", "bean", {
      working: true,
      status: "Running the test suite",
      preview: "Opening a pull request for the date picker fix…",
    }),
    bot("b_quill", "Quill", "#e9a23b", "drop", { preview: "Drafted the release notes for 2.4." }),
  ];

  const msg = (id, botId, role, text, minutesAgo, extra = {}) => ({ id, botId, role, text, at: ago(minutesAgo), ...extra });
  const messages = {
    b_ledger: [
      msg(1, "b_ledger", "user", "Match October's card payouts against the bank export and flag anything off.", 42),
      msg(
        2,
        "b_ledger",
        "bot",
        [
          "Done. I matched **214 of 214 payouts** to bank deposits.",
          "",
          "Two refunds need a look:",
          "",
          "- **3 Oct, Acme Ltd, −€420:** refunded twice.",
          "- **19 Oct, Brightside, −€89:** no matching invoice.",
          "",
          "The report is in `reports/october.xlsx` on my computer.",
        ].join("\n"),
        38,
      ),
      msg(3, "b_ledger", "user", "Thanks. Email Acme's finance contact about the double refund?", 7),
      msg(4, "b_ledger", "bot", "Which tone should I use?", 6, {
        question: { title: "Email to Acme Ltd", options: ["Friendly heads-up", "Formal request", "Let me write it"], picked: null },
      }),
    ],
    b_scout: [
      msg(11, "b_scout", "routine", "Every Monday at 08:00: research what our three main competitors shipped last week and summarise it.", 180),
      msg(
        12,
        "b_scout",
        "bot",
        "Your Monday digest:\n\n- **Northwind** launched usage-based pricing.\n- **Contoso** added SSO to its free plan.\n- **Fabrikam** had a two-hour outage on Thursday.\n\nSources and screenshots are in `digests/week-47.md`.",
        176,
      ),
    ],
    b_atlas: [
      msg(21, "b_atlas", "user", "The date picker shows the wrong month in Safari. Find the cause, fix it and open a PR.", 25),
      msg(22, "b_atlas", "bot", "Found it: the picker parses `YYYY-MM` strings as UTC, so Safari lands on the previous month. Fixing it now and running the tests.", 19),
    ],
    b_quill: [msg(31, "b_quill", "bot", "Drafted the release notes for 2.4 in `notes/2.4.md`.", 300)],
  };

  const approvals = [
    {
      id: "ap_push",
      botId: "b_atlas",
      harness: "hermes",
      tool: "terminal",
      kind: "shell",
      subject: "git push origin fix/safari-date-picker",
      class: "git_push",
      reason: "Pushes to a git remote",
      status: "pending",
      createdAt: now - 2 * MIN,
      expiresAt: now + 28 * MIN,
      runScope: { covers: ["Pushes to a git remote"], exact: false },
    },
  ];

  const policy = { mode: "ask", classes: {}, timeoutMinutes: 30, sandbox: true };

  const routines = {
    b_scout: [
      { id: "r_digest", bot_id: "b_scout", name: "Monday competitor digest", cron: "0 8 * * 1", instruction: "Research what our three main competitors shipped last week and summarise it.", enabled: true, last_run_at: Math.floor(ago(180) / 1000) },
      { id: "r_mentions", bot_id: "b_scout", name: "Daily mentions", cron: "0 9 * * *", instruction: "Collect yesterday's mentions of us on news sites and forums.", enabled: true, last_run_at: Math.floor(ago(600) / 1000) },
    ],
  };

  const state = { me, harnesses: ["hermes", "pi"], defaultHarness: "hermes", bots, policy, approvals };
  return { me, bots, messages, approvals, policy, routines, state };
}
