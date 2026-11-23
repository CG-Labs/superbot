//! `botctl`: the CLI Bots use for routines, other Bots, and handing their screen to the user. Works with any harness,
//! because every harness can run a shell command. Talks to botd over local HTTP.
//! A tiny HTTP/1.0 client over a TCP socket; no HTTP library.
//!
//! It is also the approval gate (`botctl hook <harness>`), and lets an admin manage
//! approvals, policy, users, and sessions from a shell on the server (`SUPERBOT_TOKEN`
//! from `botctl login`, or the break-glass `SUPERBOT_PASSWORD`).

#[path = "../support_report.rs"]
mod support_report;

use serde_json::{json, Map, Value};
use std::io::{BufRead, Read, Write};
use std::net::TcpStream;

const HELP: &str = r#"botctl: manage your routines (scheduled tasks).

  botctl routines                                  List your routines
  botctl routine add "<name>" "<cron>" "<what to do>"
  botctl routine rm <id>                           Delete a routine
  botctl routine pause <id> | resume <id>
  botctl bots                                      List the Bots you can see (your owner's)
  botctl ask "<Bot name or id>" "<message>"        Ask another Bot; prints its reply
  botctl handoff "<what you need>"                 Ask the user to take over your screen; waits for "Done"

Cron has 5 fields in the server's local time: minute hour day month weekday.
  "30 7 * * *"    every day at 07:30
  "0 9 * * 1-5"   weekdays at 09:00
  "*/15 * * * *"  every 15 minutes
When a routine fires, you get "<what to do>" as a message and your reply goes to the user's chat.
Confirm the schedule with the user in plain words.

`ask` and `handoff` can take minutes: run them with a long command timeout (10 minutes).
If the other Bot takes longer, its reply arrives later as a new message."#;

const ADMIN_HELP: &str = r#"Operator commands (run on the server; need SUPERBOT_TOKEN, or SUPERBOT_PASSWORD set to
AUTH_PASSWORD, and BOT_API if botd isn't on http://127.0.0.1:3000; both are only sent to this machine):

  botctl login [<code> | -]                        Sign in with a sign-in code (- reads it from stdin), or
                                                   with SUPERBOT_PASSWORD; prints a SUPERBOT_TOKEN
    [--totp <code> | --recovery-code <code>]       With two-factor authentication on, the code from
                                                   your authenticator app, or a recovery code
  botctl logout                                    End the SUPERBOT_TOKEN session
  botctl whoami                                    Who the token or password signs in as, and its role
  botctl users                                     List users
  botctl user add <email> ["<name>"] [--role admin|member|readonly]
  botctl user role <user> <admin|member|readonly>  <user> is an id or email
  botctl user disable <user> | enable <user>       Disabling ends the user's sessions and pauses the routines
                                                   that run for them; enabling leaves those paused
  botctl user routines <user>                      Routines that run for the user, and which are paused
  botctl user resume-routines <user>               Turn back on the routines paused when they were disabled
  botctl user handover <user> <to> [--resume]      Give a disabled user's Bots and routines to <to>;
                                                   --resume turns their paused routines back on
  botctl user erase <user> [--destroy-machine] [--delete-backups] --yes
                                                   Erase their personal data for good (GDPR): Bots, chats,
                                                   sign-ins, secrets; the audit log keeps a pseudonym.
                                                   Refused under a legal hold, as a team's last owner, with
                                                   a machine (--destroy-machine destroys it first), or with
                                                   their machines' backups kept (--delete-backups deletes them)
  botctl roles                                     Custom roles (ADR 0123), the permissions they're built from,
                                                   and the built-in roles as presets of them
  botctl role show <role>                          A role (id or name), its effective permissions, and who has it
  botctl role add "<name>" [--base member|readonly] [--perms <a,b>] [--description "<text>"]
                                                   A role on member (default) or read-only, plus permissions:
                                                   users.manage, bots.manage, audit.view, billing.manage,
                                                   signups.approve, machines.manage
  botctl role edit <role> [--name "<name>"] [--base member|readonly] [--perms <a,b>|none] [--description "<text>"]
                                                   A new base applies at once to everyone who has it
  botctl role rm <role>                            Delete it, once nobody has it
  botctl role assign <role> <user> [--team <team>] Give it across the server (its base becomes their role), or
                                                   with --team only in that team (its team permissions)
  botctl role unassign <role> <user> [--team <team>]  Take it away; across the server they keep its base
  botctl service-accounts                          Service accounts (ADR 0143): non-human callers for scripts
                                                   and integrations. Admins see all; others with users.manage
                                                   the ones they own
  botctl service-account show <sa>                 One, its permissions, its tokens (never their secrets), the
                                                   Bots it reaches, and its refusals in the last 30 days
  botctl service-account add "<name>" [--role member|readonly|<custom role>] [--team <team>] [--description "<text>"]
                                                   Read-only by default; never admin, never more than you hold.
                                                   With --team, a custom role applies only in that team
  botctl service-account edit <sa> [--name "<name>"] [--role <role>] [--team <team>|none] [--owner <user>] [--description "<text>"]
                                                   Only admins change the owner, whose permissions cap it
  botctl service-account disable <sa> | enable <sa> | rm <sa>
                                                   Disabling stops every token; rm revokes them for good
  botctl service-account token list <sa>           Its tokens, live, expired and revoked
  botctl service-account token add <sa> [--name "<name>"] [--scopes <a,b>] [--days <1-365>]
                                                   A token, shown once: scoped to permissions it holds (default
                                                   all), expiring in --days (default 90)
  botctl service-account token rotate <sa> <token> [--days <1-365>] [--keep-old <minutes>]
                                                   A new token with the same scopes; the old one stops now, or
                                                   after --keep-old minutes (at most 1440)
  botctl service-account token revoke <sa> <token> It stops working at once
  botctl user tier <user> <tier|default>           Their plan: the models and limits they get
  botctl user region <user> [<region>|default]     Where their machine and its backups live (ADR 0117): theirs,
                                                   their team's or the default; set it, or follow the team again.
                                                   Refused while their machine is elsewhere
  botctl team region <team> [<region>|default]     The team's data region, for members without their own
  botctl user egress <user> [inherit|open|allow <host|cidr>...]
                                                   Their machine's outbound allow-list (ADR 0135): what it gets,
                                                   and whether it's loaded there; set their own, or follow the server's
  botctl user|team residency <user|team> [pin <region> <reference...> | unpin <reason...>]
                                                   Pin their data to a region under an agreement (ADR 0129):
                                                   machines, backups and restores stay there or are refused.
                                                   Refused while any of it is elsewhere. Unpinning needs a reason
  botctl user|team residency <user|team> report [--from <when>] [--to <when>] [--json] [-o <file>]
                                                   A residency report for the customer (ADR 0155): where their
                                                   data is, what the pin refused or held, with a digest.
                                                   Markdown unless --json; the last 90 days by default
  botctl regions                                   The data regions offered, who and what is in each, the
                                                   hosts and backup store in each, and residency warnings
  botctl tiers                                     Every tier, its routes and limits, and the default
  botctl tiers move-bots <tier> [--user <user>] [--dry-run]
                                                   Move a managed tier's Bots (or one user's) that run on
                                                   another harness onto the tier's default; --dry-run lists them
  botctl usage [json]                              Everyone's plan, use against its limits, machine size,
                                                   and subscription (admins)
  botctl usage me [json]                           Your own model tokens and runs this billing period
  botctl usage user <user> [json]                  A user's tokens and runs this billing period, by Bot
                                                   and model (admins)
  botctl user isolation <user>                     With ISOLATION=users: the user's own account and folders
  botctl user isolate <user>                       Make that account and its folders now
  botctl user teammates <user>                     Teammates' accounts for the user's shared Bots here, the
                                                   user's for others', and removals (ADR 0066)
  botctl user teammates <user> remove <teammate>   Remove that teammate's account for the user's Bots now:
                                                   processes stopped, work to the user, login deleted
  botctl user teammate-removals [pending|held|done|cancelled|open|all]
                                                   Removals of leaving teammates' accounts here (default open)
  botctl user harness-login <user> <claude|codex> [--owner <owner>] [-- <args>...]
                                                   Log a harness in as that user's account, for their
                                                   Bots only (as botd's service account, at a terminal).
                                                   With --owner: the user's own login for that owner's
                                                   shared Bots, in their teammate account (ADR 0064)
  botctl setup [status | json]                     What the server still needs: the onboarding checklist
  botctl setup done | reopen | hide | show         Finish the setup wizard, reopen it, or hide it from admins
  botctl license [json]                            The self-host license, its seats, and when it ends
  botctl license install [<file> | -] < key        Install the license key CG-Labs sent (stdin by default)
  botctl license remove                            Remove it (no free tier: Bots stop unless TESTING_MODE=on)
  botctl user code <user> [--ttl <minutes>]        A one-time sign-in code (default 60 minutes)
  botctl user identities <user>                    The user's SSO identities
  botctl user link <user> <provider> <subject> [--tenant <tenant-id>]
                                                   Let an SSO identity sign in as the user. Entra:
                                                   <subject> is the user's object id; Google,
                                                   Apple, and OIDC: the sub claim (or the mapped
                                                   subject); GitHub: the numeric user id
                                                   (gh api users/<login> --jq .id)
  botctl user unlink <user> <identity-id>
  botctl signup list [pending|approved|rejected|all]  Access requests from the get-started page
  botctl signup approve <id> [--role admin|member|readonly] [--ttl <minutes>]
                                                   Make the user (member by default) and print a
                                                   one-time sign-in code, once (default 3 days)
  botctl signup reject <id> [--reason "<text>"]    No email is sent either way
  botctl sso saml <provider>                       Native SAML: what to enter at the IdP, and its metadata
  botctl sso saml <provider> import [<file> | -] < metadata.xml
                                                   Import the IdP's SAML metadata (stdin by default)
  botctl sso saml <provider> key next|promote|cancel|retire signing|encryption
                                                   Roll over botd's own SP key: next publishes a new one,
                                                   promote puts it in use once the IdP has it, retire
                                                   drops the encryption key it replaced (ADR 0181)
  botctl sso role-mappings                         SAML groups mapped to custom roles (SSO_<ID>_GROUPS_ATTRIBUTE)
  botctl sso role map <provider> <group> <role>    Sign-ins listing <group> get <role> across the server.
                                                   Never admin, nor a role that acts on admins
  botctl sso role show <id>                        A mapping and who it gave the role to
  botctl sso role unmap <id>                       Takes the role from everyone the mapping gave it to
  botctl scim tokens                               SCIM tokens (never their values), and whether SCIM is on
  botctl scim token create <tenant> [--sso <provider>] [--label "<text>"]
                                                   A bearer token for an IdP's SCIM app, shown once.
                                                   <tenant> names the IdP connection (e.g. entra);
                                                   --sso: externalId is the person's subject there
  botctl scim token revoke <id>                    The IdP's users stay as they are
  botctl scim groups                               SCIM groups and the teams they are (SCIM_GROUPS=on)
  botctl scim group link <tenant> <team> [--external-id <id>] [--name "<group name>"]
                                                   Lets <tenant>'s IdP take on a team made by hand
                                                   when it pushes the group with that externalId
                                                   (or, with none, that name; the team's by default)
  botctl scim group unlink <team>                  The team is managed by hand again; everyone stays
  botctl scim role-mappings                        SCIM groups mapped to custom roles (SCIM_GROUP_ROLES=on)
  botctl scim role map <team> <role> [--org]       The group <team> is gives its members <role> in the
                                                   team, or with --org across the server. Never admin
  botctl scim role show <id>                       A mapping and who it gave the role to
  botctl scim role unmap <id>                      Takes the role from everyone the mapping gave it to
  botctl scim role-groups                          SCIM role groups: groups that give a custom role
                                                   across the server and aren't teams
  botctl scim role-group add <tenant> <group> <role> [--external-id <id>]
                                                   When <tenant>'s IdP pushes the group with that
                                                   externalId (or, with none, that name), it is a
                                                   role group giving <role>. Never admin
  botctl scim role-group show <id>                 A role group, its members, and who holds its role
  botctl scim role-group set-role <id> <role>      The group gives <role> instead
  botctl scim role-group remove <id>               Takes its role from everyone it gave it to
  botctl scim google                               The Google Workspace sync: settings and last passes
  botctl scim google sync [--force]                A pass now. --force lets one that removes more
                                                   people than GOOGLE_DIRECTORY_MAX_REMOVALS go ahead
  botctl sessions [<user>]                         Live sessions
  botctl session revoke <id>
  botctl session revoke-all <user>

  botctl bot access <bot>                          Who owns a Bot, who can see it, and their grants
  botctl bot share <bot> | private <bot>           Shared with everyone, or only its owner and grants
  botctl bot owner <bot> <user>                    Give a Bot to another user (admins only)
  botctl bot grant <bot> <user> <viewer|operator>  viewer: read its chat; operator: also run it. <user> may be
                                                   a service account's id: never more than its owner can do
  botctl bot revoke <bot> <user>

  botctl policy [<bot>]                            Show the global or a Bot's policy
  botctl policy set <global|bot> [mode=ask|bypass] [sandbox=on|off] [timeout=<minutes>] [<class>=allow|ask|deny]...
                                                   On a Bot, =inherit follows the global value again
                                                   sandbox: the harness's own sandbox (Codex, Claude Code)
  botctl policy reset <bot>                        Drop a Bot's override; it follows global again
  botctl rules [<bot>]                             List allow/deny rules
  botctl rule add <allow|deny> "<pattern>" [--tool <tool>] [--bot <bot>]
  botctl rule rm <id>
  botctl approvals [pending|all]                   List approvals
  botctl approve <id> [--run | --remember | --remember-global]
                                                   --run: also calls of the same kind, until the task ends
  botctl deny <id> [--remember | --remember-global]
  botctl audit [<limit>] [filters]                 Recent audit events, newest first
  botctl audit export [filters] > audit.csv        All matching events as CSV, oldest first
  botctl audit verify [--pin <id>:<hash>]... [--from <id>] [--to <id>] [--key <hex>]... [--archive]
                                                   Check the audit log's hash chain, its signed
                                                   checkpoints and their timestamps; names the first
                                                   break, exits 1 if there is one. --pin: a hash kept
                                                   elsewhere (your SIEM) the row must still have.
                                                   --from/--to: only those event ids. --key: trust only
                                                   this checkpoint key (from botctl audit key).
                                                   --archive: also read the write-once S3 archive,
                                                   check it has no gaps, and hold every event here
                                                   to the hash it has there
  botctl audit siem                                The SIEM export: sink, delivered, pending, failing
  botctl audit chain                               The chain's state: head, last checkpoint and
                                                   timestamp, export lag, last check
  botctl audit key                                 The public key checkpoints are signed with
  botctl audit checkpoint                          Sign a checkpoint of the head now
  botctl audit checkpoints [<limit>]               Recent checkpoints, with their RFC 3161 tokens
    filters: --from <time> --to <time> --action <a,b.*> --actor <user|bot|system[:id]>
             --actor user:<email> --method <password,code,sso,none,bot_token,scim_token>
             --idp <entra|google|oidc|github|apple|saml> --idp-provider <id> --subject <issuer|sub>
             --session <id> --on-behalf-of <user id|email> --outcome <success|failure|denied> --bot <id>
    times: YYYY-MM-DD (UTC), RFC 3339, or unix milliseconds
  botctl support-bundle [-o <file>]                Save a support bundle for a ticket (ADR 0131): version,
                                                   redacted settings, health, recent logs and an audit
                                                   summary, in a tar; no secrets, emails or chats. When botd
                                                   is down: botd support bundle (or botd support check), ADR 0187
  botctl health-score [--days <n>] [json]          The customer health score (ADR 0144) for the last 30 days
                                                   (7 to 90): adoption, Bot runs, sign-in and SCIM, backups,
                                                   approvals and the license, each ok, watch or at risk
  botctl health-score history [--days <n>] [json]  The score botd recorded each day (ADR 0157) for the last
                                                   90 days (1 to 3650), and what got worse or better
  botctl support-report <tickets.csv | -> [--plan <plan>] [--customer <name>] [--from <YYYY-MM> --to <YYYY-MM>]
    [--hours <HH:MM-HH:MM>] [--weekdays <mon-fri>] [--utc-offset <+HH:MM>] [--holidays <dates>]
    [--target <sev>=<30m|1h|4bh|1bd>]... [--column <field>=<header>]... [--as-of <time>] [--markdown | --json]
                                                   The Provider's support report (ADR 0167), offline, from a
                                                   ticket system's CSV export: tickets by month and severity,
                                                   response targets met and missed, and what's still open.
                                                   Reads only ids, severities, plans and times
  botctl evidence                                  The evidence bundle schedule (EVIDENCE_BUNDLES), where
                                                   bundles are written and those kept (ADR 0142)
  botctl evidence baseline [json]                  Check this server against the configuration baseline
                                                   (ADR 0192): each setting meets it, doesn't, is excepted
                                                   (BASELINE_EXCEPTIONS), doesn't apply, or needs a person;
                                                   audited, and exits non-zero on a deviation
  botctl evidence bundle [--from <YYYY-MM-DD> --to <YYYY-MM-DD>] [-o <file>]
                                                   Save a SOC 2 evidence bundle for a period (last month
                                                   by default; to isn't included): access review, versions,
                                                   backups, retention, sign-ins and alerts, with SHA-256
                                                   digests; no secrets, names, emails or chats
  botctl retention                                 How long chat history, harness session files,
                                                   teammates' archived work and the audit log are kept
                                                   (CHAT_RETENTION_DAYS, HARNESS_SESSION_RETENTION_DAYS,
                                                   TEAMMATE_FILES_RETENTION_DAYS, AUDIT_RETENTION_DAYS),
                                                   each last deletion pass, and held Bots
  botctl retention hold <bot> "<reason>"           Keep a Bot's chat and files out of retention (a legal
                                                   hold); it can't be deleted while held
  botctl retention release <bot>                   Retention applies to its chat again
  botctl backups                                   Where server backups are copied off this host, the
                                                   newest copies, and the RPO (ADR 0109), and which
                                                   backups are encrypted (ADR 0114)
  botctl backups copy                              Copy the newest archive off the host now, if it isn't
  botctl database                                  Whether the database is encrypted at rest (SQLCipher,
                                                   SUPERBOT_DATABASE_ENCRYPTION), and any plain copy left
                                                   from encrypting it (ADR 0116)
  botctl machine list [<state>]                    Every user's machine (pending, running, suspended, error, ... or all)
  botctl machine show <user>                       The user's machine: provider, plan, state, address, enrollment
  botctl machine request <user> [<tier>] [<region>]  Give the user a machine (a Linode VM or an Incus container)
  botctl machine egress [open|allow <host|cidr>...]  The server's outbound allow-list for every machine (ADR 0135):
                                                   open (the default), or only these hosts and networks
  botctl machine suspend|resume <user>             Power it off (disk and address kept), or back on
  botctl machine resize <user> <tier>              Move it to the tier's plan
  botctl machine resize <user> status              Its latest resize: a tier change's, and whether it waits, and why
  botctl machine resizes                           Every resize a tier change asked for that isn't done yet
  botctl machine destroy <user> --yes              Delete it and its disk at the provider
  botctl machine revoke <user> --yes               Revoke its certificates and unused tokens now; it must enroll again
  botctl machine enroll <user>                     A one-time token to enroll it by hand, shown once, with how
                                                   (after a revoke, or a Linode backup restored onto it; ADR 0110)
  botctl machine substrate [check]                 What machines are made on, each tier's size, and isolation; check asks the host
  botctl machine reconcile                         Follow every machine to where it should be now
  botctl machine placement [<user>]                Where each user's Bots run: this server or their machine
  botctl machine assign <user>                     Run the user's Bots on their enrolled machine
  botctl machine unassign <user>                   Stop using it; with MACHINE_ROUTING=assigned they run here again
  botctl machine agent <user>                      Its agent's build, harness CLIs and upgrades, against botd's
  botctl machine upgrade <user>                    Upgrade its agent to botd's build now
  botctl machine upgrade <user> hold|release       Keep its agent at its build, or let it be upgraded again
  botctl machine harnesses <user>                  Install MACHINE_HARNESSES on it now, retrying failures
  botctl machine mirror                            Fetch every harness file machines would, from the mirrors, and check each pin (ADR 0186)
  botctl machine legacy                            Machines whose agent is from before agent upgrades, and their rebuilds
  botctl machine rebuild <user> [--discard-work]   Wipe and reinstall it with today's agent (ADR 0056); same IP and firewall
  botctl machine rebuild <user> status|cancel      How its rebuild is going, or cancel one not yet sent
  botctl machine backups [<user>]                  Off-host backups (ADR 0071): every one and the settings, or the user's and its last restore
  botctl machine backup <user>                     Back it up to object storage now
  botctl machine recovery                          Each tier's RPO and RTO, machines past their RPO, and how
                                                   long restores took (ADR 0074)
  botctl machine restore <user> <backup-id> [--identity <age-key-file>] [--host <name>] --yes  Make it again from that backup; it enrolls anew
                                                   (--host: onto that Incus host, deleting it from its own; ADR 0076)
  botctl machine restore <user> status             How its latest restore went
  botctl machine delete-backups <machine-id> --yes Delete a destroyed machine's backups now, not when their
                                                   retention ends (ADR 0108); botctl machine list destroyed
  botctl machine hosts [check]                     Incus hosts (ADR 0076): up, down or lost, their machines, load and
                                                   capacity, and where a new machine goes (ADR 0081); check asks each now
  botctl machine host drain <name> [--reason <text>]  Place nothing new on the host; its machines stay until moved (ADR 0081)
  botctl machine host undrain <name>               New machines may go on it again
  botctl machine host dedicate <name> <team-id> [--reason <text>]
                                                   Only that team's machines go on the host, and its machines only on
                                                   hosts dedicated to it (ADR 0166); refused while others' are there
  botctl machine host share <name> --reason <text> Anyone's machines may go on the host again
  botctl machine host recover <name> [--to <host>] [--identity <age-key-file>] --yes
                                                   Declare a host that doesn't answer lost, and restore its machines from
                                                   their newest off-host backups onto another host; they enroll anew
  botctl machine bot-user <user>                   Run its Bots as their own OS user now (MACHINE_BOT_USER), retrying a failure
  botctl machine harness-login <user|me> <claude|codex>  Log the harness in on the machine; the login stays there
  botctl machine harness-logins <user|me>          Which harnesses are logged in on it
  botctl machine harness-logout <user|me> <harness>  Remove that login from it
  botctl machine folder <user>                     The copy of their folder to it: done, running, or failed
  botctl machine sync <user>                       Copy their folder to it again now; files changed there are kept
  botctl machine screens <user>                    Bots' screens open on it (MACHINE_SCREENS), and what its agent reports
  botctl machine screens <user> close <bot>        Close that Bot's screen there now
  botctl machine teammates <user>                  Teammates with their own user on it, and removals of ones who left
  botctl machine teammates <user> remove <teammate>  Remove that teammate's user and home from it now
  botctl machine teammates <user> logins <teammate>  Whether that teammate's own harness logins on it are logged in
  botctl machine teammates <user> logout <teammate> <harness>  Log that teammate's own harness out on it
  botctl machine removals [<state>]                Teammate removals: open (default), pending, held, done, cancelled, all
  botctl secrets                                   List secret names (never values)
  botctl secrets backend                           Where botd reads secrets from (local, Vault, Azure Key
                                                   Vault, GCP or AWS Secrets Manager) and whether it answers now
  botctl secret set <NAME> < value-file            Save a secret, encrypted; Bots get it as $NAME
  botctl secret rm <NAME>                          Delete a saved secret

Classes: shell_destructive, file_delete, outbound_message, network_install, git_push.
Patterns are globs (* and ?) over the command, path, URL, or tool arguments."#;

enum Cred {
    Bot,
    Operator,
    /// Signing in: sends no Authorization, but the body holds a secret, so loopback only.
    Anonymous,
}

fn base() -> String {
    std::env::var("BOT_API").unwrap_or_else(|_| "http://127.0.0.1:3000".into())
}

/// Sends a request to botd and returns the connection, ready for its reply.
fn send(cred: Cred, method: &str, path: &str, body: Option<String>) -> Result<TcpStream, String> {
    let auth = match cred {
        Cred::Bot => match (std::env::var("BOT_API"), std::env::var("BOT_TOKEN")) {
            (Ok(_), Ok(token)) => format!("Bearer {token}"),
            _ => return Err("botctl only works inside a Bot run (BOT_API and BOT_TOKEN are missing).".into()),
        },
        Cred::Operator => operator_auth()?,
        Cred::Anonymous => String::new(),
    };
    let base = base();
    let addr = addr(&base)?;
    let operator = !matches!(cred, Cred::Bot);
    if operator && !loopback(addr) {
        return Err(format!("botctl sends SUPERBOT_TOKEN, SUPERBOT_PASSWORD, and sign-in codes only to a server on this machine, not {addr}. Run it on the server, or set BOT_API to an SSH tunnel on 127.0.0.1."));
    }
    let (mut s, target, via) = match TcpStream::connect(addr) {
        Ok(s) => (s, path.to_string(), String::new()),
        Err(e) => match proxy().filter(|_| !operator) {
            Some(p) => {
                let s = TcpStream::connect(p.addr.as_str()).map_err(|_| format!("Can't reach the server: {e}"))?;
                let via = p.auth.map(|a| format!("Proxy-Authorization: Basic {}\r\n", base64(a.as_bytes()))).unwrap_or_default();
                (s, format!("http://{addr}{path}"), via)
            }
            None => return Err(format!("Can't reach the server: {e}")),
        },
    };
    if operator && !s.peer_addr().is_ok_and(|a| a.ip().is_loopback()) {
        return Err(format!("{addr} isn't on this machine, so botctl won't send credentials there."));
    }
    let auth = if auth.is_empty() { String::new() } else { format!("Authorization: {auth}\r\n") };
    let body = body.unwrap_or_default();
    // BOT_TOKEN is this Bot's own, so it says which Bot is calling (ADR 0029).
    let req = format!(
        "{method} {target} HTTP/1.0\r\nHost: {addr}\r\n{via}{auth}User-Agent: botctl/{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        env!("CARGO_PKG_VERSION"),
        body.len()
    );
    s.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    Ok(s)
}

fn api(cred: Cred, method: &str, path: &str, body: Option<String>) -> Result<String, String> {
    let (code, body) = exchange(cred, method, path, body)?;
    if (200..300).contains(&code) { Ok(body) } else { Err(failure(code, &body)) }
}

/// The status and body of one request, whatever the status.
fn exchange(cred: Cred, method: &str, path: &str, body: Option<String>) -> Result<(u16, String), String> {
    let mut s = send(cred, method, path, body)?;
    let mut res = String::new();
    s.read_to_string(&mut res).map_err(|e| e.to_string())?;
    let (head, body) = res.split_once("\r\n\r\n").unwrap_or((&res, ""));
    let code: u16 = head.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    Ok((code, body.to_string()))
}

/// Like `exchange`, for replies that aren't text: the status, the head and the body's bytes.
fn exchange_bytes(cred: Cred, method: &str, path: &str) -> Result<(u16, String, Vec<u8>), String> {
    let mut s = send(cred, method, path, None)?;
    let mut res = Vec::new();
    s.read_to_end(&mut res).map_err(|e| e.to_string())?;
    let split = res.windows(4).position(|w| w == b"\r\n\r\n").unwrap_or(res.len());
    let head = String::from_utf8_lossy(&res[..split]).to_string();
    let code: u16 = head.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    Ok((code, head, res.get(split + 4..).unwrap_or_default().to_vec()))
}

fn failure(code: u16, body: &str) -> String {
    #[derive(serde::Deserialize)]
    struct Failure {
        error: String,
    }
    let msg = <Failure as serde::Deserialize>::deserialize(&mut serde_json::Deserializer::from_str(body)).map(|f| f.error).unwrap_or(body.into());
    format!("{msg} (HTTP {code})")
}

/// Where `botctl machine harness-login|harness-logins|harness-logout` go: the caller's
/// own machine for `me`, else that user's.
fn login_base(user: &str) -> String {
    if user == "me" { "/api/machine".into() } else { format!("/api/users/{}/machine", encode(user)) }
}

/// `botctl machine harness-login`: runs the harness's login on the user's machine (ADR
/// 0041), showing what it prints here and sending each line typed here to it. The login
/// is saved there only.
fn machine_login(user: &str, harness: &str) -> Result<String, String> {
    let base = login_base(user);
    let s = send(Cred::Operator, "POST", &format!("{base}/harness-login"), Some(json!({ "harness": harness }).to_string()))?;
    let mut r = std::io::BufReader::new(s);
    let mut status = String::new();
    r.read_line(&mut status).map_err(|e| e.to_string())?;
    let code: u16 = status.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0);
    loop {
        let mut h = String::new();
        if r.read_line(&mut h).map_err(|e| e.to_string())? == 0 || h.trim().is_empty() {
            break;
        }
    }
    if !(200..300).contains(&code) {
        let mut body = String::new();
        r.read_to_string(&mut body).map_err(|e| e.to_string())?;
        return Err(failure(code, &body));
    }
    let mut out = std::io::stdout();
    for l in r.lines() {
        let v: Value = serde_json::from_str(&l.map_err(|e| format!("Lost the server: {e}"))?).map_err(|e| e.to_string())?;
        match v["type"].as_str() {
            Some("started") => {
                eprintln!("The {harness} login is running on the user's machine. Type what it asks for and press Enter; Ctrl-C stops it.");
                let input = format!("{base}/harness-login/{}/input", encode(v["loginId"].as_str().unwrap_or_default()));
                std::thread::spawn(move || {
                    for line in std::io::stdin().lines().map_while(Result::ok) {
                        if let Err(e) = api(Cred::Operator, "POST", &input, Some(json!({ "text": line.trim_end() }).to_string())) {
                            eprintln!("Couldn't send that: {e}");
                        }
                    }
                });
            }
            Some("output") => {
                let _ = out.write_all(v["text"].as_str().unwrap_or_default().as_bytes());
                let _ = out.flush();
            }
            Some("error") => eprintln!("\n{}", v["message"].as_str().unwrap_or_default()),
            Some("exit") if v["loggedIn"] == true => return Ok(format!("\nDone. {harness} is logged in on the user's machine; their Bots there use it.")),
            Some("exit") => return Err(format!("\nThe login ended ({}) without saving a {harness} login.", v["status"].as_str().unwrap_or("stopped"))),
            _ => {}
        }
    }
    Err("The server ended the login without saying how it went. See botctl machine harness-logins.".into())
}

/// `botctl user teammates ...` and `botctl user teammate-removals ...` (ADR 0066).
fn teammate_accounts_request(args: &[&str]) -> Result<(&'static str, String), String> {
    Ok(match args {
        ["teammates", user] => ("GET", format!("/api/users/{}/teammate-accounts", encode(user))),
        ["teammates", user, "remove", teammate] => ("POST", format!("/api/users/{}/teammate-accounts/{}/remove", encode(user), encode(teammate))),
        ["teammate-removals"] => ("GET", "/api/isolation/teammate-removals?state=open".into()),
        ["teammate-removals", s @ ("pending" | "held" | "done" | "cancelled" | "open" | "all")] => ("GET", format!("/api/isolation/teammate-removals?state={s}")),
        _ => return Err("Usage: botctl user teammates <user> [remove <teammate>] | teammate-removals [pending|held|done|cancelled|open|all]".into()),
    })
}

/// The extra arguments of `botctl user harness-login`: the owner whose shared Bots the
/// login is for (`--owner`, ADR 0064), if any, and everything after `--`, if anything.
fn login_extra<'a>(rest: &'a [&'a str]) -> Result<(Option<&'a str>, Option<&'a [&'a str]>), String> {
    let usage = || "Usage: botctl user harness-login <user> <claude|codex> [--owner <owner>] [-- <login arguments>...]".to_string();
    let (owner, rest) = match rest {
        ["--owner", o, rest @ ..] if !o.is_empty() && *o != "--" => (Some(*o), rest),
        _ => (None, rest),
    };
    match rest {
        [] => Ok((owner, None)),
        ["--", args @ ..] => Ok((owner, Some(args))),
        _ => Err(usage()),
    }
}

/// `botctl user harness-login`: botd makes the user's account if needed and says how to
/// start the harness's login as it; this runs that here, at the admin's terminal. Only
/// botd's service account may switch to per-user accounts, so run it as that account.
fn harness_login(key: &str, harness: &str, rest: &[&str]) -> Result<String, String> {
    let (owner, args) = login_extra(rest)?;
    let body = json!({ "harness": harness, "args": args, "owner": owner });
    let res = api(Cred::Operator, "POST", &format!("/api/users/{}/harness-login", encode(key)), Some(body.to_string()))?;
    let v: Value = serde_json::from_str(&res).map_err(|e| e.to_string())?;
    let argv: Vec<&str> = v["command"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
    let (Some((bin, args)), Some(home)) = (argv.split_first(), v["home"].as_str()) else {
        return Err(format!("Unexpected reply from the server: {res}"));
    };
    match owner {
        None => eprintln!("Starting the {harness} login as the user's own account (HOME {home}). Only their Bots will use it."),
        Some(o) => eprintln!("Starting the {harness} login as the user's account for {o}'s shared Bots (HOME {home}). Only their runs of those Bots will use it."),
    }
    let mut cmd = std::process::Command::new(bin);
    cmd.args(args).current_dir(home).env_clear();
    for (k, val) in std::env::vars_os() {
        let k_str = k.to_string_lossy();
        if k_str == "TERM" || k_str == "LANG" || k_str.starts_with("LC_") {
            cmd.env(&k, val);
        }
    }
    // sudo resets PATH; superbot-run puts this one back, so the harness is found as botd finds it.
    if let Some(path) = std::env::var_os("PATH") {
        cmd.env("SUPERBOT_PATH", path);
    }
    let status = cmd.status().map_err(|e| format!("Couldn't start {bin}: {e}"))?;
    if status.success() && owner.is_some() {
        Ok(format!("Done. The user's runs of those Bots now use this {harness} login."))
    } else if status.success() {
        Ok(format!("Done. The user's Bots now use this {harness} login."))
    } else {
        Err(format!("The login exited with {status}. If sudo asked for a password, run botctl as botd's service account (sudo -iu <service user>)."))
    }
}

/// A session token from `botctl login` wins over the break-glass password.
fn operator_auth() -> Result<String, String> {
    let var = |k: &str| std::env::var(k).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    match (var("SUPERBOT_TOKEN"), var("SUPERBOT_PASSWORD")) {
        (Some(t), _) => Ok(format!("Bearer {t}")),
        (None, Some(p)) => Ok(format!("Basic {}", base64(format!("superbot:{p}").as_bytes()))),
        _ => Err("Set SUPERBOT_TOKEN (from botctl login <code>), or SUPERBOT_PASSWORD to the server's AUTH_PASSWORD.".into()),
    }
}

/// `botctl login [<code> | -] [--totp <code> | --recovery-code <code>]`: the body for
/// POST /api/auth/login. A second factor goes in the same request (ADR 0094).
fn login_body(args: &[&str]) -> Result<Value, String> {
    const USE: &str = "usage: botctl login [<code> | -] [--totp <code> | --recovery-code <code>]";
    let (arg, rest) = match args.split_first() {
        Some((a, rest)) if !a.starts_with("--") => (Some(*a), rest),
        _ => (None, args),
    };
    let second = match (flag(rest, "--totp"), flag(rest, "--recovery-code")) {
        (Some(_), Some(_)) => return Err(USE.into()),
        (Some(c), None) => Some(("totp", c)),
        (None, Some(c)) => Some(("recoveryCode", c)),
        (None, None) if rest.is_empty() => None,
        _ => return Err(USE.into()),
    };
    if second.is_some() && rest.len() != 2 {
        return Err(USE.into());
    }
    let code = match arg {
        Some("-") => {
            let mut c = String::new();
            std::io::stdin().read_to_string(&mut c).map_err(|e| e.to_string())?;
            Some(c.trim().to_string())
        }
        Some(c) => Some(c.trim().to_string()),
        None => None,
    };
    let body = match code {
        Some(c) if c.is_empty() => return Err("The sign-in code is empty.".into()),
        Some(c) => json!({ "code": c }),
        None => match std::env::var("SUPERBOT_PASSWORD") {
            Ok(p) if !p.is_empty() => json!({ "password": p }),
            _ => return Err("Give a sign-in code (botctl login <code>), or set SUPERBOT_PASSWORD.".into()),
        },
    };
    let mut body = body;
    if let Some((k, c)) = second {
        body[k] = json!(c.trim());
    }
    body["session"] = json!("token");
    body["label"] = json!("botctl");
    Ok(body)
}

/// `botctl login`. When the server asks for a second factor, asks for it here and
/// finishes the same sign-in: a sign-in code is spent by the first step.
fn login(args: &[&str]) -> Result<String, String> {
    let (mut code, mut res) = exchange(Cred::Anonymous, "POST", "/api/auth/login", Some(login_body(args)?.to_string()))?;
    let mut lines = std::io::stdin().lines();
    loop {
        let v: Value = serde_json::from_str(&res).unwrap_or(Value::Null);
        if (200..300).contains(&code) {
            return Ok(signed_in(&v));
        }
        let Some(challenge) = v["challenge"].as_str().filter(|_| code == 401) else { return Err(failure(code, &res)) };
        let enroll = v["mfa"] == "enroll";
        eprintln!("{}", v["error"].as_str().unwrap_or_default());
        if enroll {
            eprintln!("\nAdd this to your authenticator app:\n{}\n", setup_text(&v));
        }
        eprint!("{}", if enroll { "Code: " } else { "Code (or a recovery code): " });
        let _ = std::io::stderr().flush();
        let typed = match lines.next() {
            Some(l) => l.map_err(|e| e.to_string())?,
            None => return Err("No code given. Sign in again.".into()),
        };
        (code, res) = exchange(Cred::Anonymous, "POST", "/api/auth/login", Some(factor_body(challenge, &typed, enroll)?.to_string()))?;
    }
}

/// What someone types or opens to add the account to an authenticator app.
fn setup_text(v: &Value) -> String {
    let field = |k: &str| v[k].as_str().unwrap_or_default().to_string();
    format!("  Setup key: {}\n  {}", field("secret"), field("otpauthUrl"))
}

/// The second step: six digits are an authenticator code, anything else a recovery code.
/// Enrolment takes only an authenticator code.
fn factor_body(challenge: &str, typed: &str, enroll: bool) -> Result<Value, String> {
    let typed = typed.trim();
    if typed.is_empty() {
        return Err("No code given. Sign in again.".into());
    }
    let totp = enroll || (typed.len() == 6 && typed.bytes().all(|b| b.is_ascii_digit()));
    let kind = if totp { "totp" } else { "recoveryCode" };
    Ok(json!({ "challenge": challenge, (kind): typed, "session": "token", "label": "botctl" }))
}

fn signed_in(v: &Value) -> String {
    let (token, who, role) = (v["token"].as_str().unwrap_or_default(), v["user"]["name"].as_str().unwrap_or_default(), v["user"]["role"].as_str().unwrap_or_default());
    let mut out = format!("Signed in as {who} ({role}). Run:\n\n  export SUPERBOT_TOKEN={token}");
    if let Some(codes) = v["recoveryCodes"].as_array() {
        let codes: Vec<&str> = codes.iter().filter_map(Value::as_str).collect();
        out.push_str(&format!("\n\nTwo-factor sign-in is on. Save these recovery codes somewhere safe; each works once and they won't be shown again:\n\n  {}", codes.join("\n  ")));
    }
    out
}

fn role(r: &str) -> Result<&str, String> {
    match r {
        "admin" | "member" | "readonly" | "read-only" => Ok(r),
        _ => Err(format!("Role must be admin, member, or readonly, not \"{r}\".")),
    }
}

/// The `host:port` in BOT_API. botctl speaks plain http only.
fn addr(base: &str) -> Result<&str, String> {
    let a = base.strip_prefix("http://").unwrap_or("").trim_end_matches('/');
    if a.is_empty() || a.contains(['/', '@', '?', '#']) {
        return Err(format!("BOT_API should look like http://127.0.0.1:3000, not {base}"));
    }
    Ok(a)
}

/// An HTTP proxy on this machine, from `HTTP_PROXY`.
struct Proxy {
    addr: String,
    /// `user:password`, decoded.
    auth: Option<String>,
}

/// A sandboxed run (ADR 0055) may reach botd only through its harness's proxy: Claude
/// Code's runs commands in their own network, with `HTTP_PROXY` pointing at a proxy that
/// lets through the hosts it's told about. Only a proxy on this machine gets BOT_TOKEN;
/// plain http to one elsewhere would show it to the network.
fn proxy() -> Option<Proxy> {
    let url = std::env::var("HTTP_PROXY").or_else(|_| std::env::var("http_proxy")).ok()?;
    parse_proxy(&url)
}

fn parse_proxy(url: &str) -> Option<Proxy> {
    let rest = url.strip_prefix("http://")?.trim_end_matches('/');
    let (auth, addr) = match rest.rsplit_once('@') {
        Some((a, h)) => (Some(a), h),
        None => (None, rest),
    };
    (!addr.is_empty() && !addr.contains(['/', '?', '#']) && loopback(addr)).then(|| Proxy { addr: addr.to_string(), auth: auth.map(unescape) })
}

/// Percent-decodes `s`; a malformed escape stays as written.
fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match (b[i], b.get(i + 1..i + 3).and_then(|h| std::str::from_utf8(h).ok()).and_then(|h| u8::from_str_radix(h, 16).ok())) {
            (b'%', Some(x)) => {
                out.push(x);
                i += 3;
            }
            (c, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Whether `addr` names this machine. Plain http crosses any network in the clear,
/// so the operator password only goes to loopback.
fn loopback(addr: &str) -> bool {
    let host = match addr.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or_default(),
        None => addr.rsplit_once(':').map_or(addr, |(h, _)| h),
    };
    host.eq_ignore_ascii_case("localhost") || host.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

fn base64(b: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            out.push(if i <= c.len() { T[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
        }
    }
    out
}

fn pretty(body: String) -> String {
    serde_json::from_str::<Value>(&body).ok().and_then(|v| serde_json::to_string_pretty(&v).ok()).unwrap_or(body)
}

/// The approval gate. The harness pipes its PreToolUse event on stdin; botd decides,
/// waiting for the user if needed. Exit 0 allows. Anything else must block, so every
/// failure (no server, bad reply) exits 2 with the reason on stderr.
/// `--cwd` names the folder the tool runs in, for harnesses whose hook runs elsewhere.
fn hook(harness: &str, cwd: Option<&str>) -> ! {
    let mut event = String::new();
    let verdict = std::io::stdin()
        .read_to_string(&mut event)
        .map_err(|e| e.to_string())
        .and_then(|_| hook_body(harness, &std::env::var("BOT_ID").unwrap_or_default(), std::env::var("SUPERBOT_RUN_ID").ok().as_deref(), &event, cwd))
        .and_then(|body| api(Cred::Bot, "POST", "/api/approvals/check", Some(body)));
    match verdict {
        Ok(r) if r.lines().next() == Some("allow") => std::process::exit(0),
        Ok(r) => {
            let reason = r.split_once('\n').map(|(_, r)| r.trim()).filter(|r| !r.is_empty()).unwrap_or("Blocked by SuperBot policy.");
            eprintln!("{reason}");
        }
        Err(e) => eprintln!("SuperBot's approval gate failed, so this action was blocked: {e}"),
    }
    std::process::exit(2)
}

/// `run`: the run this hook is part of, so what a person approved for that run counts
/// only there (ADR 0051).
fn hook_body(harness: &str, bot: &str, run: Option<&str>, event: &str, cwd: Option<&str>) -> Result<String, String> {
    let mut event = serde_json::from_str::<Value>(event).map_err(|e| format!("bad hook input: {e}"))?;
    if let Some(cwd) = cwd {
        if !cwd.starts_with('/') {
            return Err(format!("--cwd must be an absolute path, not {cwd}"));
        }
        let obj = event.as_object_mut().ok_or("bad hook input: not a JSON object")?;
        obj.insert("cwd".into(), json!(cwd));
    }
    Ok(json!({ "from": bot, "harness": harness, "run": run.filter(|r| !r.is_empty()), "event": event }).to_string())
}

fn policy_patch(args: &[&str]) -> Result<Value, String> {
    let mut patch = Map::new();
    let mut classes = Map::new();
    for a in args {
        let (k, v) = a.split_once('=').ok_or(format!("Expected key=value, got \"{a}\""))?;
        // `inherit` puts a Bot's field back to following the global policy.
        let inherit = v == "inherit";
        match k {
            "mode" => _ = patch.insert("mode".into(), if inherit { Value::Null } else { json!(v) }),
            "sandbox" => {
                let on = match v {
                    "inherit" => Value::Null,
                    "on" => json!(true),
                    "off" => json!(false),
                    _ => return Err("sandbox must be on, off, or inherit".into()),
                };
                patch.insert("sandbox".into(), on);
            }
            "timeout" if inherit => _ = patch.insert("timeoutMinutes".into(), Value::Null),
            "timeout" => _ = patch.insert("timeoutMinutes".into(), json!(v.parse::<u64>().map_err(|_| "timeout must be minutes")?)),
            class => _ = classes.insert(class.into(), if inherit { Value::Null } else { json!(v) }),
        }
    }
    if !classes.is_empty() {
        patch.insert("classes".into(), Value::Object(classes));
    }
    if patch.is_empty() {
        return Err("Nothing to set. Example: botctl policy set global mode=ask timeout=15 git_push=deny".into());
    }
    Ok(Value::Object(patch))
}

/// Percent-encodes a query string value.
fn encode(v: &str) -> String {
    v.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'*' | b',' | b':' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// `botctl audit` options as a query string: `[<limit>] [--from <t>] [--action <a>] ...`.
fn audit_query(rest: &[&str]) -> Result<String, String> {
    let mut pairs = Vec::new();
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        match *a {
            "--from" | "--to" | "--action" | "--actor" | "--method" | "--idp" | "--idp-provider" | "--subject" | "--session" | "--on-behalf-of" | "--outcome"
            | "--bot" | "--limit" => {
                let v = it.next().ok_or(format!("{a} needs a value"))?;
                let key = match *a {
                    "--idp-provider" => "idpProvider",
                    "--on-behalf-of" => "onBehalfOf",
                    k => &k[2..],
                };
                pairs.push(format!("{key}={}", encode(v)));
            }
            n if n.parse::<u32>().is_ok() => pairs.push(format!("limit={n}")),
            other => return Err(format!("Unknown audit option \"{other}\". See botctl admin.")),
        }
    }
    Ok(if pairs.is_empty() { String::new() } else { format!("?{}", pairs.join("&")) })
}

/// `botctl audit verify [--pin <id>:<hash>]... [--from <id>] [--to <id>] [--key <hex>]... [--archive]`:
/// hashes kept elsewhere (a SIEM, an earlier check) to hold the chain to, the event ids
/// to check, the checkpoint keys to trust instead of botd's own, and whether to read the
/// write-once archive too (ADR 0163).
fn verify_query(rest: &[&str]) -> Result<String, String> {
    let (mut pins, mut keys, mut pairs) = (Vec::new(), Vec::new(), Vec::new());
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        match *a {
            "--pin" => pins.push(encode(it.next().ok_or("--pin needs <event id>:<hash>")?)),
            "--key" => keys.push(encode(it.next().ok_or("--key needs a public key in hex (botctl audit key)")?)),
            "--archive" => pairs.push("archive=on".into()),
            o @ ("--from" | "--to") => {
                let id = it.next().filter(|v| v.parse::<i64>().is_ok()).ok_or_else(|| format!("{o} needs an event id"))?;
                pairs.push(format!("{}={id}", &o[2..]));
            }
            other => return Err(format!("Unknown audit verify option \"{other}\". See botctl admin.")),
        }
    }
    if !pins.is_empty() {
        pairs.insert(0, format!("pin={}", pins.join(",")));
    }
    if !keys.is_empty() {
        pairs.push(format!("key={}", keys.join(",")));
    }
    Ok(if pairs.is_empty() { String::new() } else { format!("?{}", pairs.join("&")) })
}

fn flag<'a>(rest: &[&'a str], name: &str) -> Option<&'a str> {
    rest.windows(2).find(|w| w[0] == name).map(|w| w[1])
}

/// `botctl regions`, `botctl user region ...` and `botctl team region ...` (ADR 0117): the request to send.
fn region_request(args: &[&str]) -> Option<(&'static str, String, Option<String>)> {
    let pick = |r: &str| json!({ "region": if r == "default" { Value::Null } else { json!(r) } }).to_string();
    Some(match args {
        ["regions"] => ("GET", "/api/regions".into(), None),
        ["user", "region", key] => ("GET", format!("/api/users/{}/region", encode(key)), None),
        ["user", "region", key, r] => ("PUT", format!("/api/users/{}/region", encode(key)), Some(pick(r))),
        ["team", "region", id] => ("GET", format!("/api/teams/{}/region", encode(id)), None),
        ["team", "region", id, r] => ("PUT", format!("/api/teams/{}/region", encode(id)), Some(pick(r))),
        [kind @ ("user" | "team"), "residency", key, rest @ ..] => {
            let path = format!("/api/{kind}s/{}/residency", encode(key));
            match rest {
                [] => ("GET", path, None),
                ["pin", region, reference @ ..] if !reference.is_empty() => ("PUT", path, Some(json!({ "region": region, "reference": reference.join(" ") }).to_string())),
                ["unpin", reason @ ..] if !reason.is_empty() => ("DELETE", path, Some(json!({ "reason": reason.join(" ") }).to_string())),
                _ => return None,
            }
        }
        _ => return None,
    })
}

/// `botctl user|team residency <key> report [--from <when>] [--to <when>] [--json] [-o <file>]`
/// (ADR 0155): the path, and the file to save it in.
fn residency_report_request<'a>(kind: &str, key: &str, rest: &[&'a str]) -> Result<(String, Option<&'a str>), String> {
    let usage = || format!("Usage: botctl {kind} residency <{kind}> report [--from <when>] [--to <when>] [--json] [-o <file>]");
    let (mut pairs, mut json, mut out) = (Vec::new(), false, None);
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        match *a {
            "--json" => json = true,
            f @ ("--from" | "--to") => pairs.push(format!("{}={}", &f[2..], encode(it.next().ok_or_else(usage)?))),
            "-o" | "--out" => out = Some(*it.next().ok_or_else(usage)?),
            _ => return Err(usage()),
        }
    }
    if !json {
        pairs.push("format=markdown".into());
    }
    let q = if pairs.is_empty() { String::new() } else { format!("?{}", pairs.join("&")) };
    Ok((format!("/api/{kind}s/{}/residency/report{q}", encode(key)), out))
}

/// `botctl machine egress ...` and `botctl user egress ...` (ADR 0135): the request to send.
fn egress_request(args: &[&str]) -> Option<(&'static str, String, Option<String>)> {
    let set = |mode: &str, allow: &[&str]| Some(json!({ "mode": mode, "allow": allow }).to_string());
    let user = |key: &str| format!("/api/users/{}/machine/egress-policy", encode(key));
    Some(match args {
        ["machine", "egress"] => ("GET", "/api/machines/egress-policy".into(), None),
        ["machine", "egress", "open"] => ("PUT", "/api/machines/egress-policy".into(), set("open", &[])),
        ["machine", "egress", "allow", allow @ ..] if !allow.is_empty() => ("PUT", "/api/machines/egress-policy".into(), set("allow_list", allow)),
        ["user", "egress", key] => ("GET", user(key), None),
        ["user", "egress", key, m @ ("open" | "inherit")] => ("PUT", user(key), set(m, &[])),
        ["user", "egress", key, "allow", allow @ ..] if !allow.is_empty() => ("PUT", user(key), set("allow_list", allow)),
        _ => return None,
    })
}

/// `botctl tiers move-bots <tier> [--user <user>] [--dry-run]` (ADR 0079): the path and body.
fn move_bots_request(args: &[&str]) -> Result<(String, String), String> {
    const USE: &str = "usage: botctl tiers move-bots <tier> [--user <user>] [--dry-run]";
    let (tier, rest) = args.split_first().filter(|(t, _)| !t.starts_with("--")).ok_or(USE)?;
    let user = flag(rest, "--user");
    let known = rest.iter().enumerate().all(|(i, a)| *a == "--dry-run" || *a == "--user" || (i > 0 && rest[i - 1] == "--user"));
    if !known || (rest.contains(&"--user") && user.is_none_or(|u| u.starts_with("--"))) {
        return Err(USE.into());
    }
    let body = json!({ "user": user, "dryRun": rest.contains(&"--dry-run") });
    Ok((format!("/api/tiers/{}/move-bots", encode(tier)), body.to_string()))
}

/// `botctl bot ...`: who owns and can see a Bot (ADR 0017). The request to send.
fn bot_access(args: &[&str]) -> Result<(&'static str, String, Option<String>), String> {
    let access = |bot: &str| format!("/api/bots/{}/access", encode(bot));
    let grant = |bot: &str, user: &str| format!("/api/bots/{}/grants/{}", encode(bot), encode(user));
    Ok(match args {
        ["access", bot] => ("GET", access(bot), None),
        [v @ ("share" | "private"), bot] => {
            let visibility = if *v == "share" { "shared" } else { "private" };
            ("PATCH", access(bot), Some(json!({ "visibility": visibility }).to_string()))
        }
        ["owner", bot, user] => ("PATCH", access(bot), Some(json!({ "owner": user }).to_string())),
        ["grant", bot, user, level @ ("viewer" | "operator")] => ("PUT", grant(bot, user), Some(json!({ "level": level }).to_string())),
        ["grant", ..] => return Err("Usage: botctl bot grant <bot> <user> <viewer|operator>".into()),
        ["revoke", bot, user] => ("DELETE", grant(bot, user), None),
        _ => return Err("Unknown bot command. See botctl admin.".into()),
    })
}

/// `botctl machine ...`: which computer each user's Bots run on (ADR 0036), and its
/// agent's harnesses and upgrades (ADR 0039).
fn machine_request(args: &[&str]) -> Result<(&'static str, String), String> {
    let at = |user: &str| format!("/api/users/{}/placement", encode(user));
    let machine = |user: &str, rest: &str| format!("/api/users/{}/machine/{rest}", encode(user));
    Ok(match args {
        ["placement"] | ["placements"] => ("GET", "/api/machines/placements".into()),
        ["placement", user] => ("GET", at(user)),
        ["assign", user] => ("PUT", at(user)),
        ["unassign", user] => ("DELETE", at(user)),
        ["agent", user] => ("GET", machine(user, "agent")),
        ["upgrade", user] => ("POST", machine(user, "agent/upgrade")),
        ["upgrade", user, "hold"] => ("PUT", machine(user, "agent/hold")),
        ["upgrade", user, "release"] => ("DELETE", machine(user, "agent/hold")),
        ["harnesses", user] => ("POST", machine(user, "harnesses")),
        ["mirror"] | ["mirror", "check"] => ("GET", "/api/machines/harness-mirror".into()),
        ["bot-user", user] => ("POST", machine(user, "bot-user")),
        ["folder", user] => ("GET", machine(user, "folder-sync")),
        ["sync", user] => ("POST", machine(user, "folder-sync")),
        ["screens", user] => ("GET", machine(user, "screens")),
        ["screens", user, "close", bot] => ("DELETE", machine(user, &format!("screens/{}", encode(bot)))),
        ["teammates", user] => ("GET", machine(user, "teammates")),
        ["teammates", user, "remove", teammate] => ("POST", machine(user, &format!("teammates/{}/remove", encode(teammate)))),
        ["teammates", user, "logins", teammate] => ("GET", machine(user, &format!("teammates/{}/harness-logins", encode(teammate)))),
        ["teammates", user, "logout", teammate, harness] => {
            ("DELETE", machine(user, &format!("teammates/{}/harness-logins/{}", encode(teammate), encode(harness))))
        }
        ["removals"] => ("GET", "/api/machines/teammate-removals?state=open".into()),
        ["removals", s @ ("pending" | "held" | "done" | "cancelled" | "open" | "all")] => ("GET", format!("/api/machines/teammate-removals?state={s}")),
        _ => {
            return Err("Usage: botctl machine placement [<user>] | assign <user> | unassign <user> | agent <user> | upgrade <user> [hold|release] | harnesses <user> | mirror | legacy | rebuild <user> [--discard-work|status|cancel] | bot-user <user> | harness-login <user|me> <claude|codex> | harness-logins <user|me> | harness-logout <user|me> <harness> | folder <user> | sync <user> | screens <user> [close <bot>] | teammates <user> [remove <teammate> | logins <teammate> | logout <teammate> <harness>] | removals [pending|held|done|cancelled|open|all]".into());
        }
    })
}

type Request = (&'static str, String, Option<String>);

/// `botctl machine list|show|request|suspend|resume|resize|destroy|enroll|revoke|substrate|reconcile`:
/// the machine itself (ADR 0025, ADR 0065) and its enrollment (ADR 0031). None: not one of these.
fn lifecycle_request(args: &[&str]) -> Option<Result<Request, String>> {
    let at = |user: &str, rest: &str| format!("/api/users/{}/machine{rest}", encode(user));
    Some(Ok(match args {
        ["list"] => ("GET", "/api/machines".into(), None),
        ["list", state] => ("GET", format!("/api/machines?state={}", encode(state)), None),
        ["show", user] => ("GET", at(user, ""), None),
        ["request", user, rest @ ..] if rest.len() <= 2 => {
            let mut b = json!({});
            if let Some(tier) = rest.first() {
                b["tier"] = json!(tier);
            }
            if let Some(region) = rest.get(1) {
                b["region"] = json!(region);
            }
            ("POST", at(user, ""), Some(b.to_string()))
        }
        ["suspend", user] => ("POST", at(user, "/suspend"), None),
        ["resume", user] => ("POST", at(user, "/resume"), None),
        ["resize", user, "status"] => ("GET", at(user, "/resize"), None),
        ["resize", user, tier] => ("POST", at(user, "/resize"), Some(json!({ "tier": tier }).to_string())),
        ["resizes"] => ("GET", "/api/machines/resizes".into(), None),
        ["destroy", user, "--yes"] => ("DELETE", at(user, ""), None),
        ["enroll", user] => ("POST", at(user, "/enrollment"), None),
        ["revoke", user, "--yes"] => ("DELETE", at(user, "/certificates"), None),
        ["substrate"] => ("GET", "/api/machines/substrate".into(), None),
        ["substrate", "check"] => ("GET", "/api/machines/substrate?check=true".into(), None),
        ["reconcile"] => ("POST", "/api/machines/reconcile".into(), None),
        ["list" | "show" | "request" | "suspend" | "resume" | "resize" | "resizes" | "destroy" | "enroll" | "revoke" | "substrate" | "reconcile", ..] => {
            return Some(Err("Usage: botctl machine list [<state>] | show <user> | request <user> [<tier>] [<region>] | suspend <user> | resume <user> | resize <user> <tier>|status | resizes | destroy <user> --yes | enroll <user> | revoke <user> --yes | substrate [check] | reconcile".into()));
        }
        _ => return None,
    }))
}

/// `botctl machine rebuild ...` (ADR 0056): the request to send.
fn rebuild_request(args: &[&str]) -> Result<(&'static str, String, Option<String>), String> {
    let at = |user: &str| format!("/api/users/{}/machine/rebuild", encode(user));
    Ok(match args {
        [user] if !user.starts_with("--") => ("POST", at(user), None),
        [user, "--discard-work"] => ("POST", format!("{}?discardWork=true", at(user)), None),
        [user, "status"] => ("GET", at(user), None),
        [user, "cancel"] => ("DELETE", at(user), None),
        _ => return Err("Usage: botctl machine rebuild <user> [--discard-work] | rebuild <user> status|cancel".into()),
    })
}

/// `botctl machine backups|backup|recovery|restore ...` (ADR 0071, 0074): the request to send. The
/// identity file is read here and sent for this restore only.
fn backup_request(args: &[&str], read: impl Fn(&str) -> Result<String, String>) -> Result<(&'static str, String, Option<String>), String> {
    let at = |user: &str, verb: &str| format!("/api/users/{}/machine/{verb}", encode(user));
    Ok(match args {
        ["backups"] => ("GET", "/api/machines/backups".into(), None),
        ["recovery"] => ("GET", "/api/machines/recovery".into(), None),
        ["backups", user] => ("GET", at(user, "backups"), None),
        ["backup", user] => ("POST", at(user, "backups"), None),
        ["restore", user, "status"] => ("GET", at(user, "restore"), None),
        ["delete-backups", id, "--yes"] | ["delete-backups", "--yes", id] if !id.starts_with("--") => {
            ("DELETE", format!("/api/machines/{}/backups", encode(id)), None)
        }
        ["delete-backups", id] if !id.starts_with("--") => {
            return Err("Deleting a destroyed machine's backups can't be undone, and nothing can be restored from them after; add --yes".into());
        }
        ["restore", user, id, rest @ ..] if !id.starts_with("--") && rest.contains(&"--yes") => {
            let identity = match rest.iter().position(|a| *a == "--identity") {
                Some(i) => Some(read(rest.get(i + 1).filter(|f| !f.starts_with("--")).ok_or("--identity needs a file")?)?),
                None => None,
            };
            let mut body = json!({ "backupId": id, "identity": identity });
            if let Some(h) = flag(rest, "--host") {
                body["host"] = json!(h);
            }
            ("POST", at(user, "restore"), Some(body.to_string()))
        }
        ["hosts"] => ("GET", "/api/machines/hosts".into(), None),
        ["hosts", "check"] => ("GET", "/api/machines/hosts?check=true".into(), None),
        ["host", "recover", name, rest @ ..] if !name.starts_with("--") && rest.contains(&"--yes") => {
            let identity = match rest.iter().position(|a| *a == "--identity") {
                Some(i) => Some(read(rest.get(i + 1).filter(|f| !f.starts_with("--")).ok_or("--identity needs a file")?)?),
                None => None,
            };
            let body = json!({ "to": flag(rest, "--to"), "identity": identity });
            ("POST", format!("/api/machines/hosts/{}/recover", encode(name)), Some(body.to_string()))
        }
        ["host", "drain", name, rest @ ..] if !name.starts_with("--") => {
            ("PUT", format!("/api/machines/hosts/{}/drain", encode(name)), Some(json!({ "reason": flag(rest, "--reason") }).to_string()))
        }
        ["host", "undrain", name] if !name.starts_with("--") => ("DELETE", format!("/api/machines/hosts/{}/drain", encode(name)), None),
        ["host", "dedicate", name, team, rest @ ..] if !name.starts_with("--") && !team.starts_with("--") => {
            let body = json!({ "team": team, "reason": flag(rest, "--reason") });
            ("PUT", format!("/api/machines/hosts/{}/dedication", encode(name)), Some(body.to_string()))
        }
        ["host", "share", name, rest @ ..] if !name.starts_with("--") => {
            let reason = flag(rest, "--reason").ok_or("A dedication is often a promise to a customer: say why it ends with --reason <text>")?;
            ("DELETE", format!("/api/machines/hosts/{}/dedication", encode(name)), Some(json!({ "reason": reason }).to_string()))
        }
        ["host", "recover", _, ..] => {
            return Err("Recovering declares the host lost for good and restores its machines elsewhere from their backups; add --yes".into());
        }
        ["restore", _, _, ..] => return Err("Restoring replaces the machine and everything on it since the backup; add --yes".into()),
        _ => return Err(
            "Usage: botctl machine backups [<user>] | backup <user> | recovery | restore <user> <backup-id> [--identity <file>] [--host <name>] --yes | restore <user> status | delete-backups <machine-id> --yes | hosts [check] | host drain <name> [--reason <text>] | host undrain <name> | host dedicate <name> <team-id> [--reason <text>] | host share <name> --reason <text> | host recover <name> [--to <host>] [--identity <file>] --yes"
                .into(),
        ),
    })
}

/// `botctl signup ...`: people who asked for access on the get-started page (ADR 0022).
fn signup_request(args: &[&str]) -> Result<(&'static str, String, Option<String>), String> {
    let at = |id: &str, verb: &str| format!("/api/signups/{}/{verb}", encode(id));
    Ok(match args {
        [] | ["list"] => ("GET", "/api/signups?status=pending".into(), None),
        ["list", "all"] => ("GET", "/api/signups".into(), None),
        ["list", s @ ("pending" | "approved" | "rejected")] => ("GET", format!("/api/signups?status={s}"), None),
        ["approve", id, rest @ ..] => {
            let ttl = flag(rest, "--ttl").map(|t| t.parse::<u32>().map_err(|_| "--ttl must be minutes")).transpose()?;
            let body = json!({ "role": flag(rest, "--role").map(role).transpose()?, "ttlMinutes": ttl });
            ("POST", at(id, "approve"), Some(body.to_string()))
        }
        ["reject", id, rest @ ..] => ("POST", at(id, "reject"), Some(json!({ "reason": flag(rest, "--reason") }).to_string())),
        _ => return Err("Usage: botctl signup list [pending|approved|rejected|all] | approve <id> [--role R] [--ttl M] | reject <id> [--reason TEXT]".into()),
    })
}

/// `botctl scim ...`: SCIM provisioning tokens (ADR 0023), links from SCIM groups to
/// teams (ADR 0095), group roles (ADR 0138), role groups (ADR 0180), and the Google
/// Workspace sync (ADR 0162).
fn scim_request(args: &[&str]) -> Result<(&'static str, String, Option<String>), String> {
    Ok(match args {
        [] | ["tokens"] | ["token", "list"] => ("GET", "/api/scim/tokens".into(), None),
        ["groups"] | ["group", "list"] => ("GET", "/api/scim/groups".into(), None),
        ["group", "link", tenant, team, rest @ ..] if !tenant.starts_with("--") && !team.starts_with("--") => {
            let body = json!({ "tenant": tenant, "team": team, "externalId": flag(rest, "--external-id"), "displayName": flag(rest, "--name") });
            ("POST", "/api/scim/groups".into(), Some(body.to_string()))
        }
        ["group", "unlink", team] => ("DELETE", format!("/api/scim/groups/{}", encode(team)), None),
        ["role-mappings"] | ["role", "list"] => ("GET", "/api/scim/role-mappings".into(), None),
        ["role", "map", team, role, rest @ ..] if !team.starts_with("--") && !role.starts_with("--") && rest.iter().all(|a| *a == "--org") => {
            let body = json!({ "team": team, "role": role, "scope": if rest.is_empty() { "team" } else { "org" } });
            ("POST", "/api/scim/role-mappings".into(), Some(body.to_string()))
        }
        ["role", "show", id] => ("GET", format!("/api/scim/role-mappings/{}", encode(id)), None),
        ["role", "unmap", id] => ("DELETE", format!("/api/scim/role-mappings/{}", encode(id)), None),
        ["role-groups"] | ["role-group", "list"] => ("GET", "/api/scim/role-groups".into(), None),
        ["role-group", "add", tenant, group, role, rest @ ..] if [tenant, group, role].iter().all(|a| !a.starts_with("--")) && matches!(rest, [] | ["--external-id", _]) => {
            let body = json!({ "tenant": tenant, "displayName": group, "role": role, "externalId": flag(rest, "--external-id") });
            ("POST", "/api/scim/role-groups".into(), Some(body.to_string()))
        }
        ["role-group", "show", id] => ("GET", format!("/api/scim/role-groups/{}", encode(id)), None),
        ["role-group", "set-role", id, role] => ("PATCH", format!("/api/scim/role-groups/{}", encode(id)), Some(json!({ "role": role }).to_string())),
        ["role-group", "remove", id] => ("DELETE", format!("/api/scim/role-groups/{}", encode(id)), None),
        ["token", "create", tenant, rest @ ..] if !tenant.starts_with("--") => {
            let body = json!({ "tenant": tenant, "sso": flag(rest, "--sso"), "label": flag(rest, "--label") });
            ("POST", "/api/scim/tokens".into(), Some(body.to_string()))
        }
        ["token", "revoke", id] => ("DELETE", format!("/api/scim/tokens/{}", encode(id)), None),
        ["google"] | ["google", "status"] => ("GET", "/api/scim/google".into(), None),
        ["google", "sync"] => ("POST", "/api/scim/google/sync".into(), Some(json!({}).to_string())),
        ["google", "sync", "--force"] => ("POST", "/api/scim/google/sync".into(), Some(json!({ "force": true }).to_string())),
        _ => {
            return Err("Usage: botctl scim tokens | token create <tenant> [--sso <provider>] [--label TEXT] | token revoke <id> | groups | group link <tenant> <team> [--external-id ID] [--name NAME] | group unlink <team> | role-mappings | role map <team> <role> [--org] | role show <id> | role unmap <id> | role-groups | role-group add <tenant> <group> <role> [--external-id ID] | role-group show <id> | role-group set-role <id> <role> | role-group remove <id> | google [status] | google sync [--force]".into());
        }
    })
}

/// `botctl sso role-mappings` and `botctl sso role ...`: SAML groups mapped to custom roles (ADR 0160).
fn sso_role_request(args: &[&str]) -> Result<(&'static str, String, Option<String>), String> {
    Ok(match args {
        ["role-mappings"] | ["role", "list"] => ("GET", "/api/sso/role-mappings".into(), None),
        ["role", "map", provider, group, role] => ("POST", "/api/sso/role-mappings".into(), Some(json!({ "provider": provider, "group": group, "role": role }).to_string())),
        ["role", "show", id] => ("GET", format!("/api/sso/role-mappings/{}", encode(id)), None),
        ["role", "unmap", id] => ("DELETE", format!("/api/sso/role-mappings/{}", encode(id)), None),
        _ => return Err("Usage: botctl sso saml <provider> [json] | sso saml <provider> import [<file> | -] | sso saml <provider> key next|promote|cancel|retire signing|encryption | sso role-mappings | sso role map <provider> <group> <role> | sso role show <id> | sso role unmap <id>".into()),
    })
}

/// `botctl roles` and `botctl role ...`: custom roles (ADR 0123, 0132). The server checks
/// every name and permission; this only shapes the request.
fn role_request(args: &[&str]) -> Result<(&'static str, String, Option<String>), String> {
    const USAGE: &str = "Usage: botctl roles | role show <role> | role add \"<name>\" [--base member|readonly] [--perms a,b] [--description TEXT] | role edit <role> [--name NAME] [--base B] [--perms a,b|none] [--description TEXT] | role rm <role> | role assign|unassign <role> <user> [--team <team>]";
    let perms = |v: &str| -> Value {
        if v == "none" {
            return json!([]);
        }
        json!(v.split(',').map(str::trim).filter(|p| !p.is_empty()).collect::<Vec<_>>())
    };
    let at = |id: &str| format!("/api/roles/{}", encode(id));
    let holder = |id: &str, user: &str, rest: &[&str]| match flag(rest, "--team") {
        Some(team) => format!("{}/teams/{}/users/{}", at(id), encode(team), encode(user)),
        None => format!("{}/users/{}", at(id), encode(user)),
    };
    let known = |rest: &[&str], allowed: &[&str]| -> Result<(), String> {
        let mut it = rest.iter();
        while let Some(a) = it.next() {
            if !allowed.contains(a) || it.next().is_none() {
                return Err(format!("Unexpected \"{a}\". {USAGE}"));
            }
        }
        Ok(())
    };
    Ok(match args {
        [] | ["list"] => ("GET", "/api/roles".into(), None),
        ["show", id] => ("GET", at(id), None),
        ["add", name, rest @ ..] if !name.starts_with("--") => {
            known(rest, &["--base", "--perms", "--description"])?;
            let body = json!({ "name": name, "base": flag(rest, "--base"), "description": flag(rest, "--description"), "permissions": perms(flag(rest, "--perms").unwrap_or("none")) });
            ("POST", "/api/roles".into(), Some(body.to_string()))
        }
        ["edit", id, rest @ ..] if !id.starts_with("--") && !rest.is_empty() => {
            known(rest, &["--name", "--base", "--perms", "--description"])?;
            let mut body = Map::new();
            for (opt, field) in [("--name", "name"), ("--base", "base"), ("--description", "description")] {
                if let Some(v) = flag(rest, opt) {
                    body.insert(field.into(), json!(v));
                }
            }
            if let Some(v) = flag(rest, "--perms") {
                body.insert("permissions".into(), perms(v));
            }
            ("PATCH", at(id), Some(Value::Object(body).to_string()))
        }
        ["rm" | "delete", id] => ("DELETE", at(id), None),
        [verb @ ("assign" | "unassign"), id, user, rest @ ..] if !user.starts_with("--") => {
            known(rest, &["--team"])?;
            (if *verb == "assign" { "PUT" } else { "DELETE" }, holder(id, user, rest), None)
        }
        _ => return Err(USAGE.into()),
    })
}

/// What `botctl role assign|unassign` prints.
fn role_assigned(verb: &str, res: &Value) -> String {
    let who = res["user"]["email"].as_str().or(res["user"]["name"].as_str()).unwrap_or_default();
    let team = res["team"]["name"].as_str();
    match (verb, team) {
        ("assign", Some(t)) => format!(
            "{who} has {} in {t}. There it gives: {}.",
            res["role"]["name"].as_str().unwrap_or_default(),
            res["applies"].as_array().filter(|a| !a.is_empty()).map_or("nothing (it has no team permissions)".into(), |a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", ")),
        ),
        ("assign", None) => format!("{who} has {} now; their role is {}.", res["role"]["name"].as_str().unwrap_or_default(), res["user"]["role"].as_str().unwrap_or_default()),
        (_, Some(t)) => format!("Taken away from {who} in {t}."),
        _ => format!("Taken away. {who} keeps {} as their role.", res["user"]["role"].as_str().unwrap_or_default()),
    }
}

/// `botctl service-accounts` and `botctl service-account ...` (ADR 0143). The server checks
/// every role, scope and limit; this only shapes the request.
fn service_account_request(args: &[&str]) -> Result<(&'static str, String, Option<String>), String> {
    const USAGE: &str = "Usage: botctl service-accounts | service-account show <sa> | service-account add \"<name>\" [--role member|readonly|<custom role>] [--team <team>] [--description TEXT] | service-account edit <sa> [--name NAME] [--role R] [--team <team>|none] [--owner <user>] [--description TEXT] | service-account disable|enable|rm <sa> | service-account token list <sa> | token add <sa> [--name NAME] [--scopes a,b] [--days N] | token rotate <sa> <token> [--days N] [--keep-old <minutes>] | token revoke <sa> <token>";
    let at = |id: &str| format!("/api/service-accounts/{}", encode(id));
    let known = |rest: &[&str], allowed: &[&str]| -> Result<(), String> {
        let mut it = rest.iter();
        while let Some(a) = it.next() {
            if !allowed.contains(a) || it.next().is_none() {
                return Err(format!("Unexpected \"{a}\". {USAGE}"));
            }
        }
        Ok(())
    };
    let number = |rest: &[&str], opt: &str| -> Result<Option<i64>, String> { flag(rest, opt).map(|v| v.parse::<i64>().map_err(|_| format!("{opt} takes a whole number"))).transpose() };
    let named = |id: &str| !id.starts_with("--");
    Ok(match args {
        [] | ["list"] => ("GET", "/api/service-accounts".into(), None),
        ["show", id] => ("GET", at(id), None),
        ["add", name, rest @ ..] if named(name) => {
            known(rest, &["--role", "--team", "--description"])?;
            let body = json!({ "name": name, "role": flag(rest, "--role"), "team": flag(rest, "--team"), "description": flag(rest, "--description") });
            ("POST", "/api/service-accounts".into(), Some(body.to_string()))
        }
        ["edit", id, rest @ ..] if named(id) && !rest.is_empty() => {
            known(rest, &["--name", "--role", "--team", "--owner", "--description"])?;
            let mut body = Map::new();
            for (opt, field) in [("--name", "name"), ("--role", "role"), ("--owner", "owner"), ("--description", "description")] {
                if let Some(v) = flag(rest, opt) {
                    body.insert(field.into(), json!(v));
                }
            }
            if let Some(t) = flag(rest, "--team") {
                body.insert("team".into(), if t == "none" { Value::Null } else { json!(t) });
            }
            ("PATCH", at(id), Some(Value::Object(body).to_string()))
        }
        [verb @ ("disable" | "enable"), id] => ("PATCH", at(id), Some(json!({ "status": if *verb == "disable" { "disabled" } else { "active" } }).to_string())),
        ["rm" | "delete", id] => ("DELETE", at(id), None),
        ["token" | "tokens", "list", id] | ["tokens", id] => ("GET", format!("{}/tokens", at(id)), None),
        ["token", "add" | "create", id, rest @ ..] if named(id) => {
            known(rest, &["--name", "--scopes", "--days"])?;
            let scopes = flag(rest, "--scopes").map(|s| s.split(',').map(str::trim).filter(|p| !p.is_empty()).collect::<Vec<_>>());
            let body = json!({ "name": flag(rest, "--name"), "scopes": scopes, "expiresInDays": number(rest, "--days")? });
            ("POST", format!("{}/tokens", at(id)), Some(body.to_string()))
        }
        ["token", "rotate", id, token, rest @ ..] if named(token) => {
            known(rest, &["--days", "--keep-old"])?;
            let body = json!({ "expiresInDays": number(rest, "--days")?, "keepOldMinutes": number(rest, "--keep-old")? });
            ("POST", format!("{}/tokens/{}/rotate", at(id), encode(token)), Some(body.to_string()))
        }
        ["token", "revoke", id, token] => ("DELETE", format!("{}/tokens/{}", at(id), encode(token)), None),
        _ => return Err(USAGE.into()),
    })
}

/// What `botctl service-account token add|rotate` prints: the token once, and how to use it.
fn service_token_created(res: &Value) -> String {
    let t = &res["tokenInfo"];
    let days = (t["expiresAt"].as_i64().unwrap_or_default() - now_ms() + 12 * 3_600_000) / 86_400_000;
    let scopes = t["scopes"].as_array().map_or("all the account holds".into(), |s| s.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", "));
    let mut out = format!(
        "Token {} for service account {} ({}), with {scopes}, for {days} days.\n\n{}\n\nIt is shown only once. Send it as \"Authorization: Bearer <token>\", or set SUPERBOT_TOKEN for botctl.",
        t["id"].as_str().unwrap_or_default(),
        res["serviceAccount"]["name"].as_str().unwrap_or_default(),
        res["serviceAccount"]["id"].as_str().unwrap_or_default(),
        res["token"].as_str().unwrap_or_default(),
    );
    if let Some(old) = res["replaced"]["id"].as_str() {
        let mins = (res["replaced"]["endsAt"].as_i64().unwrap_or_default() - now_ms()) / 60_000;
        out.push_str(&if mins > 0 { format!("\nThe old token {old} keeps working for about {mins} more minutes.") } else { format!("\nThe old token {old} stopped working.") });
    }
    out
}

/// What `botctl scim token create` prints: the token once, and where the IdP sends it.
fn scim_created(res: &Value) -> String {
    let t = &res["scimToken"];
    let mut out = format!(
        "Created SCIM token {} for tenant {}.\n\n{}\n\nIt is shown only once; paste it into the IdP's provisioning settings as the secret (bearer) token.\nTenant URL: https://<your-host>/scim/v2",
        t["id"].as_str().unwrap_or_default(),
        t["tenant"].as_str().unwrap_or_default(),
        res["token"].as_str().unwrap_or_default(),
    );
    if let Some(p) = t["ssoProvider"].as_str() {
        out.push_str(&format!("\nexternalId must be each person's subject in the SSO provider {p} (Entra: map objectId to externalId)."));
    }
    if res["enabled"] == false {
        out.push_str("\n\nSCIM is off on this server: set SCIM=on and restart botd before the IdP connects.");
    }
    out
}

/// What `botctl signup approve` prints: the code once, and how to let SSO sign them in.
fn approved(res: &Value) -> String {
    let mins = (res["expiresAt"].as_i64().unwrap_or_default() - now_ms()) / 60_000;
    let (email, user) = (res["user"]["email"].as_str().unwrap_or_default(), res["user"]["id"].as_str().unwrap_or_default());
    let mut out = format!(
        "Approved. {email} is now a {} user ({user}).\n\n{}\n\nA one-time sign-in code, good for about {} hours. It is shown only once; share it privately.",
        res["user"]["role"].as_str().unwrap_or_default(),
        res["code"].as_str().unwrap_or_default(),
        ((mins + 30) / 60).max(1),
    );
    let sso: Vec<String> = res["sso"].as_array().into_iter().flatten().filter_map(|p| p["id"].as_str()).map(|id| format!("  botctl user link {email} {id} <subject>")).collect();
    if !sso.is_empty() {
        out.push_str(&format!("\n\nTo let them sign in with single sign-on instead, link their identity:\n{}", sso.join("\n")));
    }
    out
}

fn decide(verb: &str, id: &str, rest: &[&str]) -> Result<String, String> {
    let body = decide_body(rest)?;
    let done = match (verb, body["scope"].as_str()) {
        ("approve", Some("run")) => "Approved for the rest of this task.",
        ("approve", _) => "Approved.",
        _ => "Denied.",
    };
    api(Cred::Operator, "POST", &format!("/api/approvals/{id}/{verb}"), Some(body.to_string())).map(|_| done.into())
}

fn decide_body(rest: &[&str]) -> Result<Value, String> {
    let remember = if rest.contains(&"--remember-global") {
        json!("global")
    } else if rest.contains(&"--remember") {
        json!("bot")
    } else {
        Value::Null
    };
    let run = rest.contains(&"--run");
    if run && !remember.is_null() {
        return Err("Pick one: --run (the rest of this task) or --remember (a lasting rule).".into());
    }
    Ok(json!({ "remember": remember, "scope": if run { "run" } else { "once" } }))
}

fn env_name(name: &str) -> Result<&str, String> {
    if name.is_empty() || !name.bytes().all(|b| b == b'_' || b.is_ascii_uppercase() || b.is_ascii_digit()) {
        return Err(format!("\"{name}\" isn't a valid name. Use an environment variable name like OPENAI_API_KEY."));
    }
    Ok(name)
}

/// The value comes on stdin, so it stays out of shell history and the process list.
fn stdin_value(mut input: impl Read) -> Result<String, String> {
    let mut v = String::new();
    input.read_to_string(&mut v).map_err(|e| format!("Couldn't read the value from stdin: {e}"))?;
    let v = v.strip_suffix('\n').map(|t| t.strip_suffix('\r').unwrap_or(t)).unwrap_or(&v).to_string();
    if v.is_empty() {
        return Err("No value on stdin. Example: botctl secret set OPENAI_API_KEY < key.txt".into());
    }
    Ok(v)
}

/// `botctl setup ...`: the method and body for `/api/setup` (ADR 0034).
fn setup_request(a: &[&str]) -> Result<(&'static str, Option<String>), String> {
    let patch = |v: Value| Ok(("PATCH", Some(v.to_string())));
    match a {
        [] | ["status"] => Ok(("GET", None)),
        ["done"] => patch(json!({ "completed": true })),
        ["reopen"] => patch(json!({ "completed": false })),
        ["hide"] => patch(json!({ "dismissed": true })),
        ["show"] => patch(json!({ "dismissed": false })),
        _ => Err("Usage: botctl setup [status | json | done | reopen | hide | show]".into()),
    }
}

/// The setup checklist, for a terminal.
fn setup_summary(s: &Value) -> String {
    let p = &s["progress"];
    let state = if p["completedAt"].is_i64() {
        "finished"
    } else if p["dismissed"] == true {
        "hidden from admins"
    } else {
        "admins see the wizard in the console's Setup tab"
    };
    let mut out = format!("Setup: {} of {} done ({state}).\n", s["done"], s["total"]);
    for c in s["checklist"].as_array().into_iter().flatten() {
        let mark = if c["done"] == true { "x" } else { " " };
        out += &format!("  [{mark}] {}\n      {}\n", c["label"].as_str().unwrap_or_default(), c["detail"].as_str().unwrap_or_default());
    }
    for p in s["signIn"]["providers"].as_array().into_iter().flatten().filter(|p| p["ready"] != true) {
        let label = p["label"].as_str().unwrap_or_default();
        match p["secret"].as_str() {
            Some(name) => out += &format!("\n{label} needs its secret: botctl secret set {name} < file\n"),
            None => out += &format!("\n{label} needs its IdP metadata: botctl sso saml {} import idp-metadata.xml\n", p["id"].as_str().unwrap_or_default()),
        }
    }
    if s["secretsBackend"]["ok"] == false {
        out += &format!("\nSecrets backend {}: {}\n", s["secretsBackend"]["backend"].as_str().unwrap_or_default(), s["secretsBackend"]["detail"].as_str().unwrap_or_default());
    }
    if !p["completedAt"].is_i64() {
        out += "\nThe console's Setup tab has the commands for each step. When you're done: botctl setup done\n";
    }
    out
}

/// Where botd reads secrets from and whether it answers (ADR 0125, ADR 0136, ADR 0146); an error
/// when it doesn't, so scripts can check it.
fn backend_summary(b: &Value) -> Result<String, String> {
    if b.is_null() {
        return Err("This botd doesn't report its secrets backend; upgrade it.".into());
    }
    let mut out = format!("Secrets backend: {}", b["backend"].as_str().unwrap_or("unknown"));
    if let Some(d) = b["description"].as_str().filter(|_| b["backend"] != "local") {
        out += &format!(" ({d}");
        if let Some(s) = b["cacheSeconds"].as_u64() {
            out += &format!(", cached for {s} s");
        }
        out += ")";
    }
    out += &format!("\n  {}", b["detail"].as_str().unwrap_or_default());
    if b["ok"] == true { Ok(out) } else { Err(out) }
}

/// `GET /api/license`, for a terminal (ADR 0038).
fn license_summary(l: &Value) -> String {
    let s = &l["seats"];
    let seats = match s["limit"].as_u64() {
        Some(n) => format!("{} of {n} seats in use", s["used"]),
        None => format!("{} active, no seat limit", s["used"]),
    };
    let mut out = format!("License: {} ({seats}).\n  {}\n", l["mode"].as_str().unwrap_or_default(), l["detail"].as_str().unwrap_or_default());
    if let Some(id) = l["license"]["id"].as_str() {
        out += &format!("  Id {id}, source {}.\n", l["source"].as_str().unwrap_or_default());
    }
    for w in l["warnings"].as_array().into_iter().flatten().filter_map(Value::as_str).filter(|w| Some(*w) != l["detail"].as_str()) {
        out += &format!("  Warning: {w}\n");
    }
    out
}

/// `GET /api/sso/{id}/saml`, for a terminal (ADR 0127, 0137): what the IdP admin enters, then what the IdP said.
fn saml_summary(v: &Value) -> String {
    let s = |k: &str| v[k].as_str().unwrap_or("-").to_string();
    let mut out = format!(
        "{} ({}): {}\n  SP entity ID (audience):  {}\n  ACS URL (reply URL):      {}\n  SLO URL (logout URL):     {}\n  SP metadata:              {}\n  IdP entity ID:            {}\n",
        s("label"),
        s("provider"),
        v["problem"].as_str().unwrap_or("ready"),
        s("spEntityId"),
        s("acsUrl"),
        s("sloUrl"),
        s("metadataUrl"),
        s("idpEntityId"),
    );
    let key = &v["spKey"];
    if let Some(c) = key["certificate"].as_object() {
        out += &format!(
            "  SP signing certificate:   SHA-256 {} ({}), expires {}\n",
            c["sha256"].as_str().unwrap_or_default(),
            key["from"].as_str().unwrap_or_default(),
            day(&c["notAfter"])
        );
    } else if let Some(p) = key["problem"].as_str() {
        out += &format!("  SP signing key:           {p}\n");
    }
    out += &rollover_lines(key);
    let enc = &v["spEncryptionKey"];
    if let Some(c) = enc["certificate"].as_object() {
        out += &format!(
            "  SP encryption certificate: SHA-256 {} ({}), expires {}\n",
            c["sha256"].as_str().unwrap_or_default(),
            enc["from"].as_str().unwrap_or_default(),
            day(&c["notAfter"])
        );
    } else if let Some(p) = enc["problem"].as_str() {
        out += &format!("  SP encryption key:        {p}\n");
    }
    out += &rollover_lines(enc);
    out += &format!(
        "  Encrypted assertions:     {}\n",
        match v["encryptedAssertions"].as_str() {
            Some("allow") => "allowed",
            Some("require") => "required",
            _ => "off",
        }
    );
    out += &format!(
        "  IdP metadata signature:   {}\n",
        match v["signedMetadata"].as_str() {
            Some("require") => "required",
            Some("allow") => "checked when signed",
            _ => "not checked",
        }
    );
    for c in v["metadataSigningCertificates"].as_array().into_iter().flatten() {
        out += &format!("    Trusted signer: SHA-256 {} ({}), expires {}\n", c["sha256"].as_str().unwrap_or_default(), c["subject"].as_str().unwrap_or_default(), day(&c["notAfter"]));
    }
    let yes = |b: bool| if b { "yes" } else { "no" };
    out += &format!(
        "  Signs AuthnRequests:      {}\n  Single logout:            {}\n",
        yes(v["signRequests"].as_bool().unwrap_or(false)),
        if v["singleLogout"].as_bool().unwrap_or(false) { "yes" } else { "no (the IdP's metadata has no HTTP-Redirect SingleLogoutService)" }
    );
    out += &format!(
        "  IdP-initiated sign-in:    {}\n",
        if v["idpInitiated"].as_str() == Some("restart") { "restarted as SP-initiated" } else { "refused (start from SuperBot)" }
    );
    let authn = &v["authnContext"];
    match authn["required"].as_array() {
        Some(required) => {
            let required: Vec<&str> = required.iter().filter_map(Value::as_str).collect();
            out += &format!("  Authentication context:   one of {}\n", required.join(", "));
            if let Some(m) = authn["methodsAttribute"].as_str() {
                out += &format!("    Also read from attribute {m}\n");
            }
            out += if authn["requested"].as_bool().unwrap_or(false) { "    Requested in AuthnRequests (exact)\n" } else { "    Not requested: the IdP's own policy decides\n" };
        }
        None => out += "  Authentication context:   not checked (the IdP's MFA isn't required)\n",
    }
    if let Some(g) = v["groupsAttribute"].as_str() {
        let required: Vec<&str> = v["requiredGroups"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
        out += &format!(
            "  Groups attribute:         {g}\n  Required groups:          {}\n  Group role mappings:      {} (botctl sso role-mappings)\n",
            if required.is_empty() { "none (anyone the IdP signs in)".into() } else { required.join(", ") },
            v["roleMappings"].as_u64().unwrap_or(0)
        );
    }
    let from = v["from"].as_str().map(|f| format!(" ({f})")).unwrap_or_default();
    out += &format!("  IdP metadata from {}{from}", s("source"));
    let idp = &v["idp"];
    if idp.is_null() {
        out += ": not loaded yet.\n";
        return out;
    }
    out += &format!(":\n    Sign-in URL: {}\n", idp["ssoUrl"].as_str().unwrap_or_default());
    if let Some(slo) = idp["sloUrl"].as_str() {
        out += &format!("    Logout URL:  {slo}\n");
    }
    for c in idp["certificates"].as_array().into_iter().flatten() {
        out += &format!("    Certificate SHA-256 {} ({}), expires {}\n", c["sha256"].as_str().unwrap_or_default(), c["subject"].as_str().unwrap_or_default(), day(&c["notAfter"]));
    }
    out
}

/// A generated SP key's rollover under its certificate line (ADR 0181): the next key, published
/// beside it, and a replaced encryption key still decrypting; for encryption keys, when each last
/// decrypted a sign-in, so it's plain when the IdP has moved to the next one.
fn rollover_lines(key: &Value) -> String {
    let used = |k: &Value| match k.get("lastUsedSecondsAgo") {
        None => String::new(),
        Some(Value::Null) => "; no sign-in decrypted with it since botd started".into(),
        Some(s) => format!("; last decrypted a sign-in {} ago", ago(s.as_u64().unwrap_or(0))),
    };
    let mut out = String::new();
    let rolling = key["next"].is_object() || key["previous"].is_object();
    if rolling && key["certificate"].is_object() && key.get("lastUsedSecondsAgo").is_some() {
        out += &format!("    In use{}\n", used(key));
    }
    let next = &key["next"];
    if let Some(c) = next["certificate"].as_object() {
        out += &format!("    Next: SHA-256 {}, expires {}: published, not yet in use{}\n", c["sha256"].as_str().unwrap_or_default(), day(&c["notAfter"]), used(next));
    }
    let prev = &key["previous"];
    if let Some(c) = prev["certificate"].as_object() {
        out += &format!("    Previous: SHA-256 {}: no longer published, still decrypts until retired{}\n", c["sha256"].as_str().unwrap_or_default(), used(prev));
    }
    out
}

fn ago(s: u64) -> String {
    match s {
        0..60 => format!("{s}s"),
        60..3600 => format!("{}m", s / 60),
        3600..86_400 => format!("{}h", s / 3600),
        _ => format!("{}d", s / 86_400),
    }
}

/// `botctl sso saml <provider> key <step> <use>`: the request for one step of a rollover (ADR 0181).
fn saml_key_request(id: &str, step: &str, key_use: &str) -> Result<(&'static str, String), String> {
    if !matches!(key_use, "signing" | "encryption") {
        return Err("Usage: botctl sso saml <provider> key next|promote|cancel|retire signing|encryption".into());
    }
    let at = |end: &str| format!("/api/sso/{}/saml/keys/{key_use}/{end}", encode(id));
    match step {
        "next" => Ok(("POST", at("next"))),
        "promote" => Ok(("POST", at("promote"))),
        "cancel" => Ok(("DELETE", at("next"))),
        "retire" => Ok(("DELETE", at("previous"))),
        _ => Err("Usage: botctl sso saml <provider> key next|promote|cancel|retire signing|encryption".into()),
    }
}

fn day(ms: &Value) -> String {
    chrono::DateTime::from_timestamp_millis(ms.as_i64().unwrap_or_default()).map(|d| d.format("%Y-%m-%d").to_string()).unwrap_or_default()
}

/// One line per user: their plan, each limit as used/allowed, their machine, their
/// subscription, and any limit they're past (ADR 0040).
/// One user's billing period (`GET /api/me/usage` or `/api/users/{key}/usage`), for people.
fn period_summary(v: &Value) -> String {
    let n = |v: &Value| v.as_u64().unwrap_or(0);
    let of = |used: &Value, limit: &Value| match limit.as_u64() {
        Some(l) => format!("{}/{}", n(used), l),
        None => format!("{}/unlimited", n(used)),
    };
    let day = |ms: &Value| chrono::DateTime::from_timestamp_millis(ms.as_i64().unwrap_or(0)).map(|d| d.format("%Y-%m-%d").to_string()).unwrap_or_default();
    let (p, t) = (&v["period"], &v["tokens"]);
    let source = if p["source"] == "subscription" { "subscription period" } else { "calendar month, UTC" };
    let mut out = format!(
        "{} plan, {} to {} ({source})\nTokens {} (input {}, output {}, cache read {}, cache write {})\nRuns {}",
        v["tier"]["label"].as_str().unwrap_or_default(),
        day(&p["start"]),
        day(&p["end"]),
        of(&t["total"], &t["limit"]),
        n(&t["input"]),
        n(&t["output"]),
        n(&t["cacheRead"]),
        n(&t["cacheWrite"]),
        of(&v["runs"]["used"], &v["runs"]["limit"]),
    );
    if n(&t["unreportedRuns"]) > 0 {
        out += &format!("; {} reported no tokens", n(&t["unreportedRuns"]));
    }
    out.push('\n');
    if let Some(s) = storage_text(&v["storage"]) {
        out += &format!("Storage {s}\n");
    }
    for b in v["byBot"].as_array().into_iter().flatten() {
        let name = b["name"].as_str().unwrap_or("(deleted or not yours now)");
        out += &format!("  Bot {name} ({}): {} tokens in {} runs\n", b["bot"].as_str().unwrap_or_default(), n(&b["total"]), n(&b["runs"]));
    }
    for m in v["byModel"].as_array().into_iter().flatten() {
        out += &format!("  Model {}: {} tokens in {} runs\n", m["model"].as_str().unwrap_or("(not named)"), n(&m["total"]), n(&m["runs"]));
    }
    out
}

/// Storage used against the plan's cap in MB (ADR 0082), or None when not measured.
fn storage_text(s: &Value) -> Option<String> {
    let used = s["used"].as_u64()?;
    let mb = |b: u64| format!("{:.1}", b as f64 / 1_000_000.0);
    let limit = s["limitMb"].as_u64().map_or("unlimited".to_string(), |l| format!("{l} MB"));
    let mut out = format!("{} MB/{limit}", mb(used));
    match s["state"].as_str() {
        Some("warning") => out += " (nearly full)",
        Some("over") => out += " (full)",
        _ => {}
    }
    if s["partial"] == true {
        out += " (at least: some folders couldn't be read)";
    }
    Some(out)
}

fn usage_summary(v: &Value) -> String {
    let of = |used: &Value, limit: &Value| match limit.as_u64() {
        Some(l) => format!("{}/{l}", used.as_u64().unwrap_or(0)),
        None => format!("{}/unlimited", used.as_u64().unwrap_or(0)),
    };
    let mode = match (v["billing"] == true, v["checkout"] == true) {
        (false, _) => "off",
        (true, false) => "Stripe webhook on, checkout off",
        (true, true) => "Stripe webhook and checkout on",
    };
    let mut out = format!("Billing: {mode}.\n");
    for u in v["users"].as_array().into_iter().flatten() {
        let (p, use_) = (&u["plan"], &u["plan"]["usage"]);
        let who = u["user"]["email"].as_str().or(u["user"]["name"].as_str()).unwrap_or_default();
        let mut line = format!(
            "{who}: {} plan; Bots {}; runs {} and tokens {} in {}; routine runs {} on {}",
            p["label"].as_str().unwrap_or_default(),
            of(&use_["bots"], &p["limits"]["maxBots"]),
            of(&use_["runs"], &p["limits"]["monthlyRuns"]),
            of(&use_["tokens"], &p["limits"]["monthlyTokens"]),
            use_["period"].as_str().unwrap_or_default(),
            of(&use_["routineRuns"], &p["limits"]["dailyRoutineRuns"]),
            use_["day"].as_str().unwrap_or_default(),
        );
        if let Some(s) = storage_text(&use_["storage"]) {
            line += &format!("; storage {s}");
        }
        let allowed = p["limits"]["machineType"].as_str();
        match (&u["machine"], allowed) {
            (Value::Null, Some(t)) => line += &format!("; machine size {t}, none yet"),
            (Value::Null, None) => {}
            (m, _) => line += &format!("; machine {} ({}){}", m["plan"].as_str().unwrap_or_default(), m["state"].as_str().unwrap_or_default(), allowed.map_or(String::new(), |t| format!(", plan size {t}"))),
        }
        let r = &u["machine"]["resize"];
        if let (Some(state @ ("pending" | "waiting" | "failed")), Some(to)) = (r["state"].as_str(), r["toPlan"].as_str()) {
            line += &format!("; resizing to {to} ({state}");
            if let Some(why) = r["message"].as_str() {
                line += &format!(": {why}");
            }
            line += ")";
        }
        if let Some(st) = u["subscription"]["status"].as_str() {
            line += &format!("; Stripe {st}");
        }
        if let Some(c) = u["customer"].as_str() {
            line += &format!("; customer {c}");
        }
        let over: Vec<&str> = u["over"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
        if !over.is_empty() {
            line += &format!("; OVER: {}", over.join(", "));
        }
        out += &line;
        out.push('\n');
    }
    out
}

fn run(args: &[String]) -> Result<String, String> {
    let bot = std::env::var("BOT_ID").unwrap_or_default();
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    let op = |m: &str, p: &str, b: Option<String>| api(Cred::Operator, m, p, b).map(pretty);
    match a.as_slice() {
        ["routines"] | ["routine", "list"] => api(Cred::Bot, "GET", &format!("/api/bots/{bot}/routines"), None),
        ["routine", "add", name, cron, what] => {
            let body = json!({ "name": name, "cron": cron, "instruction": what }).to_string();
            api(Cred::Bot, "POST", &format!("/api/bots/{bot}/routines"), Some(body)).map(|_| format!("Added routine \"{name}\" ({cron})."))
        }
        ["routine", "rm" | "delete", id] => api(Cred::Bot, "DELETE", &format!("/api/routines/{id}"), None).map(|_| "Deleted.".into()),
        ["routine", cmd @ ("pause" | "resume"), id] => {
            let body = json!({ "enabled": *cmd == "resume" }).to_string();
            api(Cred::Bot, "PATCH", &format!("/api/routines/{id}"), Some(body)).map(|_| if *cmd == "pause" { "Paused." } else { "Resumed." }.into())
        }
        ["bots"] => api(Cred::Bot, "GET", "/api/bots", None),
        ["ask", to, message] => {
            let body = json!({ "from": bot, "to": to, "text": message }).to_string();
            api(Cred::Bot, "POST", "/api/ask", Some(body))
        }
        ["handoff", text] => {
            let body = json!({ "from": bot, "text": text }).to_string();
            api(Cred::Bot, "POST", "/api/handoff", Some(body))
        }
        ["hook", harness] => hook(harness, None),
        ["hook", harness, "--cwd", cwd] => hook(harness, Some(cwd)),
        ["hook", ..] => {
            // Exit 0 would allow the tool call, so a malformed gate blocks.
            eprintln!("SuperBot's approval gate is misconfigured, so this action was blocked. Usage: botctl hook <harness> [--cwd <dir>]");
            std::process::exit(2)
        }

        ["policy"] | ["policy", "global"] => op("GET", "/api/policy", None),
        ["policy", "set", "global", rest @ ..] => op("PUT", "/api/policy", Some(policy_patch(rest)?.to_string())),
        ["policy", "set", id, rest @ ..] => op("PUT", &format!("/api/bots/{id}/policy"), Some(policy_patch(rest)?.to_string())),
        ["policy", "reset", id] => op("DELETE", &format!("/api/bots/{id}/policy"), None).map(|_| "Reset. This Bot follows the global policy.".into()),
        ["policy", id] => op("GET", &format!("/api/bots/{id}/policy"), None),
        ["rules"] => op("GET", "/api/policy/rules", None),
        ["rules", id] => op("GET", &format!("/api/policy/rules?bot={id}"), None),
        ["rule", "add", action @ ("allow" | "deny"), pattern, rest @ ..] => {
            let body = json!({ "action": action, "pattern": pattern, "tool": flag(rest, "--tool"), "botId": flag(rest, "--bot") });
            op("POST", "/api/policy/rules", Some(body.to_string()))
        }
        ["rule", "rm" | "delete", id] => op("DELETE", &format!("/api/policy/rules/{id}"), None).map(|_| "Deleted.".into()),
        ["bot", rest @ ..] => {
            let (method, path, body) = bot_access(rest)?;
            op(method, &path, body)
        }
        ["machine", "harness-login", user, harness] => machine_login(user, harness),
        ["machine", "harness-logins", user] => op("GET", &format!("{}/harness-logins", login_base(user)), None),
        ["machine", "harness-logout", user, harness] => op("DELETE", &format!("{}/harness-logins/{}", login_base(user), encode(harness)), None),
        ["machine", "legacy"] => op("GET", "/api/machines/legacy", None),
        [..] if egress_request(&a).is_some() => {
            let (method, path, body) = egress_request(&a).unwrap();
            op(method, &path, body)
        }
        ["machine" | "user", "egress", ..] => {
            Err("Usage: botctl machine egress [open|allow <host|cidr>...] | botctl user egress <user> [inherit|open|allow <host|cidr>...]".into())
        }
        ["machine", rest @ ..] if matches!(rest.first(), Some(&("backups" | "backup" | "restore" | "delete-backups" | "recovery" | "hosts" | "host"))) => {
            let (method, path, body) = backup_request(rest, |f| std::fs::read_to_string(f).map_err(|e| format!("--identity {f}: {e}")))?;
            op(method, &path, body)
        }
        ["machine", "rebuild", rest @ ..] => {
            let (method, path, body) = rebuild_request(rest)?;
            op(method, &path, body)
        }
        ["machine", rest @ ..] if lifecycle_request(rest).is_some() => {
            let (method, path, body) = lifecycle_request(rest).unwrap()?;
            op(method, &path, body)
        }
        ["machine", rest @ ..] => {
            let (method, path) = machine_request(rest)?;
            let res = op(method, &path, None)?;
            Ok(if matches!(rest, ["screens", _, "close", _]) { "Closed.".into() } else { res })
        }
        ["signups"] | ["signup", ..] => {
            let (method, path, body) = signup_request(a.get(1..).unwrap_or_default())?;
            let res = api(Cred::Operator, method, &path, body)?;
            match a.get(1) {
                Some(&"approve") => Ok(approved(&serde_json::from_str(&res).map_err(|e| e.to_string())?)),
                Some(&"reject") => Ok("Rejected. No email was sent.".into()),
                _ => Ok(pretty(res)),
            }
        }
        ["scim", rest @ ..] => {
            let (method, path, body) = scim_request(rest)?;
            let res = api(Cred::Operator, method, &path, body)?;
            match rest {
                ["token", "create", ..] => Ok(scim_created(&serde_json::from_str(&res).map_err(|e| e.to_string())?)),
                ["token", "revoke", ..] => Ok("Revoked. The IdP can't provision with it any more; its users stay as they are.".into()),
                _ => Ok(pretty(res)),
            }
        }
        ["roles"] | ["role", ..] => {
            let rest = a.get(1..).unwrap_or_default();
            let (method, path, body) = role_request(rest)?;
            let res = api(Cred::Operator, method, &path, body)?;
            match rest.first() {
                Some(&("rm" | "delete")) => Ok("Deleted.".into()),
                Some(&verb @ ("assign" | "unassign")) => Ok(role_assigned(verb, &serde_json::from_str(&res).map_err(|e| e.to_string())?)),
                _ => Ok(pretty(res)),
            }
        }
        ["service-accounts"] | ["service-account", ..] => {
            let rest = a.get(1..).unwrap_or_default();
            let (method, path, body) = service_account_request(rest)?;
            let res = api(Cred::Operator, method, &path, body)?;
            match rest {
                ["token", "add" | "create" | "rotate", ..] => Ok(service_token_created(&serde_json::from_str(&res).map_err(|e| e.to_string())?)),
                ["token", "revoke", ..] => Ok("Revoked. It stopped working.".into()),
                ["rm" | "delete", ..] => Ok("Deleted. Its tokens are revoked; the audit log keeps its name.".into()),
                _ => Ok(pretty(res)),
            }
        }
        ["approvals"] => op("GET", "/api/approvals?status=pending", None),
        ["approvals", status] => op("GET", &format!("/api/approvals?status={status}"), None),
        [verb @ ("approve" | "deny"), id, rest @ ..] => decide(verb, id, rest),
        ["support-bundle", rest @ ..] => support_bundle(rest),
        ["support-report", rest @ ..] => support_report(rest, std::io::stdin()),
        ["health-score", "history", rest @ ..] => {
            let (path, json) = health_request_at(rest, "/api/support/health-score/history", "Usage: botctl health-score history [--days <n>] [json]")?;
            let res = api(Cred::Operator, "GET", &path, None)?;
            if json { Ok(pretty(res)) } else { Ok(history_summary(&serde_json::from_str(&res).map_err(|e| e.to_string())?)) }
        }
        ["health-score", rest @ ..] => {
            let (path, json) = health_request(rest)?;
            let res = api(Cred::Operator, "GET", &path, None)?;
            if json { Ok(pretty(res)) } else { Ok(health_summary(&serde_json::from_str(&res).map_err(|e| e.to_string())?)) }
        }
        ["evidence"] => op("GET", "/api/evidence", None),
        ["evidence", "bundle", rest @ ..] => evidence_bundle(rest),
        ["evidence", "baseline", rest @ ..] => {
            let json = match rest {
                [] => false,
                ["json"] => true,
                _ => return Err("Usage: botctl evidence baseline [json]".into()),
            };
            let res = api(Cred::Operator, "GET", "/api/evidence/baseline", None)?;
            let v: Value = serde_json::from_str(&res).map_err(|e| e.to_string())?;
            let out = if json { pretty(res) } else { baseline_summary(&v) };
            // A deviation exits non-zero, so a cron job or the change checklist notices,
            // with the report still on stdout for `> baseline.txt` to keep.
            if v["ok"] == false {
                println!("{}", out.trim_end());
                std::process::exit(2);
            }
            Ok(out)
        }
        ["audit", "export", rest @ ..] => api(Cred::Operator, "GET", &format!("/api/audit/export.csv{}", audit_query(rest)?), None),
        ["audit", "verify", rest @ ..] => {
            let res = op("GET", &format!("/api/audit/verify{}", verify_query(rest)?), None)?;
            // A broken chain is a failure, so a cron job or CI step notices.
            if serde_json::from_str::<Value>(&res).ok().and_then(|v| v["ok"].as_bool()) == Some(false) { Err(res) } else { Ok(res) }
        }
        ["audit", "siem"] => op("GET", "/api/audit/siem", None),
        ["audit", "chain"] => op("GET", "/api/audit/chain", None),
        ["audit", "key"] => op("GET", "/api/audit/checkpoints/key", None),
        ["audit", "checkpoint"] => op("POST", "/api/audit/checkpoints", None),
        ["audit", "checkpoints"] => op("GET", "/api/audit/checkpoints", None),
        ["audit", "checkpoints", limit] => {
            let n: u32 = limit.parse().map_err(|_| format!("{limit} isn't a number of checkpoints"))?;
            op("GET", &format!("/api/audit/checkpoints?limit={n}"), None)
        }
        ["audit", rest @ ..] => op("GET", &format!("/api/audit{}", audit_query(rest)?), None),
        ["retention"] => op("GET", "/api/retention", None),
        ["retention", "hold", bot, reason] => op("PUT", &format!("/api/retention/holds/{}", encode(bot)), Some(json!({ "reason": reason }).to_string())),
        ["retention", "release", bot] => op("DELETE", &format!("/api/retention/holds/{}", encode(bot)), None),
        ["backups"] => op("GET", "/api/backups", None),
        ["backups", "copy"] => op("POST", "/api/backups", None),
        ["database"] => op("GET", "/api/database", None),

        ["login", rest @ ..] => login(rest),
        ["logout"] => op("POST", "/api/auth/logout", None).map(|_| "Signed out. Unset SUPERBOT_TOKEN.".into()),
        ["whoami"] => op("GET", "/api/auth/me", None),
        ["users"] | ["user", "list"] => op("GET", "/api/users", None),
        [kind @ ("user" | "team"), "residency", key, "report", rest @ ..] => {
            let (path, out) = residency_report_request(kind, key, rest)?;
            let res = api(Cred::Operator, "GET", &path, None)?;
            let res = if path.contains("format=markdown") { res } else { pretty(res) };
            match out {
                Some(file) => save_private(file, res.as_bytes()).map(|_| format!("Saved {file}.")),
                None => Ok(res),
            }
        }
        [..] if region_request(&a).is_some() => {
            let (method, path, body) = region_request(&a).unwrap();
            op(method, &path, body)
        }
        ["user", "add", email, rest @ ..] => {
            let name = rest.first().filter(|n| !n.starts_with("--"));
            let body = json!({ "email": email, "name": name, "role": flag(rest, "--role").map(role).transpose()? });
            op("POST", "/api/users", Some(body.to_string()))
        }
        ["user", "role", key, r] => op("PATCH", &format!("/api/users/{}", encode(key)), Some(json!({ "role": role(r)? }).to_string())),
        ["user", "tier", key, t] => {
            let tier = if *t == "default" { Value::Null } else { json!(t) };
            op("PATCH", &format!("/api/users/{}", encode(key)), Some(json!({ "tier": tier }).to_string()))
        }
        ["user", "isolation", key] => op("GET", &format!("/api/users/{}/isolation", encode(key)), None),
        ["user", "isolate", key] => op("POST", &format!("/api/users/{}/isolation", encode(key)), None),
        ["user", "harness-login", key, harness, rest @ ..] => harness_login(key, harness, rest),
        ["user", sub @ ("teammates" | "teammate-removals"), rest @ ..] => {
            let mut args = vec![*sub];
            args.extend_from_slice(rest);
            let (method, path) = teammate_accounts_request(&args)?;
            op(method, &path, None)
        }
        ["tiers"] => op("GET", "/api/tiers", None),
        ["tiers", "move-bots", rest @ ..] => {
            let (path, body) = move_bots_request(rest)?;
            op("POST", &path, Some(body))
        }
        ["usage"] => Ok(usage_summary(&serde_json::from_str(&api(Cred::Operator, "GET", "/api/usage", None)?).map_err(|e| e.to_string())?)),
        ["usage", "json"] => op("GET", "/api/usage", None),
        ["usage", "me"] => Ok(period_summary(&serde_json::from_str(&op("GET", "/api/me/usage", None)?).map_err(|e| e.to_string())?)),
        ["usage", "me", "json"] => op("GET", "/api/me/usage", None),
        ["usage", "user", key] => Ok(period_summary(&serde_json::from_str(&op("GET", &format!("/api/users/{}/usage", encode(key)), None)?).map_err(|e| e.to_string())?)),
        ["usage", "user", key, "json"] => op("GET", &format!("/api/users/{}/usage", encode(key)), None),
        ["license"] | ["license", "status"] => Ok(license_summary(&serde_json::from_str(&api(Cred::Operator, "GET", "/api/license", None)?).map_err(|e| e.to_string())?)),
        ["license", "json"] => op("GET", "/api/license", None),
        ["license", "install", rest @ ..] if rest.len() <= 1 => {
            let key = match rest.first() {
                None | Some(&"-") => stdin_value(std::io::stdin())?,
                Some(path) => std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?,
            };
            let res = api(Cred::Operator, "PUT", "/api/license", Some(json!({ "key": key.trim() }).to_string()))?;
            Ok(format!("Installed.\n{}", license_summary(&serde_json::from_str(&res).map_err(|e| e.to_string())?)))
        }
        ["license", "remove"] => {
            let res = api(Cred::Operator, "DELETE", "/api/license", None)?;
            Ok(format!("Removed.\n{}", license_summary(&serde_json::from_str(&res).map_err(|e| e.to_string())?)))
        }
        ["sso", "saml", id] => Ok(saml_summary(&serde_json::from_str(&api(Cred::Operator, "GET", &format!("/api/sso/{}/saml", encode(id)), None)?).map_err(|e| e.to_string())?)),
        ["sso", "saml", id, "json"] => op("GET", &format!("/api/sso/{}/saml", encode(id)), None),
        ["sso", "saml", id, "import", rest @ ..] if rest.len() <= 1 => {
            let xml = match rest.first() {
                None | Some(&"-") => stdin_value(std::io::stdin())?,
                Some(path) => std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?,
            };
            let res = api(Cred::Operator, "PUT", &format!("/api/sso/{}/saml/idp-metadata", encode(id)), Some(json!({ "xml": xml }).to_string()))?;
            Ok(format!("Imported.\n{}", saml_summary(&serde_json::from_str(&res).map_err(|e| e.to_string())?)))
        }
        ["sso", "saml", id, "key", step, key_use] => {
            let (method, path) = saml_key_request(id, step, key_use)?;
            let res = api(Cred::Operator, method, &path, None)?;
            let done = match *step {
                "next" => format!("Made a next {key_use} key. Give the IdP SuperBot's metadata again (or the new certificate), then: botctl sso saml {id} key promote {key_use}"),
                "promote" if *key_use == "encryption" => format!("Promoted. The replaced key still decrypts: once the IdP encrypts to the new one, botctl sso saml {id} key retire encryption"),
                "promote" => "Promoted: botd signs with the new key.".into(),
                "cancel" => "Cancelled: the next key is gone.".into(),
                _ => "Retired: the previous key is gone.".into(),
            };
            Ok(format!("{done}\n{}", saml_summary(&serde_json::from_str(&res).map_err(|e| e.to_string())?)))
        }
        ["sso", rest @ ..] => {
            let (method, path, body) = sso_role_request(rest)?;
            op(method, &path, body)
        }
        ["setup", "json"] => op("GET", "/api/setup", None),
        ["setup", rest @ ..] => {
            let (method, body) = setup_request(rest)?;
            let res = api(Cred::Operator, method, "/api/setup", body)?;
            Ok(setup_summary(&serde_json::from_str(&res).map_err(|e| e.to_string())?))
        }
        ["user", cmd @ ("disable" | "enable"), key] => {
            let status = if *cmd == "disable" { "disabled" } else { "active" };
            op("PATCH", &format!("/api/users/{}", encode(key)), Some(json!({ "status": status }).to_string()))
        }
        ["user", "routines", key] => op("GET", &format!("/api/users/{}/routines", encode(key)), None),
        ["user", "resume-routines", key] => op("POST", &format!("/api/users/{}/routines/resume", encode(key)), None),
        ["user", "erase", key, rest @ ..] => {
            let (path, body) = erase_request(key, rest)?;
            op("POST", &path, Some(body.to_string()))
        }
        ["user", "handover", key, rest @ ..] => {
            let (path, body) = handover_request(key, rest)?;
            op("POST", &path, Some(body.to_string()))
        }
        ["user", "code", key, rest @ ..] => {
            let ttl = flag(rest, "--ttl").map(|t| t.parse::<u32>().map_err(|_| "--ttl must be minutes")).transpose()?;
            let body = json!({ "ttlMinutes": ttl }).to_string();
            let res: Value = serde_json::from_str(&api(Cred::Operator, "POST", &format!("/api/users/{}/login-codes", encode(key)), Some(body))?).map_err(|e| e.to_string())?;
            let mins = (res["expiresAt"].as_i64().unwrap_or_default() - now_ms()) / 60_000;
            Ok(format!("{}\n\nA one-time sign-in code for {}, good for about {} minutes. Share it privately.", res["code"].as_str().unwrap_or_default(), res["user"]["email"].as_str().unwrap_or(key), mins.max(1)))
        }
        ["user", "identities", key] => op("GET", &format!("/api/users/{}/identities", encode(key)), None),
        ["user", "link", key, provider, subject, rest @ ..] => {
            let body = json!({ "provider": provider, "subject": subject, "tenant": flag(rest, "--tenant") });
            op("POST", &format!("/api/users/{}/identities", encode(key)), Some(body.to_string()))
        }
        ["user", "unlink", key, id] => op("DELETE", &format!("/api/users/{}/identities/{}", encode(key), encode(id)), None),
        ["sessions"] => op("GET", "/api/sessions", None),
        ["sessions", key] => op("GET", &format!("/api/sessions?user={}", encode(key)), None),
        ["session", "revoke", id] => op("DELETE", &format!("/api/sessions/{}", encode(id)), None).map(|_| "Revoked.".into()),
        ["session", "revoke-all", key] => op("DELETE", &format!("/api/users/{}/sessions", encode(key)), None),
        ["secrets"] => op("GET", "/api/secrets", None),
        ["secrets", "backend"] => {
            let res = api(Cred::Operator, "GET", "/api/setup", None)?;
            backend_summary(&serde_json::from_str::<Value>(&res).map_err(|e| e.to_string())?["secretsBackend"])
        }
        ["secret", "set", name] => {
            let name = env_name(name)?;
            let body = json!({ "value": stdin_value(std::io::stdin())? }).to_string();
            let res: Value = serde_json::from_str(&op("PUT", &format!("/api/secrets/{name}"), Some(body))?).unwrap_or_default();
            Ok(if res["secret"]["forBots"] == false {
                format!("Saved {name}. It is botd's own (single sign-on); Bots never get it.")
            } else {
                format!("Saved {name}. Bots get it as ${name} from their next run.")
            })
        }
        ["secret", "rm" | "delete", name] => op("DELETE", &format!("/api/secrets/{}", env_name(name)?), None).map(|_| "Deleted.".into()),
        ["help", "admin"] | ["admin"] => Ok(ADMIN_HELP.into()),
        _ => Ok(HELP.into()),
    }
}

/// `user handover <user> <to> [--resume]`: the path and body.
fn handover_request(key: &str, rest: &[&str]) -> Result<(String, Value), String> {
    let usage = "Usage: botctl user handover <user> <to> [--resume]";
    let (to, resume) = match rest {
        [to] => (*to, false),
        [to, "--resume"] | ["--resume", to] => (*to, true),
        _ => return Err(usage.into()),
    };
    if to.starts_with("--") {
        return Err(usage.into());
    }
    Ok((format!("/api/users/{}/handover", encode(key)), json!({ "to": to, "resumeRoutines": resume })))
}

fn erase_request(key: &str, rest: &[&str]) -> Result<(String, Value), String> {
    if key.starts_with("--") || rest.iter().any(|a| !matches!(*a, "--yes" | "--destroy-machine" | "--delete-backups")) {
        return Err("Usage: botctl user erase <user> [--destroy-machine] [--delete-backups] --yes".into());
    }
    if !rest.contains(&"--yes") {
        return Err("Erasing deletes their personal data for good and can't be undone; add --yes".into());
    }
    let body = json!({ "destroyMachine": rest.contains(&"--destroy-machine"), "deleteBackups": rest.contains(&"--delete-backups") });
    Ok((format!("/api/users/{}/erase", encode(key)), body))
}

/// `botctl support-bundle [-o <file>]`: the file to save it as, if not botd's name for it.
fn bundle_out<'a>(rest: &[&'a str]) -> Result<Option<&'a str>, String> {
    match rest {
        [] => Ok(None),
        ["-o" | "--out", file] => Ok(Some(file)),
        _ => Err("Usage: botctl support-bundle [-o <file>]".into()),
    }
}

/// The file name a reply's `Content-Disposition` gives, if it is a plain one: it is saved
/// in the current folder, so no paths and no hidden files.
fn attachment_name(head: &str) -> Option<String> {
    let line = head.lines().find(|l| l.to_ascii_lowercase().starts_with("content-disposition:"))?;
    let name = line.split_once("filename=")?.1.trim().trim_matches('"');
    let plain = !name.is_empty() && !name.starts_with('.') && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
    plain.then(|| name.to_string())
}

/// Writes a new file only its owner can read; never over an existing one.
fn save_private(path: &str, bytes: &[u8]) -> Result<(), String> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    o.open(path).and_then(|mut f| f.write_all(bytes)).map_err(|e| format!("{path}: {e}"))
}

fn support_bundle(rest: &[&str]) -> Result<String, String> {
    let out = bundle_out(rest)?;
    let (code, head, body) = exchange_bytes(Cred::Operator, "GET", "/api/support/bundle").map_err(offline_hint)?;
    if !(200..300).contains(&code) {
        return Err(failure(code, &String::from_utf8_lossy(&body)));
    }
    let path = out.map(String::from).or_else(|| attachment_name(&head)).unwrap_or_else(|| "superbot-support.tar".into());
    save_private(&path, &body)?;
    Ok(format!(
        "Saved {path} ({} KB). It has no secrets, emails or chats, but read it before you attach it to a ticket:\n  tar -tvf {path}\n  tar -xOf {path} | less",
        body.len().div_ceil(1024)
    ))
}

/// Says how to make a bundle without botd when it can't be reached (ADR 0187).
fn offline_hint(e: String) -> String {
    if e.starts_with("Can't reach the server") {
        format!("{e}\nbotd isn't answering. On the server, botd support bundle makes one without it, and botd support check says what's wrong (docs/support/support-check.md).")
    } else {
        e
    }
}

/// `botctl support-report`: needs no botd, only the ticket system's export.
fn support_report(rest: &[&str], mut stdin: impl Read) -> Result<String, String> {
    let (file, options, format) = support_report::parse_args(rest, chrono::Utc::now())?;
    let mut csv = String::new();
    match file.as_str() {
        "-" => stdin.read_to_string(&mut csv).map(drop).map_err(|e| format!("stdin: {e}"))?,
        _ => csv = std::fs::read_to_string(&file).map_err(|e| format!("{file}: {e}"))?,
    }
    let report = support_report::report(&csv, &options)?;
    Ok(match format {
        support_report::Format::Text => report.text(),
        support_report::Format::Markdown => report.markdown(),
        support_report::Format::Json => pretty(report.json().to_string()),
    })
}

/// `botctl health-score [--days <n>] [json]`: the path, and whether to print the JSON.
fn health_request(rest: &[&str]) -> Result<(String, bool), String> {
    health_request_at(rest, "/api/support/health-score", "Usage: botctl health-score [--days <n>] [json]")
}

fn health_request_at(rest: &[&str], base: &str, usage: &str) -> Result<(String, bool), String> {
    let usage = || usage.to_string();
    let (mut days, mut json) = (None, false);
    let mut args = rest.iter();
    while let Some(a) = args.next() {
        match *a {
            "json" if !json => json = true,
            "--days" if days.is_none() => {
                let n = args.next().ok_or_else(usage)?;
                days = Some(n.parse::<u32>().map_err(|_| format!("--days must be a whole number of days, not \"{n}\""))?);
            }
            _ => return Err(usage()),
        }
    }
    let path = match days {
        Some(d) => format!("{base}?days={d}"),
        None => base.into(),
    };
    Ok((path, json))
}

/// The recorded days for a person: a line per day with a bar, then the trend.
fn history_summary(v: &Value) -> String {
    let points = v["points"].as_array().cloned().unwrap_or_default();
    let mut out = format!("Customer health history: last {} days, {} recorded\n", v["days"], if points.len() == 1 { "1 day".to_string() } else { format!("{} days", points.len()) });
    if v["recording"] == false {
        out.push_str("botd isn't recording the score (HEALTH_SCORE_HISTORY_DAYS=0).\n");
    }
    for p in &points {
        let score = p["score"].as_u64();
        let at_risk: Vec<&str> = p["signals"].as_object().map(|s| s.iter().filter(|(_, v)| *v == "risk").map(|(k, _)| k.as_str()).collect()).unwrap_or_default();
        let bar = "#".repeat(score.map_or(0, |s| s.div_ceil(5)) as usize);
        let line = format!(
            "  {}  {:>3}  {:<8}  {bar:<20}{}",
            p["date"].as_str().unwrap_or(""),
            score.map_or("-".to_string(), |s| s.to_string()),
            p["band"].as_str().unwrap_or("unknown").replace('_', " "),
            if at_risk.is_empty() { String::new() } else { format!("  at risk: {}", at_risk.join(", ")) },
        );
        out.push_str(line.trim_end());
        out.push('\n');
    }
    let t = &v["trend"];
    if t.is_object() {
        let change = t["change"].as_i64().map_or(String::new(), |c| format!(" ({c:+})"));
        let score = |k: &str| t[k].as_u64().map_or("no score".to_string(), |s| s.to_string());
        out.push_str(&format!("Since {}: {} to {}{change}.", t["from"].as_str().unwrap_or(""), score("fromScore"), score("toScore")));
        for (key, said) in [("worse", "Worse"), ("better", "Better")] {
            let ids: Vec<&str> = t[key].as_array().map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
            if !ids.is_empty() {
                out.push_str(&format!(" {said}: {}.", ids.join(", ")));
            }
        }
        out.push('\n');
    }
    out
}

/// The health score for a person: the score and band, then each signal on a line.
/// `botctl evidence baseline`: a line per setting, deviations first, then what to do.
fn baseline_summary(v: &Value) -> String {
    let c = &v["counts"];
    let mut out = format!(
        "Configuration baseline (docs/security/configuration-baseline.md), checked {}: {} meet it, {} don't, {} excepted, {} not applicable, {} to judge by hand\n",
        v["checkedAt"].as_str().unwrap_or("now"),
        c["pass"],
        c["fail"],
        c["excepted"],
        c["notApplicable"],
        c["manual"]
    );
    let settings = v["settings"].as_array().cloned().unwrap_or_default();
    let width = settings.iter().filter_map(|s| s["setting"].as_str()).map(str::len).max().unwrap_or(0);
    for want in ["fail", "excepted", "manual", "notApplicable", "pass"] {
        for s in settings.iter().filter(|s| s["status"] == want) {
            let status = match want {
                "fail" => "FAIL",
                "excepted" => "EXCEPTED",
                "manual" => "CHECK",
                "notApplicable" => "n/a",
                _ => "ok",
            };
            let (setting, value, note) = (s["setting"].as_str().unwrap_or(""), s["value"].as_str().unwrap_or(""), s["note"].as_str().unwrap_or(""));
            out.push_str(&format!("  {status:<8}  {setting:<width$}  {value} (baseline: {}); {note}\n", s["baseline"].as_str().unwrap_or("")));
        }
    }
    let names = |a: &Value| a.as_array().map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", ")).unwrap_or_default();
    let unknown = names(&v["exceptions"]["unknownExceptions"]);
    if !unknown.is_empty() {
        out.push_str(&format!("BASELINE_EXCEPTIONS names settings the baseline doesn't have: {unknown}.\n"));
    }
    let unneeded = names(&v["unneededExceptions"]);
    if !unneeded.is_empty() {
        out.push_str(&format!("Excepted but meeting the baseline, so the exception can go: {unneeded}.\n"));
    }
    out.push_str(&format!("Digest {}. Fix each FAIL or approve an exception for it (BASELINE_EXCEPTIONS); save this output with the quarterly check.\n", v["digest"].as_str().unwrap_or("")));
    out
}

fn health_summary(v: &Value) -> String {
    let score = v["score"].as_u64().map_or("no score".to_string(), |s| format!("{s}/100"));
    let band = v["band"].as_str().unwrap_or("unknown").replace('_', " ");
    let mut out = format!("Customer health: {score}, {band} (last {} days)\n", v["windowDays"]);
    let signals = v["signals"].as_array().cloned().unwrap_or_default();
    let width = signals.iter().filter_map(|s| s["label"].as_str()).map(str::len).max().unwrap_or(0);
    for s in &signals {
        let status = match s["status"].as_str().unwrap_or("") {
            "risk" => "AT RISK",
            other => other,
        };
        let label = s["label"].as_str().unwrap_or("");
        out.push_str(&format!("  {status:<7}  {label:<width$}  {:>2}  {}\n", s["weight"].as_u64().unwrap_or(0), s["summary"].as_str().unwrap_or("")));
    }
    let named = |key: &str| -> Vec<String> {
        let ids: Vec<&str> = v[key].as_array().map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
        signals.iter().filter(|s| s["id"].as_str().is_some_and(|id| ids.contains(&id))).filter_map(|s| s["label"].as_str().map(String::from)).collect()
    };
    let (risk, watch) = (named("atRisk"), named("watch"));
    if !risk.is_empty() {
        out.push_str(&format!("At risk: {}.\n", risk.join(", ")));
    }
    if !watch.is_empty() {
        out.push_str(&format!("Worth a look: {}.\n", watch.join(", ")));
    }
    if v["partial"] == true {
        out.push_str(&format!("The audit log keeps {} days, so its counts cover less than the window.\n", v["auditRetentionDays"]));
    }
    out.push_str("Weights are out of 100; n/a signals don't count. What each means and what to do: docs/support/health-score.md\n");
    out
}

/// `botctl evidence bundle [--from <date> --to <date>] [-o <file>]`: botd's path and the file to save it as.
fn evidence_request<'a>(rest: &[&'a str]) -> Result<(String, Option<&'a str>), String> {
    const USE: &str = "Usage: botctl evidence bundle [--from <YYYY-MM-DD> --to <YYYY-MM-DD>] [-o <file>]";
    let (mut from, mut to, mut out) = (None, None, None);
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        let slot = match *a {
            "--from" => &mut from,
            "--to" => &mut to,
            "-o" | "--out" => &mut out,
            _ => return Err(USE.into()),
        };
        if slot.is_some() {
            return Err(USE.into());
        }
        *slot = Some(*it.next().filter(|v| !v.starts_with("--")).ok_or(USE)?);
    }
    let path = match (from, to) {
        (None, None) => "/api/evidence/bundle".to_string(),
        (Some(f), Some(t)) => format!("/api/evidence/bundle?from={}&to={}", encode(f), encode(t)),
        _ => return Err("Give both --from and --to, or neither for last month.".into()),
    };
    Ok((path, out))
}

fn evidence_bundle(rest: &[&str]) -> Result<String, String> {
    let (path, out) = evidence_request(rest)?;
    let (code, head, body) = exchange_bytes(Cred::Operator, "GET", &path)?;
    if !(200..300).contains(&code) {
        return Err(failure(code, &String::from_utf8_lossy(&body)));
    }
    let served = attachment_name(&head);
    let file = out.map(String::from).or_else(|| served.clone()).unwrap_or_else(|| "superbot-evidence.tar".into());
    save_private(&file, &body)?;
    let manifest = head.lines().find_map(|l| l.to_ascii_lowercase().strip_prefix("x-evidence-manifest-sha256:").map(|v| v.trim().to_string())).unwrap_or_default();
    Ok(format!(
        "Saved {file} ({} KB). Its manifest's SHA-256 is {manifest}, as audited (evidence.bundle_created). Keep it in the evidence store; to check it:\n  {}",
        body.len().div_ceil(1024),
        evidence_check(&file, served.as_deref())
    ))
}

/// The shell line that checks a saved bundle. Its files sit in a folder named as botd
/// served the bundle, whatever it was saved as.
fn evidence_check(file: &str, served: Option<&str>) -> String {
    let quote = |s: &str| format!("'{}'", s.replace('\'', "'\\''"));
    let folder = served.unwrap_or_else(|| file.rsplit('/').next().unwrap_or(file));
    let folder = folder.strip_suffix(".tar").unwrap_or(folder);
    format!("tar -xf {} && cd {} && sha256sum -c SHA256SUMS", quote(file), quote(folder))
}

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as i64)
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(out) if out.ends_with('\n') => print!("{out}"),
        Ok(out) => println!("{out}"),
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Held by tests that set botctl's environment variables.
    static ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn support_report_reads_a_file_or_stdin_without_botd() {
        let csv = "id,severity,opened,first response\nT-9,2,2026-09-01T10:00:00Z,2026-09-01T10:30:00Z\n";
        let period = ["--plan", "max", "--from", "2026-09", "--to", "2026-09"];
        let from_stdin = support_report(&[&["-"][..], &period].concat(), csv.as_bytes()).unwrap();
        assert!(from_stdin.contains("1 of 1 answered within target (100%)."), "{from_stdin}");
        let file = std::env::temp_dir().join(format!("botctl-support-report-{}.csv", std::process::id()));
        std::fs::write(&file, csv).unwrap();
        let path = file.to_str().unwrap();
        let md = support_report(&[&[path, "--markdown"][..], &period].concat(), std::io::empty()).unwrap();
        assert!(md.contains("| 2026-09 | 2 | 1 | 1 | 0 | 0 | 30 min |"), "{md}");
        let json: Value = serde_json::from_str(&support_report(&[&[path, "--json"][..], &period].concat(), std::io::empty()).unwrap()).unwrap();
        assert_eq!(json["totals"]["metPercent"], 100);
        std::fs::remove_file(&file).unwrap();
        assert!(support_report(&["/nonexistent/tickets.csv", "--plan", "pro"], std::io::empty()).unwrap_err().contains("/nonexistent/tickets.csv"));
        assert!(support_report(&[], std::io::empty()).unwrap_err().starts_with("Usage: botctl support-report"));
    }

    #[test]
    fn a_failure_shows_the_servers_error() {
        assert_eq!(failure(403, r#"{"error":"not allowed"}"#), "not allowed (HTTP 403)");
        assert_eq!(failure(502, "Bad Gateway"), "Bad Gateway (HTTP 502)");
        assert_eq!(failure(400, r#"{"error":7}"#), r#"{"error":7} (HTTP 400)"#);
    }

    #[test]
    fn a_support_bundle_without_botd_points_at_the_offline_one() {
        let hint = offline_hint("Can't reach the server: Connection refused (os error 111)".into());
        assert!(hint.contains("botd support bundle") && hint.contains("docs/support/support-check.md"), "{hint}");
        assert_eq!(offline_hint("Missing SUPERBOT_TOKEN".into()), "Missing SUPERBOT_TOKEN");
    }

    #[test]
    fn a_support_bundle_is_saved_where_asked_or_under_botds_plain_name() {
        assert_eq!(bundle_out(&[]), Ok(None));
        assert_eq!(bundle_out(&["-o", "t.tar"]), Ok(Some("t.tar")));
        assert_eq!(bundle_out(&["--out", "/tmp/t.tar"]), Ok(Some("/tmp/t.tar")));
        assert!(bundle_out(&["-o"]).is_err() && bundle_out(&["t.tar"]).is_err());
        let head = "HTTP/1.1 200 OK\r\ncontent-type: application/x-tar\r\ncontent-disposition: attachment; filename=\"superbot-support-20261122T120000Z.tar\"";
        assert_eq!(attachment_name(head).as_deref(), Some("superbot-support-20261122T120000Z.tar"));
        for bad in ["../etc/passwd", ".bashrc", "a/b.tar", "", "x y.tar"] {
            assert_eq!(attachment_name(&format!("Content-Disposition: attachment; filename=\"{bad}\"")), None, "{bad}");
        }
        assert_eq!(attachment_name("HTTP/1.1 200 OK"), None);
    }

    #[test]
    fn health_score_takes_a_window_and_json() {
        assert_eq!(health_request(&[]), Ok(("/api/support/health-score".into(), false)));
        assert_eq!(health_request(&["json"]), Ok(("/api/support/health-score".into(), true)));
        assert_eq!(health_request(&["--days", "90", "json"]), Ok(("/api/support/health-score?days=90".into(), true)));
        assert_eq!(health_request(&["json", "--days", "7"]), Ok(("/api/support/health-score?days=7".into(), true)));
        for bad in [&["--days"][..], &["--days", "x"], &["--days", "-3"], &["7"], &["json", "json"], &["--days", "7", "--days", "8"]] {
            assert!(health_request(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn an_evidence_bundles_check_uses_the_served_folder_and_quotes_paths() {
        let served = "superbot-evidence-2026-10-01_2026-11-01-20261101T000000Z.tar";
        assert_eq!(evidence_check("evidence.tar", Some(served)), "tar -xf 'evidence.tar' && cd 'superbot-evidence-2026-10-01_2026-11-01-20261101T000000Z' && sha256sum -c SHA256SUMS");
        assert_eq!(evidence_check("my dir/it's.tar", None), "tar -xf 'my dir/it'\\''s.tar' && cd 'it'\\''s' && sha256sum -c SHA256SUMS");
    }

    #[test]
    fn an_evidence_bundle_is_for_last_month_or_the_period_given() {
        assert_eq!(evidence_request(&[]), Ok(("/api/evidence/bundle".into(), None)));
        assert_eq!(evidence_request(&["--from", "2026-10-01", "--to", "2026-11-01", "-o", "e.tar"]), Ok(("/api/evidence/bundle?from=2026-10-01&to=2026-11-01".into(), Some("e.tar"))));
        assert_eq!(evidence_request(&["--to", "2026-11-01", "--from", "2026-10-01"]).unwrap().0, "/api/evidence/bundle?from=2026-10-01&to=2026-11-01");
        for bad in [&["--from", "2026-10-01"][..], &["--from"], &["--from", "--to"], &["x"], &["-o", "a", "-o", "b"], &["--to", "2026-11-01"]] {
            assert!(evidence_request(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn health_score_history_reads_as_a_line_per_day() {
        assert_eq!(health_request_at(&["--days", "30", "json"], "/api/support/health-score/history", "u"), Ok(("/api/support/health-score/history?days=30".into(), true)));
        assert!(health_request_at(&["x"], "/a", "u").is_err());
        let v = json!({
            "days": 90, "recording": true,
            "points": [
                { "date": "2026-10-01", "score": 92, "band": "healthy", "signals": { "runs": "ok" } },
                { "date": "2026-11-01", "score": 41, "band": "at_risk", "signals": { "runs": "risk", "backups": "risk", "adoption": "watch" } },
                { "date": "2026-11-02", "score": null, "band": "unknown", "signals": {} },
            ],
            "trend": { "from": "2026-10-01", "fromScore": 92, "toScore": 41, "change": -51, "worse": ["runs"], "better": [] },
        });
        assert_eq!(
            history_summary(&v),
            "Customer health history: last 90 days, 3 days recorded\n  \
             2026-10-01   92  healthy   ###################\n  \
             2026-11-01   41  at risk   #########             at risk: backups, runs\n  \
             2026-11-02    -  unknown\n\
             Since 2026-10-01: 92 to 41 (-51). Worse: runs.\n"
        );
        let off = history_summary(&json!({ "days": 7, "recording": false, "points": [], "trend": null }));
        assert_eq!(off, "Customer health history: last 7 days, 0 days recorded\nbotd isn't recording the score (HEALTH_SCORE_HISTORY_DAYS=0).\n");
    }

    #[test]
    fn the_baseline_reads_as_a_line_per_setting_deviations_first() {
        let v = json!({
            "checkedAt": "2027-01-01T00:00:00Z", "ok": false, "digest": "ab12",
            "counts": { "pass": 1, "fail": 1, "excepted": 0, "notApplicable": 0, "manual": 1 },
            "settings": [
                { "setting": "AUTH_MFA", "status": "pass", "value": "admins", "baseline": "admins or all", "note": "n1" },
                { "setting": "TEAMS", "status": "manual", "value": "off", "baseline": "on when customers share the server", "note": "n2" },
                { "setting": "EVIDENCE_BUNDLES", "status": "fail", "value": "off", "baseline": "monthly", "note": "n3" },
            ],
            "exceptions": { "deviations": ["EVIDENCE_BUNDLES"], "excepted": [], "unknownExceptions": ["NOPE"] },
            "unneededExceptions": ["AUTH_MFA"],
        });
        let out = baseline_summary(&v);
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].contains("1 meet it, 1 don't, 0 excepted, 0 not applicable, 1 to judge by hand"), "{out}");
        assert!(lines[1].starts_with("  FAIL      EVIDENCE_BUNDLES  off (baseline: monthly); n3"), "{out}");
        assert!(lines[2].starts_with("  CHECK     TEAMS") && lines[3].starts_with("  ok        AUTH_MFA"), "{out}");
        assert!(out.contains("doesn't have: NOPE.") && out.contains("exception can go: AUTH_MFA.") && out.contains("Digest ab12."), "{out}");
    }

    #[test]
    fn health_score_reads_as_a_line_per_signal() {
        let v = json!({
            "score": 72, "band": "watch", "windowDays": 30, "atRisk": ["runs"], "watch": ["adoption"], "partial": true, "auditRetentionDays": 14,
            "signals": [
                { "id": "adoption", "label": "Adoption", "weight": 25, "status": "watch", "summary": "9 of 20 people (45%) signed in." },
                { "id": "runs", "label": "Bot runs", "weight": 20, "status": "risk", "summary": "20 of 100 runs (20%) failed." },
                { "id": "license", "label": "License", "weight": 5, "status": "n/a", "summary": "Testing mode." },
            ],
        });
        let out = health_summary(&v);
        assert_eq!(
            out,
            "Customer health: 72/100, watch (last 30 days)\n  \
             watch    Adoption  25  9 of 20 people (45%) signed in.\n  \
             AT RISK  Bot runs  20  20 of 100 runs (20%) failed.\n  \
             n/a      License    5  Testing mode.\n\
             At risk: Bot runs.\nWorth a look: Adoption.\n\
             The audit log keeps 14 days, so its counts cover less than the window.\n\
             Weights are out of 100; n/a signals don't count. What each means and what to do: docs/support/health-score.md\n"
        );
        assert!(health_summary(&json!({ "band": "at_risk", "windowDays": 7 })).starts_with("Customer health: no score, at risk (last 7 days)"));
    }

    #[test]
    fn a_saved_bundle_is_private_and_never_overwrites() {
        let path = std::env::temp_dir().join(format!("botctl-bundle-{}.tar", std::process::id()));
        let p = path.to_str().unwrap();
        let _ = std::fs::remove_file(&path);
        save_private(p, b"tar").unwrap();
        assert!(save_private(p, b"other").is_err(), "an existing file is kept");
        assert_eq!(std::fs::read(&path).unwrap(), b"tar");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn handover_names_the_disabled_user_and_who_takes_over() {
        let (path, body) = handover_request("ada@example.com", &["bea@example.com"]).unwrap();
        assert_eq!(path, "/api/users/ada%40example.com/handover");
        assert_eq!(body, json!({ "to": "bea@example.com", "resumeRoutines": false }));
        assert_eq!(handover_request("u1", &["u2", "--resume"]).unwrap().1["resumeRoutines"], true);
        assert_eq!(handover_request("u1", &["--resume", "u2"]).unwrap().1["to"], "u2");
        assert!(handover_request("u1", &[]).is_err());
        assert!(handover_request("u1", &["--resume"]).is_err());
        assert!(handover_request("u1", &["u2", "u3"]).is_err());
    }

    #[test]
    fn erase_needs_yes_and_maybe_destroys_the_machine() {
        let (path, body) = erase_request("ada@example.com", &["--yes"]).unwrap();
        assert_eq!(path, "/api/users/ada%40example.com/erase");
        assert_eq!(body, json!({ "destroyMachine": false, "deleteBackups": false }));
        assert_eq!(erase_request("u1", &["--destroy-machine", "--yes"]).unwrap().1["destroyMachine"], true);
        let (_, body) = erase_request("u1", &["--delete-backups", "--destroy-machine", "--yes"]).unwrap();
        assert_eq!(body, json!({ "destroyMachine": true, "deleteBackups": true }));
        assert!(erase_request("u1", &["--delete-backups"]).unwrap_err().contains("--yes"));
        assert!(erase_request("u1", &[]).unwrap_err().contains("--yes"));
        assert!(erase_request("u1", &["--destroy-machine"]).is_err());
        assert!(erase_request("u1", &["--yes", "u2"]).is_err());
        assert!(erase_request("--yes", &[]).is_err());
    }

    #[test]
    fn move_bots_names_the_tier_and_maybe_one_user() {
        let parse = |a: &[&str]| move_bots_request(a).map(|(p, b)| (p, serde_json::from_str::<Value>(&b).unwrap()));
        assert_eq!(parse(&["pro"]).unwrap(), ("/api/tiers/pro/move-bots".into(), json!({ "user": null, "dryRun": false })));
        assert_eq!(parse(&["pro", "--dry-run"]).unwrap().1, json!({ "user": null, "dryRun": true }));
        assert_eq!(parse(&["pro", "--user", "ada@example.com", "--dry-run"]).unwrap().1, json!({ "user": "ada@example.com", "dryRun": true }));
        assert_eq!(parse(&["pro", "--dry-run", "--user", "u1"]).unwrap().1["user"], "u1");
        for bad in [&[][..], &["--dry-run"], &["pro", "--user"], &["pro", "--user", "--dry-run"], &["pro", "ada"], &["pro", "--apply"]] {
            assert!(move_bots_request(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn harness_login_takes_extra_arguments_only_after_a_double_dash() {
        assert_eq!(login_extra(&[]), Ok((None, None)));
        assert_eq!(login_extra(&["--"]), Ok((None, Some(&[][..]))));
        assert_eq!(login_extra(&["--", "setup-token"]), Ok((None, Some(&["setup-token"][..]))));
        assert!(login_extra(&["setup-token"]).is_err());
        assert_eq!(login_extra(&["--owner", "ada"]), Ok((Some("ada"), None)));
        assert_eq!(login_extra(&["--owner", "ada", "--", "setup-token"]), Ok((Some("ada"), Some(&["setup-token"][..]))));
        assert_eq!(login_extra(&["--", "--owner", "ada"]), Ok((None, Some(&["--owner", "ada"][..]))), "after -- it's the login's");
        for bad in [&["--owner"][..], &["--owner", "--"], &["--owner", ""], &["ada", "--owner"]] {
            assert!(login_extra(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn machine_lifecycle_commands() {
        let r = |a: &[&str]| lifecycle_request(a).unwrap().unwrap();
        assert_eq!(r(&["list"]), ("GET", "/api/machines".into(), None));
        assert_eq!(r(&["list", "running"]), ("GET", "/api/machines?state=running".into(), None));
        assert_eq!(r(&["show", "a@example.com"]), ("GET", "/api/users/a%40example.com/machine".into(), None));
        assert_eq!(r(&["request", "u1"]), ("POST", "/api/users/u1/machine".into(), Some("{}".into())));
        let (_, _, body) = r(&["request", "u1", "pro", "node2"]);
        assert_eq!(serde_json::from_str::<Value>(&body.unwrap()).unwrap(), json!({ "tier": "pro", "region": "node2" }));
        assert_eq!(r(&["suspend", "u1"]), ("POST", "/api/users/u1/machine/suspend".into(), None));
        assert_eq!(r(&["resume", "u1"]), ("POST", "/api/users/u1/machine/resume".into(), None));
        assert_eq!(r(&["resize", "u1", "max"]), ("POST", "/api/users/u1/machine/resize".into(), Some(r#"{"tier":"max"}"#.into())));
        assert_eq!(r(&["resize", "u1", "status"]), ("GET", "/api/users/u1/machine/resize".into(), None));
        assert_eq!(r(&["resizes"]), ("GET", "/api/machines/resizes".into(), None));
        assert_eq!(r(&["destroy", "u1", "--yes"]), ("DELETE", "/api/users/u1/machine".into(), None));
        assert_eq!(r(&["enroll", "u1"]), ("POST", "/api/users/u1/machine/enrollment".into(), None));
        assert_eq!(r(&["revoke", "u1", "--yes"]), ("DELETE", "/api/users/u1/machine/certificates".into(), None));
        assert_eq!(r(&["substrate"]), ("GET", "/api/machines/substrate".into(), None));
        assert_eq!(r(&["substrate", "check"]), ("GET", "/api/machines/substrate?check=true".into(), None));
        assert_eq!(r(&["reconcile"]), ("POST", "/api/machines/reconcile".into(), None));
        for bad in [&["destroy", "u1"][..], &["revoke", "u1"], &["enroll"], &["resize", "u1"], &["request", "u1", "pro", "node2", "x"], &["substrate", "now"], &["show"], &["resizes", "all"]] {
            assert!(lifecycle_request(bad).unwrap().is_err(), "{bad:?}");
        }
        assert!(lifecycle_request(&["placement"]).is_none(), "the rest are machine_request's");
    }

    #[test]
    fn machine_commands_name_the_users_placement() {
        assert_eq!(machine_request(&["placement"]).unwrap(), ("GET", "/api/machines/placements".into()));
        assert_eq!(machine_request(&["placement", "a@example.com"]).unwrap(), ("GET", "/api/users/a%40example.com/placement".into()));
        assert_eq!(machine_request(&["assign", "u1"]).unwrap(), ("PUT", "/api/users/u1/placement".into()));
        assert_eq!(machine_request(&["unassign", "u1"]).unwrap(), ("DELETE", "/api/users/u1/placement".into()));
        assert!(machine_request(&["assign"]).is_err());
        assert_eq!(machine_request(&["agent", "a@example.com"]).unwrap(), ("GET", "/api/users/a%40example.com/machine/agent".into()));
        assert_eq!(machine_request(&["upgrade", "u1"]).unwrap(), ("POST", "/api/users/u1/machine/agent/upgrade".into()));
        assert_eq!(machine_request(&["upgrade", "u1", "hold"]).unwrap(), ("PUT", "/api/users/u1/machine/agent/hold".into()));
        assert_eq!(machine_request(&["upgrade", "u1", "release"]).unwrap(), ("DELETE", "/api/users/u1/machine/agent/hold".into()));
        assert_eq!(machine_request(&["harnesses", "u1"]).unwrap(), ("POST", "/api/users/u1/machine/harnesses".into()));
        assert_eq!(machine_request(&["mirror"]).unwrap(), ("GET", "/api/machines/harness-mirror".into()));
        assert_eq!(machine_request(&["bot-user", "u1"]).unwrap(), ("POST", "/api/users/u1/machine/bot-user".into()));
        assert!(machine_request(&["upgrade", "u1", "now"]).is_err());
        assert_eq!(machine_request(&["folder", "u1"]).unwrap(), ("GET", "/api/users/u1/machine/folder-sync".into()));
        assert_eq!(machine_request(&["sync", "u1"]).unwrap(), ("POST", "/api/users/u1/machine/folder-sync".into()));
        assert_eq!(machine_request(&["screens", "a@example.com"]).unwrap(), ("GET", "/api/users/a%40example.com/machine/screens".into()));
        assert_eq!(machine_request(&["screens", "u1", "close", "b 1"]).unwrap(), ("DELETE", "/api/users/u1/machine/screens/b%201".into()));
        assert!(machine_request(&["screens", "u1", "close"]).is_err());
        assert_eq!(teammate_accounts_request(&["teammates", "u1"]).unwrap(), ("GET", "/api/users/u1/teammate-accounts".into()));
        assert_eq!(
            teammate_accounts_request(&["teammates", "a@example.com", "remove", "b@example.com"]).unwrap(),
            ("POST", "/api/users/a%40example.com/teammate-accounts/b%40example.com/remove".into())
        );
        assert_eq!(teammate_accounts_request(&["teammate-removals"]).unwrap(), ("GET", "/api/isolation/teammate-removals?state=open".into()));
        assert_eq!(teammate_accounts_request(&["teammate-removals", "held"]).unwrap(), ("GET", "/api/isolation/teammate-removals?state=held".into()));
        for bad in [&["teammates", "u1", "remove"][..], &["teammates"], &["teammate-removals", "soon"], &["teammates", "u1", "purge", "u2"]] {
            assert!(teammate_accounts_request(bad).is_err(), "{bad:?}");
        }
        assert_eq!(machine_request(&["teammates", "u1"]).unwrap(), ("GET", "/api/users/u1/machine/teammates".into()));
        assert_eq!(
            machine_request(&["teammates", "u1", "remove", "b@example.com"]).unwrap(),
            ("POST", "/api/users/u1/machine/teammates/b%40example.com/remove".into())
        );
        assert_eq!(machine_request(&["removals"]).unwrap(), ("GET", "/api/machines/teammate-removals?state=open".into()));
        assert_eq!(machine_request(&["removals", "held"]).unwrap(), ("GET", "/api/machines/teammate-removals?state=held".into()));
        assert!(machine_request(&["removals", "soon"]).is_err());
        assert!(machine_request(&["teammates", "u1", "remove"]).is_err());
        assert_eq!(
            machine_request(&["teammates", "u1", "logins", "b@example.com"]).unwrap(),
            ("GET", "/api/users/u1/machine/teammates/b%40example.com/harness-logins".into())
        );
        assert_eq!(
            machine_request(&["teammates", "u1", "logout", "u2", "claude"]).unwrap(),
            ("DELETE", "/api/users/u1/machine/teammates/u2/harness-logins/claude".into())
        );
        assert!(machine_request(&["teammates", "u1", "logout", "u2"]).is_err());
        assert_eq!(rebuild_request(&["a@example.com"]).unwrap(), ("POST", "/api/users/a%40example.com/machine/rebuild".into(), None));
        assert_eq!(
            rebuild_request(&["u1", "--discard-work"]).unwrap(),
            ("POST", "/api/users/u1/machine/rebuild?discardWork=true".into(), None)
        );
        assert_eq!(rebuild_request(&["u1", "status"]).unwrap(), ("GET", "/api/users/u1/machine/rebuild".into(), None));
        assert_eq!(rebuild_request(&["u1", "cancel"]).unwrap(), ("DELETE", "/api/users/u1/machine/rebuild".into(), None));
        assert!(rebuild_request(&[]).is_err());
        assert!(rebuild_request(&["--discard-work"]).is_err());
        assert!(rebuild_request(&["u1", "--discard"]).is_err());
        let read = |f: &str| if f == "key.txt" { Ok("AGE-SECRET-KEY-1X".to_string()) } else { Err(format!("{f}: missing")) };
        assert_eq!(backup_request(&["backups"], read).unwrap(), ("GET", "/api/machines/backups".into(), None));
        assert_eq!(backup_request(&["recovery"], read).unwrap(), ("GET", "/api/machines/recovery".into(), None));
        assert_eq!(backup_request(&["backups", "a@example.com"], read).unwrap(), ("GET", "/api/users/a%40example.com/machine/backups".into(), None));
        assert_eq!(backup_request(&["backup", "u1"], read).unwrap(), ("POST", "/api/users/u1/machine/backups".into(), None));
        assert_eq!(backup_request(&["restore", "u1", "status"], read).unwrap(), ("GET", "/api/users/u1/machine/restore".into(), None));
        let (m, p, b) = backup_request(&["restore", "u1", "b1", "--identity", "key.txt", "--yes"], read).unwrap();
        assert_eq!((m, p.as_str()), ("POST", "/api/users/u1/machine/restore"));
        assert_eq!(serde_json::from_str::<serde_json::Value>(&b.unwrap()).unwrap(), json!({ "backupId": "b1", "identity": "AGE-SECRET-KEY-1X" }));
        let (_, _, b) = backup_request(&["restore", "u1", "b1", "--yes"], read).unwrap();
        assert_eq!(serde_json::from_str::<serde_json::Value>(&b.unwrap()).unwrap(), json!({ "backupId": "b1", "identity": null }));
        assert!(backup_request(&["restore", "u1", "b1"], read).unwrap_err().contains("--yes"));
        assert!(backup_request(&["restore", "u1", "b1", "--identity", "--yes"], read).is_err());
        assert!(backup_request(&["restore", "u1", "b1", "--identity", "nope", "--yes"], read).is_err());
        assert!(backup_request(&["backup"], read).is_err());
        assert_eq!(backup_request(&["delete-backups", "m1a2", "--yes"], read).unwrap(), ("DELETE", "/api/machines/m1a2/backups".into(), None));
        assert_eq!(backup_request(&["delete-backups", "--yes", "m/1"], read).unwrap(), ("DELETE", "/api/machines/m%2F1/backups".into(), None));
        assert!(backup_request(&["delete-backups", "m1a2"], read).unwrap_err().contains("--yes"));
        assert!(backup_request(&["delete-backups", "--yes"], read).is_err());
        assert!(backup_request(&["delete-backups", "m1", "--yes", "extra"], read).is_err());
        let (_, _, b) = backup_request(&["restore", "u1", "b1", "--host", "spare", "--yes"], read).unwrap();
        assert_eq!(serde_json::from_str::<serde_json::Value>(&b.unwrap()).unwrap(), json!({ "backupId": "b1", "identity": null, "host": "spare" }));
        assert_eq!(backup_request(&["hosts"], read).unwrap(), ("GET", "/api/machines/hosts".into(), None));
        assert_eq!(backup_request(&["hosts", "check"], read).unwrap(), ("GET", "/api/machines/hosts?check=true".into(), None));
        let (m, p, b) = backup_request(&["host", "recover", "main", "--to", "spare", "--identity", "key.txt", "--yes"], read).unwrap();
        assert_eq!((m, p.as_str()), ("POST", "/api/machines/hosts/main/recover"));
        assert_eq!(serde_json::from_str::<serde_json::Value>(&b.unwrap()).unwrap(), json!({ "to": "spare", "identity": "AGE-SECRET-KEY-1X" }));
        let (_, _, b) = backup_request(&["host", "recover", "main", "--yes"], read).unwrap();
        assert_eq!(serde_json::from_str::<serde_json::Value>(&b.unwrap()).unwrap(), json!({ "to": null, "identity": null }));
        assert!(backup_request(&["host", "recover", "main"], read).unwrap_err().contains("--yes"));
        assert!(backup_request(&["host", "recover", "--yes"], read).is_err());
        let (m, p, b) = backup_request(&["host", "drain", "b", "--reason", "disk swap"], read).unwrap();
        assert_eq!((m, p.as_str()), ("PUT", "/api/machines/hosts/b/drain"));
        assert_eq!(serde_json::from_str::<serde_json::Value>(&b.unwrap()).unwrap(), json!({ "reason": "disk swap" }));
        let (_, _, b) = backup_request(&["host", "drain", "b"], read).unwrap();
        assert_eq!(serde_json::from_str::<serde_json::Value>(&b.unwrap()).unwrap(), json!({ "reason": null }));
        assert_eq!(backup_request(&["host", "undrain", "b"], read).unwrap(), ("DELETE", "/api/machines/hosts/b/drain".into(), None));
        assert!(backup_request(&["host", "undrain"], read).is_err());
        let (m, p, b) = backup_request(&["host", "dedicate", "b", "t1", "--reason", "MSA-7"], read).unwrap();
        assert_eq!((m, p.as_str()), ("PUT", "/api/machines/hosts/b/dedication"));
        assert_eq!(serde_json::from_str::<serde_json::Value>(&b.unwrap()).unwrap(), json!({ "team": "t1", "reason": "MSA-7" }));
        let (_, _, b) = backup_request(&["host", "dedicate", "b", "t1"], read).unwrap();
        assert_eq!(serde_json::from_str::<serde_json::Value>(&b.unwrap()).unwrap(), json!({ "team": "t1", "reason": null }));
        assert!(backup_request(&["host", "dedicate", "b"], read).is_err(), "a team is needed");
        let (m, p, b) = backup_request(&["host", "share", "b", "--reason", "contract ended"], read).unwrap();
        assert_eq!((m, p.as_str()), ("DELETE", "/api/machines/hosts/b/dedication"));
        assert_eq!(serde_json::from_str::<serde_json::Value>(&b.unwrap()).unwrap(), json!({ "reason": "contract ended" }));
        assert!(backup_request(&["host", "share", "b"], read).unwrap_err().contains("--reason"));
        assert_eq!(login_base("me"), "/api/machine");
        assert_eq!(login_base("a@example.com"), "/api/users/a%40example.com/machine");
    }

    #[test]
    fn base64_matches_the_standard() {
        assert_eq!(base64(b"superbot:pw"), "c3VwZXJib3Q6cHc=");
        assert_eq!(base64(b"ab"), "YWI=");
        assert_eq!(base64(b"abc"), "YWJj");
    }

    #[test]
    fn the_operator_password_only_goes_to_this_machine() {
        for a in ["127.0.0.1:3000", "127.1.2.3:80", "localhost:3000", "LOCALHOST:3000", "[::1]:3000"] {
            assert!(loopback(a), "{a}");
        }
        for a in ["192.0.2.7:3000", "example.com:3000", "localhost.example.com:3000", "[2001:db8::1]:3000", "0.0.0.0:3000", "127.0.0.1.example.com:3000"] {
            assert!(!loopback(a), "{a}");
        }
        assert_eq!(addr("http://127.0.0.1:3000/"), Ok("127.0.0.1:3000"));
        for b in ["https://127.0.0.1:3000", "127.0.0.1:3000", "http://user@192.0.2.7:3000", "http://192.0.2.7:3000/x", "http://"] {
            assert!(addr(b).is_err(), "{b}");
        }
        let _env = ENV.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: tests that set these variables hold ENV.
        unsafe {
            std::env::set_var("BOT_API", "http://192.0.2.7:3000");
            std::env::set_var("SUPERBOT_PASSWORD", std::process::id().to_string());
        }
        let err = api(Cred::Operator, "GET", "/api/approvals", None).unwrap_err();
        assert!(err.contains("only to a server on this machine"), "{err}");
    }

    #[test]
    fn audit_options_become_a_query() {
        assert_eq!(audit_query(&[]).unwrap(), "");
        assert_eq!(audit_query(&["50"]).unwrap(), "?limit=50");
        assert_eq!(
            audit_query(&["--from", "2026-11-19T13:00:00+01:00", "--action", "bot.*,auth.login", "--actor", "bot:ab12"]).unwrap(),
            "?from=2026-11-19T13:00:00%2B01:00&action=bot.*,auth.login&actor=bot:ab12"
        );
        assert_eq!(audit_query(&["--to", "a b&c"]).unwrap(), "?to=a%20b%26c");
        assert_eq!(
            audit_query(&["--actor", "user:ada@example.com", "--method", "sso,password", "--idp", "entra", "--idp-provider", "work"]).unwrap(),
            "?actor=user:ada%40example.com&method=sso,password&idp=entra&idpProvider=work"
        );
        assert_eq!(
            audit_query(&["--subject", "https://idp.example/t1|oid-1", "--session", "s0a1b", "--on-behalf-of", "u42"]).unwrap(),
            "?subject=https:%2F%2Fidp.example%2Ft1%7Coid-1&session=s0a1b&onBehalfOf=u42"
        );
        assert!(audit_query(&["--from"]).is_err());
        assert!(audit_query(&["--nope", "x"]).is_err());
        assert_eq!(verify_query(&[]).unwrap(), "");
        assert_eq!(verify_query(&["--pin", "12:ab", "--pin", "13:cd"]).unwrap(), "?pin=12:ab,13:cd");
        assert!(verify_query(&["--pin"]).is_err() && verify_query(&["--all"]).is_err());
        let key = "ab".repeat(32);
        assert_eq!(verify_query(&["--from", "10", "--to", "20", "--key", &key, "--pin", "12:ab"]).unwrap(), format!("?pin=12:ab&from=10&to=20&key={key}"));
        assert!(verify_query(&["--from", "x"]).is_err() && verify_query(&["--to"]).is_err() && verify_query(&["--key"]).is_err());
        assert_eq!(verify_query(&["--archive", "--from", "10"]).unwrap(), "?archive=on&from=10");
    }

    #[test]
    fn login_and_user_commands() {
        assert_eq!(login_body(&[" sbc_abc "]).unwrap(), json!({ "code": "sbc_abc", "session": "token", "label": "botctl" }));
        assert!(login_body(&["  "]).is_err());
        assert_eq!(login_body(&["sbc_abc", "--totp", " 123456"]).unwrap(), json!({ "code": "sbc_abc", "totp": "123456", "session": "token", "label": "botctl" }));
        assert_eq!(login_body(&["sbc_abc", "--recovery-code", "abcde-fghij"]).unwrap()["recoveryCode"], "abcde-fghij");
        for bad in [&["sbc_abc", "--totp"][..], &["sbc_abc", "--totp", "1", "--recovery-code", "2"], &["sbc_abc", "extra"], &["sbc_abc", "--nope", "1"]] {
            assert!(login_body(bad).is_err(), "{bad:?}");
        }
        assert_eq!(factor_body("sbm_x", " 123456\n", false).unwrap(), json!({ "challenge": "sbm_x", "totp": "123456", "session": "token", "label": "botctl" }));
        assert_eq!(factor_body("sbm_x", "abcde-fghij", false).unwrap()["recoveryCode"], "abcde-fghij");
        assert_eq!(factor_body("sbm_x", "12345", true).unwrap()["totp"], "12345");
        assert!(factor_body("sbm_x", "  ", false).is_err());
        assert_eq!(setup_text(&json!({ "secret": "ABCD", "otpauthUrl": "otpauth://totp/x" })), "  Setup key: ABCD\n  otpauth://totp/x");
        let done = signed_in(&json!({ "token": "sbt_t", "user": { "name": "Ana", "role": "admin" }, "recoveryCodes": ["aaaaa-bbbbb", "ccccc-ddddd"] }));
        assert!(done.contains("export SUPERBOT_TOKEN=sbt_t") && done.contains("  aaaaa-bbbbb\n  ccccc-ddddd"), "{done}");
        assert_eq!(role("read-only"), Ok("read-only"));
        assert!(role("root").is_err());
        assert_eq!(encode("a.b+c@example.com"), "a.b%2Bc%40example.com");
    }

    #[test]
    fn region_commands() {
        let body = |r: Value| Some(json!({ "region": r }).to_string());
        assert_eq!(region_request(&["regions"]), Some(("GET", "/api/regions".into(), None)));
        assert_eq!(region_request(&["user", "region", "ada@example.com"]), Some(("GET", "/api/users/ada%40example.com/region".into(), None)));
        assert_eq!(region_request(&["user", "region", "u1", "gb-lon"]), Some(("PUT", "/api/users/u1/region".into(), body(json!("gb-lon")))));
        assert_eq!(region_request(&["user", "region", "u1", "default"]), Some(("PUT", "/api/users/u1/region".into(), body(Value::Null))));
        assert_eq!(region_request(&["team", "region", "t1", "de-fra-2"]), Some(("PUT", "/api/teams/t1/region".into(), body(json!("de-fra-2")))));
        assert_eq!(region_request(&["team", "region", "t1", "default"]), Some(("PUT", "/api/teams/t1/region".into(), body(Value::Null))));
        assert_eq!(region_request(&["team", "region", "t1"]), Some(("GET", "/api/teams/t1/region".into(), None)));
        for other in [&["team", "region"][..], &["user", "tier", "u1", "pro"], &["region"]] {
            assert_eq!(region_request(other), None, "{other:?}");
        }
    }

    #[test]
    fn egress_commands() {
        let req = |a: &[&str]| egress_request(a).map(|(m, p, b)| (m, p, b.map(|b| serde_json::from_str::<Value>(&b).unwrap())));
        assert_eq!(req(&["machine", "egress"]), Some(("GET", "/api/machines/egress-policy".into(), None)));
        assert_eq!(req(&["machine", "egress", "open"]), Some(("PUT", "/api/machines/egress-policy".into(), Some(json!({ "mode": "open", "allow": [] })))));
        assert_eq!(
            req(&["machine", "egress", "allow", "api.anthropic.com", "203.0.113.0/24"]),
            Some(("PUT", "/api/machines/egress-policy".into(), Some(json!({ "mode": "allow_list", "allow": ["api.anthropic.com", "203.0.113.0/24"] }))))
        );
        assert_eq!(req(&["user", "egress", "ada@example.com"]), Some(("GET", "/api/users/ada%40example.com/machine/egress-policy".into(), None)));
        assert_eq!(req(&["user", "egress", "u1", "inherit"]), Some(("PUT", "/api/users/u1/machine/egress-policy".into(), Some(json!({ "mode": "inherit", "allow": [] })))));
        assert_eq!(
            req(&["user", "egress", "u1", "allow", "registry.npmjs.org"]),
            Some(("PUT", "/api/users/u1/machine/egress-policy".into(), Some(json!({ "mode": "allow_list", "allow": ["registry.npmjs.org"] }))))
        );
        for other in [&["machine", "egress", "allow"][..], &["user", "egress", "u1", "closed"], &["user", "egress"], &["machine", "egress", "shut"]] {
            assert_eq!(egress_request(other), None, "{other:?}");
            let args: Vec<String> = other.iter().map(|s| s.to_string()).collect();
            let e = run(&args).unwrap_err();
            assert!(e.starts_with("Usage: botctl machine egress"), "{other:?} reached another command: {e}");
        }
    }

    #[test]
    fn residency_commands() {
        let body = |v: Value| Some(v.to_string());
        assert_eq!(region_request(&["user", "residency", "ada@example.com"]), Some(("GET", "/api/users/ada%40example.com/residency".into(), None)));
        assert_eq!(
            region_request(&["user", "residency", "u1", "pin", "gb-lon", "DPA", "2026-014"]),
            Some(("PUT", "/api/users/u1/residency".into(), body(json!({ "region": "gb-lon", "reference": "DPA 2026-014" }))))
        );
        assert_eq!(
            region_request(&["team", "residency", "t1", "unpin", "contract", "ended"]),
            Some(("DELETE", "/api/teams/t1/residency".into(), body(json!({ "reason": "contract ended" }))))
        );
        assert_eq!(region_request(&["team", "residency", "t1"]), Some(("GET", "/api/teams/t1/residency".into(), None)));
        for other in [&["user", "residency", "u1", "pin", "gb-lon"][..], &["team", "residency", "t1", "unpin"], &["user", "residency"], &["bot", "residency", "b1"]] {
            assert_eq!(region_request(other), None, "{other:?}");
        }
    }

    #[test]
    fn residency_report_commands() {
        assert_eq!(residency_report_request("user", "ada@example.com", &[]), Ok(("/api/users/ada%40example.com/residency/report?format=markdown".into(), None)));
        assert_eq!(
            residency_report_request("team", "t1", &["--from", "2026-08-01", "--to", "2026-10-31", "--json", "-o", "r.json"]),
            Ok(("/api/teams/t1/residency/report?from=2026-08-01&to=2026-10-31".into(), Some("r.json")))
        );
        for bad in [&["--from"][..], &["--json", "extra"], &["-o"]] {
            assert!(residency_report_request("team", "t1", bad).unwrap_err().starts_with("Usage: botctl team residency <team> report"), "{bad:?}");
        }
        assert_eq!(region_request(&["user", "residency", "u1", "report"]), None, "the report isn't a pin or an unpin");
    }

    #[test]
    fn bot_access_commands() {
        let req = |a: &[&str]| bot_access(a).map(|(m, p, b)| (m, p, b.map(|b| serde_json::from_str::<Value>(&b).unwrap())));
        assert_eq!(req(&["access", "b1"]), Ok(("GET", "/api/bots/b1/access".into(), None)));
        assert_eq!(req(&["share", "b1"]), Ok(("PATCH", "/api/bots/b1/access".into(), Some(json!({ "visibility": "shared" })))));
        assert_eq!(req(&["private", "b1"]), Ok(("PATCH", "/api/bots/b1/access".into(), Some(json!({ "visibility": "private" })))));
        assert_eq!(req(&["owner", "b1", "a@example.com"]), Ok(("PATCH", "/api/bots/b1/access".into(), Some(json!({ "owner": "a@example.com" })))));
        assert_eq!(req(&["grant", "b1", "a+b@example.com", "operator"]), Ok(("PUT", "/api/bots/b1/grants/a%2Bb%40example.com".into(), Some(json!({ "level": "operator" })))));
        assert_eq!(req(&["revoke", "b1", "u1"]), Ok(("DELETE", "/api/bots/b1/grants/u1".into(), None)));
        assert!(req(&["grant", "b1", "u1", "owner"]).is_err());
        assert!(req(&["share"]).is_err());
        assert!(req(&[]).is_err());
    }

    #[test]
    fn setup_commands() {
        let req = |a: &[&str]| setup_request(a).map(|(m, b)| (m, b.map(|b| serde_json::from_str::<Value>(&b).unwrap())));
        assert_eq!(req(&[]), Ok(("GET", None)));
        assert_eq!(req(&["status"]), Ok(("GET", None)));
        assert_eq!(req(&["done"]), Ok(("PATCH", Some(json!({ "completed": true })))));
        assert_eq!(req(&["reopen"]), Ok(("PATCH", Some(json!({ "completed": false })))));
        assert_eq!(req(&["hide"]), Ok(("PATCH", Some(json!({ "dismissed": true })))));
        assert_eq!(req(&["show"]), Ok(("PATCH", Some(json!({ "dismissed": false })))));
        assert!(req(&["finish", "now"]).is_err());

        let s = json!({
            "progress": { "step": "signin", "dismissed": false, "completedAt": null },
            "done": 1, "total": 2,
            "checklist": [
                { "id": "domain", "label": "A public address with HTTPS", "done": true, "detail": "People reach SuperBot at https://bots.example.com." },
                { "id": "signin", "label": "Sign-in providers ready", "done": false, "detail": "Waiting for a secret: Okta." },
            ],
            "signIn": { "providers": [
                { "label": "Okta", "ready": false, "secret": "SSO_OKTA_CLIENT_SECRET" },
                { "id": "corp", "label": "Corp SAML", "ready": false, "secret": null },
            ] },
        });
        let out = setup_summary(&s);
        assert!(out.starts_with("Setup: 1 of 2 done (admins see the wizard"), "{out}");
        assert!(out.contains("[x] A public address with HTTPS") && out.contains("[ ] Sign-in providers ready"), "{out}");
        assert!(out.contains("botctl secret set SSO_OKTA_CLIENT_SECRET < file") && out.contains("botctl setup done"), "{out}");
        assert!(out.contains("Corp SAML needs its IdP metadata: botctl sso saml corp import idp-metadata.xml") && !out.contains("secret set  <"));
        let done = setup_summary(&json!({ "progress": { "completedAt": 1 }, "done": 2, "total": 2, "checklist": [] }));
        assert!(done.starts_with("Setup: 2 of 2 done (finished).") && !done.contains("botctl setup done"), "{done}");
        let down = setup_summary(&json!({ "progress": { "completedAt": 1 }, "checklist": [], "secretsBackend": { "backend": "azure-keyvault", "ok": false, "detail": "azure-keyvault can't be read: 403" } }));
        assert!(down.contains("Secrets backend azure-keyvault: azure-keyvault can't be read: 403"), "{down}");
    }

    #[test]
    fn secrets_backend_summary() {
        let local = json!({ "backend": "local", "description": "the environment and the sealed store", "ok": true, "detail": "Local: ..." });
        assert_eq!(backend_summary(&local).unwrap(), "Secrets backend: local\n  Local: ...");
        let gcp = json!({ "backend": "gcp-secret-manager", "description": "GCP Secret Manager at https://secretmanager.googleapis.com", "cacheSeconds": 300, "ok": true, "names": 3, "detail": "gcp-secret-manager answers: 3 names" });
        assert_eq!(backend_summary(&gcp).unwrap(), "Secrets backend: gcp-secret-manager (GCP Secret Manager at https://secretmanager.googleapis.com, cached for 300 s)\n  gcp-secret-manager answers: 3 names");
        let down = json!({ "backend": "vault", "description": "HashiCorp Vault at https://v", "ok": false, "detail": "vault can't be read" });
        assert!(backend_summary(&down).unwrap_err().ends_with("vault can't be read"), "a failing backend is an error, for scripts");
        assert!(backend_summary(&Value::Null).is_err());
    }

    #[test]
    fn usage_summary_shows_use_against_limits() {
        let v = json!({ "billing": true, "checkout": true, "users": [
            { "user": { "email": "ada@example.com" }, "over": ["bots", "machineType"],
              "plan": { "label": "Starter", "limits": { "maxBots": 2, "monthlyRuns": 300, "dailyRoutineRuns": 24, "machineType": "g6-standard-1" },
                        "usage": { "bots": 3, "runs": 12, "tokens": 4500, "period": "2026-11", "routineRuns": 4, "day": "2026-11-20" } },
              "machine": { "plan": "g6-standard-2", "state": "running", "resize": { "state": "waiting", "toPlan": "g6-standard-1", "message": "Storage is 6 GB used of the Starter plan's 5 GB." } }, "subscription": { "status": "active" }, "customer": "cus_123" },
            { "user": { "name": "Owner" }, "over": [], "machine": null, "subscription": null,
              "plan": { "label": "Self-host", "limits": {}, "usage": { "bots": 1, "runs": 0, "period": "2026-11", "routineRuns": 0, "day": "2026-11-20" } } },
        ]});
        let out = usage_summary(&v);
        assert!(out.starts_with("Billing: Stripe webhook and checkout on.\n"), "{out}");
        assert!(out.contains("ada@example.com: Starter plan; Bots 3/2; runs 12/300 and tokens 4500/unlimited in 2026-11; routine runs 4/24 on 2026-11-20; machine g6-standard-2 (running), plan size g6-standard-1; resizing to g6-standard-1 (waiting: Storage is 6 GB used of the Starter plan's 5 GB.); Stripe active; customer cus_123; OVER: bots, machineType\n"), "{out}");
        assert!(usage_summary(&json!({ "billing": true, "users": [] })).starts_with("Billing: Stripe webhook on, checkout off.\n"));
        assert!(out.contains("Owner: Self-host plan; Bots 1/unlimited; runs 0/unlimited and tokens 0/unlimited in 2026-11; routine runs 0/unlimited on 2026-11-20\n"), "{out}");
    }

    #[test]
    fn storage_shows_against_the_plan() {
        assert_eq!(storage_text(&json!({ "used": null, "limitMb": 5 })), None);
        assert_eq!(storage_text(&json!({ "used": 940_000, "limitMb": 1, "state": "warning" })).unwrap(), "0.9 MB/1 MB (nearly full)");
        assert_eq!(storage_text(&json!({ "used": 12_345_678, "limitMb": null, "state": "ok" })).unwrap(), "12.3 MB/unlimited");
        assert_eq!(storage_text(&json!({ "used": 2_000_000, "limitMb": 1, "state": "over", "partial": true })).unwrap(), "2.0 MB/1 MB (full) (at least: some folders couldn't be read)");
    }

    #[test]
    fn period_summary_shows_tokens_by_bot_and_model() {
        let v = json!({
            "tier": { "label": "Pro" },
            "period": { "start": 1_794_990_000_000_i64, "end": 1_797_582_000_000_i64, "source": "subscription" },
            "tokens": { "input": 1000, "output": 200, "cacheRead": 300, "cacheWrite": 0, "total": 1500, "limit": 5_000_000, "unreportedRuns": 1 },
            "runs": { "used": 2, "limit": null },
            "byBot": [{ "bot": "b1", "name": "Ada's", "total": 1500, "runs": 2 }, { "bot": "b2", "name": null, "total": 0, "runs": 1 }],
            "byModel": [{ "model": "claude-sonnet-4-5", "total": 1500, "runs": 1 }],
        });
        let out = period_summary(&v);
        assert_eq!(
            out,
            "Pro plan, 2026-11-18 to 2026-12-18 (subscription period)\nTokens 1500/5000000 (input 1000, output 200, cache read 300, cache write 0)\nRuns 2/unlimited; 1 reported no tokens\n  Bot Ada's (b1): 1500 tokens in 2 runs\n  Bot (deleted or not yours now) (b2): 0 tokens in 1 runs\n  Model claude-sonnet-4-5: 1500 tokens in 1 runs\n"
        );
        // A member on a managed plan gets no models; the calendar month says so.
        let mut member = v.clone();
        member.as_object_mut().unwrap().remove("byModel");
        member["period"]["source"] = json!("calendar");
        let out = period_summary(&member);
        assert!(out.contains("(calendar month, UTC)") && !out.contains("Model"), "{out}");
    }

    #[test]
    fn license_summary_reads_like_a_status_line() {
        let grace = json!({
            "mode": "grace", "source": "file", "detail": "The license for Acme Ltd ended on 2027-01-01.",
            "license": { "id": "lic-7" }, "seats": { "limit": 30, "used": 31 },
            "warnings": ["The license for Acme Ltd ended on 2027-01-01.", "31 people are active, over the 30 seats allowed."],
        });
        let out = license_summary(&grace);
        assert!(out.starts_with("License: grace (31 of 30 seats in use).\n  The license for Acme Ltd ended"), "{out}");
        assert!(out.contains("Id lic-7, source file.") && out.contains("Warning: 31 people") && out.matches("ended on").count() == 1, "{out}");
        let open = license_summary(&json!({ "mode": "active", "detail": "Licensed.", "seats": { "limit": null, "used": 4 }, "warnings": [] }));
        assert!(open.starts_with("License: active (4 active, no seat limit)."), "{open}");
    }

    #[test]
    fn signup_commands() {
        let req = |a: &[&str]| signup_request(a).map(|(m, p, b)| (m, p, b.map(|b| serde_json::from_str::<Value>(&b).unwrap())));
        assert_eq!(req(&[]), Ok(("GET", "/api/signups?status=pending".into(), None)));
        assert_eq!(req(&["list", "all"]), Ok(("GET", "/api/signups".into(), None)));
        assert_eq!(req(&["list", "rejected"]), Ok(("GET", "/api/signups?status=rejected".into(), None)));
        assert_eq!(req(&["approve", "su1"]), Ok(("POST", "/api/signups/su1/approve".into(), Some(json!({ "role": null, "ttlMinutes": null })))));
        assert_eq!(
            req(&["approve", "su1", "--role", "readonly", "--ttl", "90"]),
            Ok(("POST", "/api/signups/su1/approve".into(), Some(json!({ "role": "readonly", "ttlMinutes": 90 }))))
        );
        assert_eq!(req(&["reject", "su1", "--reason", "spam"]), Ok(("POST", "/api/signups/su1/reject".into(), Some(json!({ "reason": "spam" })))));
        assert!(req(&["approve", "su1", "--role", "root"]).is_err());
        assert!(req(&["approve", "su1", "--ttl", "soon"]).is_err());
        assert!(req(&["list", "maybe"]).is_err());

        let res = json!({
            "user": { "id": "u1", "email": "ada@example.com", "role": "member" },
            "code": "sbc_x", "expiresAt": now_ms() + 3 * 24 * 3_600_000,
            "sso": [{ "id": "work", "label": "Work", "type": "entra" }],
        });
        let out = approved(&res);
        assert!(out.contains("sbc_x") && out.contains("about 72 hours") && out.contains("botctl user link ada@example.com work <subject>"), "{out}");
        assert!(!approved(&json!({ "sso": [] })).contains("user link"));
    }

    #[test]
    fn saml_summary_shows_what_to_enter_at_the_idp() {
        let mut v = json!({
            "provider": "corp", "label": "Corp", "problem": null, "spEntityId": "https://bots.example/api/auth/sso/corp/metadata",
            "acsUrl": "https://bots.example/api/auth/sso/corp/acs", "metadataUrl": "https://bots.example/api/auth/sso/corp/metadata",
            "idpEntityId": "https://idp.example/saml", "source": "botctl", "from": null, "idp": null,
        });
        let out = saml_summary(&v);
        assert!(out.contains("ACS URL (reply URL):      https://bots.example/api/auth/sso/corp/acs"), "{out}");
        assert!(out.contains("from botctl: not loaded yet."), "{out}");
        assert!(out.contains("Signs AuthnRequests:      no") && out.contains("Single logout:            no ("), "{out}");
        assert!(out.contains("IdP-initiated sign-in:    refused (start from SuperBot)\n"), "{out}");
        v["idpInitiated"] = json!("restart");
        assert!(saml_summary(&v).contains("IdP-initiated sign-in:    restarted as SP-initiated\n"));
        v["idp"] = json!({ "ssoUrl": "https://idp.example/sso", "sloUrl": "https://idp.example/slo", "certificates": [{ "sha256": "ab:cd", "subject": "CN=idp", "notAfter": 1_900_000_000_000_i64 }] });
        v["sloUrl"] = json!("https://bots.example/api/auth/sso/corp/slo");
        v["signRequests"] = json!(true);
        v["singleLogout"] = json!(true);
        v["spKey"] = json!({ "from": "generated", "certificate": { "sha256": "12:34", "subject": "CN=sp", "notAfter": 1_900_000_000_000_i64 } });
        let out = saml_summary(&v);
        assert!(out.contains("Certificate SHA-256 ab:cd (CN=idp), expires 2030-03-17"), "{out}");
        assert!(out.contains("SLO URL (logout URL):     https://bots.example/api/auth/sso/corp/slo") && out.contains("    Logout URL:  https://idp.example/slo"), "{out}");
        assert!(out.contains("SP signing certificate:   SHA-256 12:34 (generated), expires 2030-03-17"), "{out}");
        assert!(out.contains("Signs AuthnRequests:      yes") && out.contains("Single logout:            yes\n"), "{out}");
        assert!(out.contains("Encrypted assertions:     off") && !out.contains("SP encryption"), "{out}");
        v["encryptedAssertions"] = json!("require");
        v["spEncryptionKey"] = json!({ "from": "secret", "certificate": { "sha256": "56:78", "subject": "CN=enc", "notAfter": 1_900_000_000_000_i64 } });
        let out = saml_summary(&v);
        assert!(out.contains("SP encryption certificate: SHA-256 56:78 (secret), expires 2030-03-17") && out.contains("Encrypted assertions:     required"), "{out}");
        v["spEncryptionKey"] = json!({ "problem": "not offered until SSO_CORP_ENCRYPTION_PRIVATE_KEY is set" });
        assert!(saml_summary(&v).contains("SP encryption key:        not offered until SSO_CORP_ENCRYPTION_PRIVATE_KEY"));
        assert!(saml_summary(&v).contains("IdP metadata signature:   not checked\n"));
        v["signedMetadata"] = json!("require");
        v["metadataSigningCertificates"] = json!([{ "sha256": "9a:bc", "subject": "CN=metadata", "notAfter": 1_900_000_000_000_i64 }]);
        let out = saml_summary(&v);
        assert!(out.contains("IdP metadata signature:   required\n    Trusted signer: SHA-256 9a:bc (CN=metadata), expires 2030-03-17"), "{out}");
        assert!(!out.contains("Groups attribute"), "{out}");
        v["groupsAttribute"] = json!("groups");
        v["requiredGroups"] = json!([]);
        v["roleMappings"] = json!(0);
        assert!(saml_summary(&v).contains("Groups attribute:         groups\n  Required groups:          none (anyone the IdP signs in)\n  Group role mappings:      0 (botctl sso role-mappings)\n"));
        v["requiredGroups"] = json!(["SuperBot Users", "Admins"]);
        v["roleMappings"] = json!(2);
        let out = saml_summary(&v);
        assert!(out.contains("Required groups:          SuperBot Users, Admins\n  Group role mappings:      2 "), "{out}");
    }

    #[test]
    fn saml_summary_shows_the_authentication_context_required() {
        let mut v = json!({ "provider": "corp", "label": "Corp", "idp": null, "authnContext": null });
        assert!(saml_summary(&v).contains("  Authentication context:   not checked (the IdP's MFA isn't required)\n"));
        v["authnContext"] = json!({ "required": ["http://schemas.microsoft.com/claims/multipleauthn"], "methodsAttribute": null, "requested": true });
        let out = saml_summary(&v);
        assert!(out.contains("  Authentication context:   one of http://schemas.microsoft.com/claims/multipleauthn\n    Requested in AuthnRequests (exact)\n"), "{out}");
        assert!(!out.contains("Also read from"), "{out}");
        v["authnContext"] = json!({ "required": ["mfa", "urn:okta:loa:2fa:any"], "methodsAttribute": "amr", "requested": false });
        let out = saml_summary(&v);
        assert!(out.contains("  Authentication context:   one of mfa, urn:okta:loa:2fa:any\n    Also read from attribute amr\n    Not requested: the IdP's own policy decides\n"), "{out}");
    }

    #[test]
    fn saml_summary_shows_a_key_rollover_and_botctl_drives_it() {
        let cert = |sha: &str| json!({ "sha256": sha, "subject": "CN=sp", "notAfter": 1_900_000_000_000_i64 });
        let mut v = json!({ "provider": "corp", "label": "Corp", "idp": null, "encryptedAssertions": "allow" });
        v["spKey"] = json!({ "from": "generated", "certificate": cert("12:34"), "next": { "certificate": cert("ab:01") } });
        v["spEncryptionKey"] = json!({
            "from": "generated", "certificate": cert("56:78"), "lastUsedSecondsAgo": 7200,
            "next": null, "previous": { "certificate": cert("cd:02"), "lastUsedSecondsAgo": null },
        });
        let out = saml_summary(&v);
        assert!(out.contains("SP signing certificate:   SHA-256 12:34 (generated), expires 2030-03-17\n    Next: SHA-256 ab:01, expires 2030-03-17: published, not yet in use\n"), "{out}");
        assert!(out.contains("SP encryption certificate: SHA-256 56:78 (generated), expires 2030-03-17\n    In use; last decrypted a sign-in 2h ago\n"), "{out}");
        assert!(out.contains("    Previous: SHA-256 cd:02: no longer published, still decrypts until retired; no sign-in decrypted with it since botd started\n"), "{out}");
        v["spKey"] = json!({ "from": "secret", "certificate": cert("12:34") });
        assert!(!saml_summary(&v).contains("    Next:"), "a configured key has no rollover here");

        assert_eq!(saml_key_request("corp", "next", "signing"), Ok(("POST", "/api/sso/corp/saml/keys/signing/next".into())));
        assert_eq!(saml_key_request("corp", "promote", "encryption"), Ok(("POST", "/api/sso/corp/saml/keys/encryption/promote".into())));
        assert_eq!(saml_key_request("corp", "cancel", "signing"), Ok(("DELETE", "/api/sso/corp/saml/keys/signing/next".into())));
        assert_eq!(saml_key_request("a b", "retire", "encryption"), Ok(("DELETE", "/api/sso/a%20b/saml/keys/encryption/previous".into())));
        assert!(saml_key_request("corp", "rotate", "signing").is_err());
        assert!(saml_key_request("corp", "next", "both").is_err());
        assert_eq!((ago(59), ago(60), ago(7200), ago(200_000)), ("59s".into(), "1m".into(), "2h".into(), "2d".into()));
    }

    #[test]
    fn sso_role_commands() {
        let req = |a: &[&str]| sso_role_request(a).map(|(m, p, b)| (m, p, b.map(|b| serde_json::from_str::<Value>(&b).unwrap())));
        assert_eq!(req(&["role-mappings"]), Ok(("GET", "/api/sso/role-mappings".into(), None)));
        assert_eq!(req(&["role", "list"]), Ok(("GET", "/api/sso/role-mappings".into(), None)));
        assert_eq!(
            req(&["role", "map", "corp", "SuperBot Auditors", "Auditor"]),
            Ok(("POST", "/api/sso/role-mappings".into(), Some(json!({ "provider": "corp", "group": "SuperBot Auditors", "role": "Auditor" }))))
        );
        assert_eq!(req(&["role", "show", "gm 1"]), Ok(("GET", "/api/sso/role-mappings/gm%201".into(), None)));
        assert_eq!(req(&["role", "unmap", "gm1"]), Ok(("DELETE", "/api/sso/role-mappings/gm1".into(), None)));
        assert!(req(&["role", "map", "corp", "Auditors"]).is_err());
        assert!(req(&["role", "map", "corp", "Auditors", "Auditor", "--org"]).is_err());
        assert!(req(&["role", "unmap"]).is_err());
        assert!(req(&[]).unwrap_err().contains("sso saml <provider>"));
    }

    #[test]
    fn service_account_commands() {
        let req = |a: &[&str]| service_account_request(a).map(|(m, p, b)| (m, p, b.map(|b| serde_json::from_str::<Value>(&b).unwrap())));
        let sa = "/api/service-accounts";
        assert_eq!(req(&[]), Ok(("GET", sa.into(), None)));
        assert_eq!(req(&["show", "sa1"]), Ok(("GET", format!("{sa}/sa1"), None)));
        assert_eq!(req(&["add", "CI"]), Ok(("POST", sa.into(), Some(json!({ "name": "CI", "role": null, "team": null, "description": null })))));
        assert_eq!(
            req(&["add", "HR sync", "--role", "Help desk", "--team", "t1", "--description", "From HR"]),
            Ok(("POST", sa.into(), Some(json!({ "name": "HR sync", "role": "Help desk", "team": "t1", "description": "From HR" }))))
        );
        assert_eq!(req(&["edit", "sa1", "--team", "none", "--owner", "ada@example.com"]), Ok(("PATCH", format!("{sa}/sa1"), Some(json!({ "team": null, "owner": "ada@example.com" })))));
        assert_eq!(req(&["edit", "sa1", "--name", "CD", "--role", "member"]), Ok(("PATCH", format!("{sa}/sa1"), Some(json!({ "name": "CD", "role": "member" })))));
        assert_eq!(req(&["disable", "sa1"]), Ok(("PATCH", format!("{sa}/sa1"), Some(json!({ "status": "disabled" })))));
        assert_eq!(req(&["enable", "sa1"]), Ok(("PATCH", format!("{sa}/sa1"), Some(json!({ "status": "active" })))));
        assert_eq!(req(&["rm", "sa1"]), Ok(("DELETE", format!("{sa}/sa1"), None)));
        assert_eq!(req(&["token", "list", "sa1"]), Ok(("GET", format!("{sa}/sa1/tokens"), None)));
        assert_eq!(req(&["token", "add", "sa1"]), Ok(("POST", format!("{sa}/sa1/tokens"), Some(json!({ "name": null, "scopes": null, "expiresInDays": null })))));
        assert_eq!(
            req(&["token", "add", "sa1", "--name", "deploy", "--scopes", "read, write", "--days", "30"]),
            Ok(("POST", format!("{sa}/sa1/tokens"), Some(json!({ "name": "deploy", "scopes": ["read", "write"], "expiresInDays": 30 }))))
        );
        assert_eq!(
            req(&["token", "rotate", "sa1", "st1", "--keep-old", "60"]),
            Ok(("POST", format!("{sa}/sa1/tokens/st1/rotate"), Some(json!({ "expiresInDays": null, "keepOldMinutes": 60 }))))
        );
        assert_eq!(req(&["token", "revoke", "sa1", "st1"]), Ok(("DELETE", format!("{sa}/sa1/tokens/st1"), None)));
        for bad in [
            &["add"][..],
            &["add", "--role", "member"],
            &["add", "X", "--scopes", "read"],
            &["edit", "sa1"],
            &["token", "add", "sa1", "--days", "ninety"],
            &["token", "add", "sa1", "--days"],
            &["token", "rotate", "sa1"],
            &["token", "revoke", "sa1"],
            &["disable"],
        ] {
            assert!(req(bad).is_err(), "{bad:?}");
        }

        let made = json!({
            "token": "sbsa_secret", "serviceAccount": { "id": "sa1", "name": "CI" },
            "tokenInfo": { "id": "st1", "scopes": ["read"], "expiresAt": now_ms() + 30 * 86_400_000 },
        });
        let out = service_token_created(&made);
        assert!(out.contains("Token st1 for service account CI (sa1), with read, for 30 days.\n\nsbsa_secret\n\nIt is shown only once."), "{out}");
        let rotated = json!({ "token": "sbsa_new", "serviceAccount": made["serviceAccount"], "tokenInfo": { "id": "st2", "expiresAt": now_ms() + 86_400_000 }, "replaced": { "id": "st1", "endsAt": now_ms() + 30 * 60_000 + 30_000 } });
        let out = service_token_created(&rotated);
        assert!(out.contains("with all the account holds, for 1 days") && out.contains("The old token st1 keeps working for about 30 more minutes."), "{out}");
        let now = json!({ "replaced": { "id": "st1", "endsAt": now_ms() } });
        assert!(service_token_created(&now).ends_with("The old token st1 stopped working."));
    }

    #[test]
    fn role_commands() {
        let req = |a: &[&str]| role_request(a).map(|(m, p, b)| (m, p, b.map(|b| serde_json::from_str::<Value>(&b).unwrap())));
        assert_eq!(req(&[]), Ok(("GET", "/api/roles".into(), None)));
        assert_eq!(req(&["show", "Help desk"]), Ok(("GET", "/api/roles/Help%20desk".into(), None)));
        assert_eq!(
            req(&["add", "Auditor"]),
            Ok(("POST", "/api/roles".into(), Some(json!({ "name": "Auditor", "base": null, "description": null, "permissions": [] }))))
        );
        assert_eq!(
            req(&["add", "Auditor", "--base", "readonly", "--perms", "audit.view, signups.approve", "--description", "Reviews"]),
            Ok(("POST", "/api/roles".into(), Some(json!({ "name": "Auditor", "base": "readonly", "description": "Reviews", "permissions": ["audit.view", "signups.approve"] }))))
        );
        assert_eq!(req(&["edit", "r1", "--perms", "none"]), Ok(("PATCH", "/api/roles/r1".into(), Some(json!({ "permissions": [] })))));
        assert_eq!(
            req(&["edit", "r1", "--name", "Support", "--base", "member", "--description", ""]),
            Ok(("PATCH", "/api/roles/r1".into(), Some(json!({ "name": "Support", "base": "member", "description": "" }))))
        );
        assert_eq!(req(&["rm", "r1"]), Ok(("DELETE", "/api/roles/r1".into(), None)));
        assert_eq!(req(&["assign", "r1", "ada@example.com"]), Ok(("PUT", "/api/roles/r1/users/ada%40example.com".into(), None)));
        assert_eq!(req(&["assign", "r1", "u1", "--team", "t1"]), Ok(("PUT", "/api/roles/r1/teams/t1/users/u1".into(), None)));
        assert_eq!(req(&["unassign", "r1", "u1"]), Ok(("DELETE", "/api/roles/r1/users/u1".into(), None)));
        assert_eq!(req(&["unassign", "r1", "u1", "--team", "t1"]), Ok(("DELETE", "/api/roles/r1/teams/t1/users/u1".into(), None)));
        for bad in [&["add"][..], &["add", "--base", "member"], &["add", "X", "--perm", "audit.view"], &["add", "X", "--base"], &["edit", "r1"], &["assign", "r1"], &["assign", "r1", "u1", "--org", "x"], &["show"]] {
            assert!(req(bad).is_err(), "{bad:?}");
        }

        let org = json!({ "user": { "email": "ada@example.com", "role": "readonly" }, "role": { "name": "Auditor" } });
        assert_eq!(role_assigned("assign", &org), "ada@example.com has Auditor now; their role is readonly.");
        assert_eq!(role_assigned("unassign", &org), "Taken away. ada@example.com keeps readonly as their role.");
        let team = json!({ "team": { "name": "Ops" }, "user": { "email": "ada@example.com" }, "role": { "name": "Lead" }, "applies": ["users.manage"] });
        assert_eq!(role_assigned("assign", &team), "ada@example.com has Lead in Ops. There it gives: users.manage.");
        assert!(role_assigned("assign", &json!({ "team": { "name": "Ops" }, "user": {}, "role": {}, "applies": [] })).contains("no team permissions"));
        assert_eq!(role_assigned("unassign", &team), "Taken away from ada@example.com in Ops.");
    }

    #[test]
    fn scim_commands() {
        let req = |a: &[&str]| scim_request(a).map(|(m, p, b)| (m, p, b.map(|b| serde_json::from_str::<Value>(&b).unwrap())));
        assert_eq!(req(&["tokens"]), Ok(("GET", "/api/scim/tokens".into(), None)));
        assert_eq!(req(&["token", "create", "okta"]), Ok(("POST", "/api/scim/tokens".into(), Some(json!({ "tenant": "okta", "sso": null, "label": null })))));
        assert_eq!(
            req(&["token", "create", "entra", "--sso", "work", "--label", "Entra prod"]),
            Ok(("POST", "/api/scim/tokens".into(), Some(json!({ "tenant": "entra", "sso": "work", "label": "Entra prod" }))))
        );
        assert_eq!(req(&["token", "revoke", "st1"]), Ok(("DELETE", "/api/scim/tokens/st1".into(), None)));
        assert!(req(&["token", "create"]).is_err());
        assert!(req(&["token", "create", "--sso", "work"]).is_err());
        assert!(req(&["token", "revoke"]).is_err());
        assert_eq!(req(&["groups"]), Ok(("GET", "/api/scim/groups".into(), None)));
        assert_eq!(req(&["group", "link", "okta", "t1"]), Ok(("POST", "/api/scim/groups".into(), Some(json!({ "tenant": "okta", "team": "t1", "externalId": null, "displayName": null })))));
        assert_eq!(
            req(&["group", "link", "entra", "t1", "--external-id", "8aa1", "--name", "Platform Team"]),
            Ok(("POST", "/api/scim/groups".into(), Some(json!({ "tenant": "entra", "team": "t1", "externalId": "8aa1", "displayName": "Platform Team" }))))
        );
        assert_eq!(req(&["group", "unlink", "t 1"]), Ok(("DELETE", "/api/scim/groups/t%201".into(), None)));
        assert!(req(&["group", "link", "okta"]).is_err());
        assert!(req(&["group", "link", "okta", "--name", "x"]).is_err());
        assert!(req(&["group", "unlink"]).is_err());
        assert_eq!(req(&["role-mappings"]), Ok(("GET", "/api/scim/role-mappings".into(), None)));
        assert_eq!(req(&["role", "list"]), Ok(("GET", "/api/scim/role-mappings".into(), None)));
        assert_eq!(req(&["role", "map", "t1", "Support Lead"]), Ok(("POST", "/api/scim/role-mappings".into(), Some(json!({ "team": "t1", "role": "Support Lead", "scope": "team" })))));
        assert_eq!(req(&["role", "map", "t1", "auditor", "--org"]), Ok(("POST", "/api/scim/role-mappings".into(), Some(json!({ "team": "t1", "role": "auditor", "scope": "org" })))));
        assert_eq!(req(&["role", "show", "sm 1"]), Ok(("GET", "/api/scim/role-mappings/sm%201".into(), None)));
        assert_eq!(req(&["role", "unmap", "sm1"]), Ok(("DELETE", "/api/scim/role-mappings/sm1".into(), None)));
        assert_eq!(req(&["role-groups"]), Ok(("GET", "/api/scim/role-groups".into(), None)));
        assert_eq!(req(&["role-group", "list"]), Ok(("GET", "/api/scim/role-groups".into(), None)));
        assert_eq!(
            req(&["role-group", "add", "entra", "SuperBot Auditors", "Auditor"]),
            Ok(("POST", "/api/scim/role-groups".into(), Some(json!({ "tenant": "entra", "displayName": "SuperBot Auditors", "role": "Auditor", "externalId": null }))))
        );
        assert_eq!(
            req(&["role-group", "add", "entra", "Auditors", "Auditor", "--external-id", "8aa1"]),
            Ok(("POST", "/api/scim/role-groups".into(), Some(json!({ "tenant": "entra", "displayName": "Auditors", "role": "Auditor", "externalId": "8aa1" }))))
        );
        assert_eq!(req(&["role-group", "show", "g 1"]), Ok(("GET", "/api/scim/role-groups/g%201".into(), None)));
        assert_eq!(req(&["role-group", "set-role", "g1", "Billing"]), Ok(("PATCH", "/api/scim/role-groups/g1".into(), Some(json!({ "role": "Billing" })))));
        assert_eq!(req(&["role-group", "remove", "g1"]), Ok(("DELETE", "/api/scim/role-groups/g1".into(), None)));
        assert!(req(&["role-group", "add", "entra", "Auditors"]).is_err());
        assert!(req(&["role-group", "add", "entra", "--external-id", "8aa1", "Auditor"]).is_err());
        assert!(req(&["role-group", "add", "entra", "Auditors", "Auditor", "--org"]).is_err());
        assert!(req(&["role-group", "set-role", "g1"]).is_err());
        assert_eq!(req(&["google"]), Ok(("GET", "/api/scim/google".into(), None)));
        assert_eq!(req(&["google", "status"]), Ok(("GET", "/api/scim/google".into(), None)));
        assert_eq!(req(&["google", "sync"]), Ok(("POST", "/api/scim/google/sync".into(), Some(json!({})))));
        assert_eq!(req(&["google", "sync", "--force"]), Ok(("POST", "/api/scim/google/sync".into(), Some(json!({ "force": true })))));
        assert!(req(&["google", "sync", "--hard"]).is_err());
        assert!(req(&["role", "map", "t1"]).is_err());
        assert!(req(&["role", "map", "--org", "t1"]).is_err());
        assert!(req(&["role", "map", "t1", "auditor", "--team"]).is_err());
        assert!(req(&["role", "unmap"]).is_err());

        let res = json!({ "token": "sbp_x", "enabled": false, "scimToken": { "id": "st1", "tenant": "entra", "ssoProvider": "work" } });
        let out = scim_created(&res);
        assert!(out.contains("sbp_x") && out.contains("shown only once") && out.contains("/scim/v2") && out.contains("objectId") && out.contains("SCIM=on"), "{out}");
        let on = scim_created(&json!({ "token": "sbp_y", "enabled": true, "scimToken": { "id": "st2", "tenant": "okta" } }));
        assert!(!on.contains("SCIM=on") && !on.contains("objectId"), "{on}");
    }

    #[test]
    fn hook_cwd_overrides_where_the_harness_says_it_runs() {
        let event = r#"{"tool_name":"terminal","tool_input":{"command":"ls"},"cwd":"/opt/hermes"}"#;
        let body: Value = serde_json::from_str(&hook_body("hermes", "b1", None, event, Some("/workspace")).unwrap()).unwrap();
        assert_eq!(body["event"]["cwd"], "/workspace");
        assert_eq!(body["event"]["tool_name"], "terminal");
        assert_eq!(body["from"], "b1");
        let body: Value = serde_json::from_str(&hook_body("claude", "b1", None, event, None).unwrap()).unwrap();
        assert_eq!(body["event"]["cwd"], "/opt/hermes");
        assert!(hook_body("hermes", "b1", None, event, Some("workspace")).is_err());
        assert!(hook_body("hermes", "b1", None, "[1]", Some("/workspace")).is_err());
        assert!(hook_body("hermes", "b1", None, "not json", None).is_err());
        // The run the hook is part of goes with it, so run approvals count only there.
        let body: Value = serde_json::from_str(&hook_body("claude", "b1", Some("r1"), event, None).unwrap()).unwrap();
        assert_eq!((body["run"].as_str(), body["from"].as_str()), (Some("r1"), Some("b1")));
        assert!(serde_json::from_str::<Value>(&hook_body("claude", "b1", Some(""), event, None).unwrap()).unwrap()["run"].is_null());
    }

    #[test]
    fn approve_for_the_run_or_remember() {
        assert_eq!(decide_body(&[]).unwrap(), json!({ "remember": null, "scope": "once" }));
        assert_eq!(decide_body(&["--run"]).unwrap(), json!({ "remember": null, "scope": "run" }));
        assert_eq!(decide_body(&["--remember"]).unwrap(), json!({ "remember": "bot", "scope": "once" }));
        assert!(decide_body(&["--run", "--remember-global"]).is_err());
    }

    #[test]
    fn policy_set_builds_a_patch() {
        let p = policy_patch(&["mode=ask", "timeout=15", "git_push=deny"]).unwrap();
        assert_eq!(p, json!({ "mode": "ask", "timeoutMinutes": 15, "classes": { "git_push": "deny" } }));
        assert!(policy_patch(&[]).is_err());
        assert!(policy_patch(&["timeout=soon"]).is_err());
        let p = policy_patch(&["mode=inherit", "timeout=inherit", "git_push=inherit"]).unwrap();
        assert_eq!(p, json!({ "mode": null, "timeoutMinutes": null, "classes": { "git_push": null } }));
        assert_eq!(policy_patch(&["sandbox=on"]).unwrap(), json!({ "sandbox": true }));
        assert_eq!(policy_patch(&["sandbox=off", "mode=bypass"]).unwrap(), json!({ "sandbox": false, "mode": "bypass" }));
        assert_eq!(policy_patch(&["sandbox=inherit"]).unwrap(), json!({ "sandbox": null }));
        assert!(policy_patch(&["sandbox=yes"]).is_err());
    }

    #[test]
    fn only_a_proxy_on_this_machine_gets_the_bot_token() {
        let p = parse_proxy("http://user:p%40ss%3Aw@localhost:3128").unwrap();
        assert_eq!((p.addr.as_str(), p.auth.as_deref()), ("localhost:3128", Some("user:p@ss:w")));
        let p = parse_proxy("http://127.0.0.1:41000/").unwrap();
        assert_eq!((p.addr.as_str(), p.auth), ("127.0.0.1:41000", None));
        for bad in ["http://proxy.example:3128", "https://localhost:3128", "http://localhost:3128/x", "socks5://localhost:1080", "http://", "http://u:p@10.0.0.1:3128"] {
            assert!(parse_proxy(bad).is_none(), "{bad}");
        }
        assert_eq!(unescape("a%2"), "a%2");
    }

    #[test]
    fn a_bot_run_reaches_botd_through_its_sandboxs_proxy() {
        use std::net::TcpListener;
        let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
        let at = proxy.local_addr().unwrap();
        let seen = std::thread::spawn(move || {
            let (mut c, _) = proxy.accept().unwrap();
            let mut buf = [0u8; 4096];
            let n = c.read(&mut buf).unwrap();
            c.write_all(b"HTTP/1.0 200 OK\r\n\r\n{\"ok\":true}").unwrap();
            String::from_utf8_lossy(&buf[..n]).into_owned()
        });
        // Nothing listens on BOT_API itself, as in a sandbox's own network.
        let closed = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        let _env = ENV.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: tests that set these variables hold ENV.
        unsafe {
            std::env::set_var("BOT_API", format!("http://{closed}"));
            std::env::set_var("BOT_TOKEN", "tok");
            std::env::set_var("HTTP_PROXY", format!("http://sb:s%3Acret@{at}"));
        }
        let body = api(Cred::Bot, "GET", "/api/bot/routines", None).unwrap();
        assert_eq!(body, r#"{"ok":true}"#);
        let req = seen.join().unwrap();
        assert!(req.starts_with(&format!("GET http://{closed}/api/bot/routines HTTP/1.0\r\n")), "{req}");
        assert!(req.contains(&format!("Proxy-Authorization: Basic {}\r\n", base64(b"sb:s:cret"))), "{req}");
        assert!(req.contains("Authorization: Bearer tok\r\n"));
        // An operator's credentials never take a proxy.
        unsafe { std::env::set_var("SUPERBOT_TOKEN", "op") };
        assert!(api(Cred::Operator, "GET", "/api/policy", None).is_err());
        unsafe {
            for k in ["BOT_API", "BOT_TOKEN", "HTTP_PROXY", "SUPERBOT_TOKEN"] {
                std::env::remove_var(k);
            }
        }
    }

    #[test]
    fn values_come_from_stdin_without_the_newline() {
        assert_eq!(stdin_value("sk-1\n".as_bytes()).unwrap(), "sk-1");
        assert_eq!(stdin_value("sk-1\r\n".as_bytes()).unwrap(), "sk-1");
        assert_eq!(stdin_value("a b\n\n".as_bytes()).unwrap(), "a b\n");
        assert!(stdin_value("\n".as_bytes()).is_err());
        assert!(env_name("OPENAI_API_KEY").is_ok());
        for bad in ["", "lower", "A/B", "../X", "A B"] {
            assert!(env_name(bad).is_err(), "{bad}");
        }
    }
}
