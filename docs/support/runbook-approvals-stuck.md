# Runbook: approval queue stuck

Bots stop and wait on approvals that nobody sees, that pile up faster than people answer, or that seem not to resolve. Severity: [2](severity.md#severities) when Bots across a team wait and nobody is told, 3 for one Bot or person. How approvals work: [ADR 0007](../adr/0007-approvals.md) and the [backend guide](../backend.md#approvals).

What "stuck" can't be: an approval waits at most the policy's timeout (`timeoutMinutes`, 10 by default, at most 4 for Hermes Agent Bots), then it's denied. Stopping the Bot, its run ending, or a server restart also closes it. Approvals fail closed: nothing runs because an approval was lost. So "stuck" is one of the cases below, and the fix is rarely in the queue itself.

## First five minutes

1. **What they see.** A Bot that says it's waiting for approval; an approval in the app that won't go away; or Bots that keep getting denied.
2. **The queue**, as an admin on the server:

   ```sh
   botctl approvals pending
   botctl audit 50 --action 'approval.*'
   botctl policy                       # mode, timeout, classes; botctl policy <bot> for one Bot
   ```

   A support bundle has `health.json` → `approvals` (`pending`, `oldestPendingSeconds`, `timeoutMinutes`, `mode`), and metrics show `superbot_approvals_pending` and `superbot_approvals_oldest_pending_age_seconds` ([metrics](../../deploy/README.md#metrics-and-logs)).
3. **Compare the oldest age with the timeout.** Older than the timeout is a bug (escalate, below); younger is normal waiting.

## Cases

| What you see | Usually | Do |
|---|---|---|
| Approvals pending, nobody knew | Nobody had the app open, and notifications are off or failing | Decide them now (`botctl approve <id>`, `botctl deny <id>`, or the app). Turn notifications on ([approval notifications](../../deploy/README.md#approval-notifications), [ADR 0061](../adr/0061-approval-notifications.md)); check `botctl audit --action 'notification.*'` for `notification.failed` and its reason (SMTP, webhook) |
| People are notified, but too often to keep up | The policy asks about routine work | Allow what's routine with rules (`botctl rule add allow "<pattern>" --bot <bot>`), "remember" on an approval, or "approve for this run". Keep `deny` for what must never run |
| Every call denied at once, nothing reaches the queue | A `deny` rule or class, or a command too unusual to read (always denied) | `botctl rules <bot>`; the audit log's `policy.*` and `approval.denied` events say which rule or why. The Bot is told why, too |
| Runs blocked with "SuperBot's approval gate failed" or "is misconfigured" | The harness's hook can't reach botd, got a bad answer, or was set up wrong (fail closed) | Check the run can reach `BOT_API`, the harness's hook settings, and `deploy/harness-e2e.sh` for that harness ([checking approvals](../../deploy/README.md#checking-approvals-through-the-harnesses)) |
| Approved, but the Bot still waits or says denied | The decision came after the timeout or after the run ended; or a harness's own hook timeout is shorter than botd's wait | The audit log shows the order (`approval.expired` before `approval.approved`). Ask the owner to send the task again; lower `timeoutMinutes` if a harness gives up first |
| Pending approvals vanish after a restart | Expected: a restart closes them | Send the tasks again. Plan restarts for quiet times |
| Approvals appear for one person only | Only admins and members decide; read-only users and other people's Bots they can't see aren't shown | `botctl bot access <bot>`: give an operator grant, or share the Bot |

## Escalate when

- An approval is pending for longer than its timeout, or the queue doesn't empty after the runs are stopped.
- A Bot runs a call in a risky class without an approval when the policy says ask: that's a [Severity 1 security incident](escalation.md#security-incidents).
- Notifications fail and the reason isn't the customer's SMTP server or webhook.

## Afterwards

If people were not told, check notifications are on before closing. If the queue was noisy, review the policy with the customer at the next check-in ([success cadence](onboarding.md#success-cadence)).
