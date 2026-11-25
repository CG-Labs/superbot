# Runbook: running a Severity 1

The service is down or unusable for most of a customer's people, data is lost or exposed, or a security incident is suspected: [Severity 1](severity.md#severities). This runbook is for the incident commander ([escalation](escalation.md#inside-the-provider)): owning the status page, the updates and the ticket, and handing the fixing to others. The runbook for the cause ([machine down](runbook-machine-down.md), [sign-in](runbook-sign-in.md), [harness outage](runbook-harness-outage.md), [upgrades](runbook-upgrade.md), [server restore](runbook-server-restore.md) and the rest in the [index](README.md#the-playbooks)) is for whoever fixes it.

The commands run on the server as an admin (`SUPERBOT_TOKEN` from `botctl login`); the console's Status tab does the same. Posting and updating in full: [incidents and their reviews](incident-review.md).

## First five minutes

1. **Write down when it was detected**, in UTC: the page alert, the probe, or the first customer report. The review measures from it.
2. **Name the incident commander** in `<incident-channel>`: the on-call engineer until they hand over. Page whoever the cause needs (`<on-call-pager>`).
3. **Post it on the status page within 15 minutes** of confirming it, naming the components it affects, in words the public can read:

   ```sh
   botctl incident open "Bot runs fail" "Runs are failing for many customers. We're investigating." \
     --impact critical --component runners
   ```

   `--impact critical` for an outage, `major` for a partial one ([posting](incident-review.md#posting-and-updating)). Keep the id it prints.
4. **Answer the customers' tickets** with the status page link and when the next update comes. Security incidents follow [their own route](escalation.md#security-incidents) first: post on the status page only what the security lead agrees.
5. **Get the facts started**: a [support bundle](support-bundle.md) (`botctl support-bundle`), or the [offline one](support-check.md) (`botd support bundle`) if botd is down.

## Every hour until it's fixed

- **Update the status page**, even with no news: what's known, what's being done, when the next update comes ([update targets](severity.md#updates-until-its-fixed)).

  ```sh
  botctl incident update <id> identified "We've found the cause and are rolling back a configuration change."
  ```

- Update the tickets the same way, and the customer's TAM for Enterprise customers ([TAM](tam.md)). `botctl support-escalations --updates <replies.csv>` on the open tickets names each one whose update is overdue or nearly so, and each Severity 1 past 2 hours ([escalation check](escalation-check.md)).
- Change the impact as it changes: `botctl incident edit <id> --impact major`.
- Keep a rough timeline in the channel: what was tried, decided and handed to whom, with times. The review needs it.

## When it's fixed

1. **Move to monitoring** once the fix is in, and watch the status page's own components and the tickets: `botctl incident update <id> monitoring "<text>"`.
2. **Resolve** when it's held (an hour is usual): `botctl incident resolve <id> "<text>"`. botd prints the command for the review.
3. **Tell the customers** on their tickets, and lower or close them as [severity](severity.md#updates-until-its-fixed) says.

## Escalate when

- 2 hours pass without a workaround: management (`<support-manager>`, then `<engineering-manager>`), as [timed escalation](escalation.md#timed-escalation) says.
- Data is lost or exposed, or it's a security incident: management and `<security-email>` at once.
- The fix needs a code change, a data repair or a decision outside the runbooks: the component's engineering owner (`<engineering-escalation>`).
- The commander can't keep up the hourly updates: hand over, by name, in the channel, and say so on the ticket.

## Afterwards

Within 5 business days, the review ([after a Severity 1](escalation.md#after-a-severity-1)):

```sh
botctl incident review <id> --detected <when it was detected> -o review-<id>.md
```

The draft has the status page timeline, botd's starts and configuration changes around it, what failed while it lasted against the time before, and whether the 15-minute first post and the hourly updates were kept. Fill in the rest as [finishing the review](incident-review.md#finishing-the-review) says, link it from the incident's last update, share it with affected Enterprise customers, and change any runbook it shows was wrong or missing, this one included.
