# Privacy policy (template)

> **Template. Draft for legal review. Not legal advice.** A starting point for the provider of a managed SuperBot service, written from what the code on `main` does. It has not been reviewed by a lawyer and does not make anyone GDPR compliant or certified. Fill in every `[bracketed]` placeholder, delete what doesn't apply, and have counsel review it before publishing. Part of the [security pack](README.md).

**How to use it.** The policy covers personal data the provider controls. Content a business customer's users and Bots handle is processed for that customer under the [DPA](dpa-template.md), and the customer's own privacy notice covers it; for individual customers, the provider is the controller of their content too, and Section 3 says so. Notes in *italics* say what in SuperBot backs a statement; delete them before publishing. Retention periods depend on how the provider sets SuperBot ([data flows: retention](data-flows.md#retention)); state the values actually used.

---

**Last updated: [date]**

## 1. Who we are

[Company legal name] ("**we**", "**us**") provides [service name], a managed service built on SuperBot (the "**Service**"). We are registered at [Registered address] under company number [Company registration number].

Contact for privacy questions and requests: [Contact email]. [Our data protection officer is [name or role], at [contact].] [Our representative in the [EU / UK] is [name, address].]

## 2. What this policy covers

This policy explains how we use personal data about people who visit our website, ask for access, hold an account, or pay for the Service.

If you use the Service through an organisation (your employer, for example), that organisation decides how your content in the Service is used and is its controller; we process it on the organisation's behalf under our data processing agreement with them. Ask the organisation about that data. This policy still covers what we use for our own purposes: your account, billing, security and support.

## 3. What we collect and why

| Data | When | Why | Legal basis | How long |
|------|------|-----|-------------|----------|
| Name, work email, company, team size, use case, preferred sign-in, your consent, IP address and browser user agent | You ask for access on our signup form | To review your request and contact you about it, and to stop abuse | [Steps before a contract / legitimate interests / consent: legal review] | [period] *(SuperBot keeps access requests until deleted and has no setting to expire them yet: [self-hosting guide](gdpr-self-hosting.md#what-exists-and-what-is-missing). The provider must delete them by hand.)* |
| Name, email, role, team, sign-in identity from your identity provider, whether you use a second factor, sign-in times | You hold an account | To give you the Service and keep it secure | Contract | While you hold an account, then [period] *(an erased account keeps no name or email: [ADR 0102](../adr/0102-erasing-a-users-data.md))* |
| Your Bots, messages, routines, files, Bot memory and facts about you, and harness logins you make on your computer | You use the Service as an individual customer | To provide the Service you asked for, including sending prompts and files to the AI model providers your plan uses | Contract | [As you keep them / our retention settings] *(chat: `CHAT_RETENTION_DAYS`; harness session files: `HARNESS_SESSION_RETENTION_DAYS`)* |
| Security and audit records: what was done, by which account, when, from which IP address and browser | You sign in or use the Service | To protect the Service and our users, investigate incidents, and show what happened | Legitimate interests (security) | [period] *(`AUDIT_RETENTION_DAYS`; after an erasure, kept under a random pseudonym: [ADR 0102](../adr/0102-erasing-a-users-data.md))* |
| Plan, subscription, payment processor customer id, token and storage use | You pay for the Service | To bill you and enforce plan limits | Contract; legal obligation (accounting records) | [period required by law, e.g. [6] years] *(card details go to [payment processor] directly and never reach us: [data flows: billing](data-flows.md#billing-stripe))* |
| Email address for approval and billing emails; phone push token | You turn notifications on | To tell you a Bot needs your approval, or about your plan | Contract / [legitimate interests] | Until you turn them off or your account ends *(a push says only which Bot is waiting, never commands or output: [ADR 0080](../adr/0080-client-push-notifications.md))* |
| Messages you send us | You contact support | To answer you | Legitimate interests | [period] |

We do not sell personal data. We do not use it for advertising. [We do not use your content to train AI models, and our agreements with model providers [do / do not] let them train on it: legal review.] *(SuperBot trains nothing; what a model provider does with prompts is set by its terms: [questionnaire FAQ](questionnaire-faq.md).)*

We do not make decisions about you with legal or similarly significant effects by automated means alone. *(Access requests are approved by a person: [ADR 0022](../adr/0022-landing-and-signups.md).)*

## 4. Who we share it with

We use service providers ("subprocessors") to run the Service: [list them, or link to the published list at [URL]]. *(Start from the [subprocessor list](subprocessors.md) and list only the services the managed service turns on. The DPA's [Annex III](dpa-template.md#annex-iii-subprocessors) has the same list.)*

In particular:

- **AI model providers** receive the prompts, conversation, tool output and file contents your Bots send them, to produce replies. [Names.]
- **[Payment processor]** receives your plan, an email to set up a customer, and usage counts; you enter card details on its pages.
- **[Hosting provider]** hosts your computer and our servers. **[Object storage provider]** holds encrypted backups.
- **[Email provider], [push service]** deliver notifications you turn on.
- **[Bot check provider]** checks our signup form for abuse and receives your IP address. *(Only with Cloudflare Turnstile configured.)*

If you sign in your computer's coding tools with your own AI subscription, those tools talk to that provider under your own account and its terms.

We also share data when the law requires it, to protect rights and safety, or with a buyer if our business is sold, under this policy.

## 5. International transfers

Your data is stored in [region(s)]. [Some subprocessors process it in [countries].] Where data leaves the UK or EEA for a country without an adequacy decision, we rely on [Standard Contractual Clauses / the UK International Data Transfer Addendum / other mechanism]. Ask us for a copy at [Contact email].

## 6. How we protect it

Data is encrypted in transit; secrets and other sensitive fields are encrypted in our database; backups are encrypted; sign-in can require a second factor; and every significant action is recorded in an audit log. [Describe your own organisational measures.] *(Each statement must match the measures the provider has turned on: [DPA Annex II](dpa-template.md#annex-ii-technical-and-organisational-measures).)*

## 7. Your rights

You can ask us to:

- give you a copy of your personal data (access);
- correct it (rectification);
- delete it (erasure);
- limit how we use it (restriction);
- give it to you in a portable format (portability);
- stop using it where we rely on legitimate interests (objection);

and you can withdraw consent where we rely on it, without affecting what we did before.

Write to [Contact email]. We will confirm who you are and answer within one month, or tell you why we need longer. Some rights have limits: for example, we keep invoices as accounting law requires, and keep security records about an erased account under a pseudonym. *(How the provider answers each with SuperBot's tools: [self-hosting GDPR guide](gdpr-self-hosting.md#answering-requests).)*

If you use the Service through an organisation, we will pass requests about your content to that organisation.

You can complain to a data protection authority, such as [the UK Information Commissioner's Office / the authority where you live or work, or [lead authority]].

## 8. Cookies and local storage

The Service uses only strictly necessary cookies and storage: a cookie or your browser's storage keeps you signed in to the web app, and a short-lived cookie ties a single sign-on to the browser that started it. The mobile apps keep your sign-in in your phone's secure storage. None of these is used for tracking, and we use no analytics or advertising cookies. [If our signup form uses a bot check, its provider may set its own cookie.] *(The cookies are `__Host-superbot_session` (HttpOnly, Secure, SameSite=Strict: [access control](access-control.md#authentication)) and `__Host-superbot_sso` ([`server/src/sso/mod.rs`](../../server/src/sso/mod.rs)); the apps' storage is in [data flows](data-flows.md#on-peoples-devices). SuperBot ships no analytics, and the site's Content-Security-Policy allows no outside origin but Cloudflare's Turnstile: [ADR 0022](../adr/0022-landing-and-signups.md). Check the provider's own website before claiming this for it.)*

## 9. Children

The Service is not meant for children under [16], and we do not knowingly collect their data.

## 10. Changes

We will post changes here with a new date, and tell account holders by [email] before significant changes take effect.
