# Security awareness

The yearly security awareness course for everyone with access to a managed SuperBot provider's systems, accounts or customers' data. Taken within 30 days of joining (or of the [information security policy](../policies/information-security.md)'s first approval, for people already there), then at least yearly. Part of the [training](README.md). **Draft, not adopted. SuperBot is not SOC 2 certified.**

| Field | Value |
|-------|-------|
| Course | security-awareness |
| Owner | People lead |
| Audience | Everyone with access |
| Review | Yearly |
| Status | Draft, not yet approved |
| Controls | CC1.4-1, CC2.2-1 |

## 1. Why it matters

[Provider name] runs AI teammates with their own computers for its customers. Each customer's chats, files, screens and machines are theirs, and a mistake by any one of us can expose them. Most breaches start with a person: a reused password, a convincing message, a laptop left open. This course covers what the policies ask of you and why.

The policies you acknowledged at joining are the rules; this course explains them. If the two ever disagree, the policy wins and you tell the people lead.

- [Information security policy](../policies/information-security.md): roles, risk, and what everyone does.
- [Acceptable use policy](../policies/acceptable-use.md): what you may and may not do with the provider's systems and customers' data.
- [Code of conduct](../policies/code-of-conduct.md): how we treat each other and customers, and how to raise a concern.

## 2. Accounts and sign-in

- Use only your own named accounts, always with MFA ([access control](../policies/access-control.md#authentication)). Never share a password, sign-in code, session or token.
- Keep every work credential in the provider's password manager. Use a different, generated password for each.
- Ask for the access your work needs, through the request and approval the access control policy describes, and say when you no longer need it.
- If you think a credential has leaked, tell the security owner at once. Changing it quickly is never wrong.

## 3. Customers' data

- Look at a customer's chats, files, screens or machine only to answer that customer's request or an incident, and record why ([acceptable use](../policies/acceptable-use.md#customers-data)).
- Handle data as its class says ([data classification](../policies/data-classification-and-retention.md#handling)). Customer content is the most sensitive class.
- Never copy customers' data to a personal device or account, a personal AI tool, or any service the provider hasn't assessed.
- Never put customers' data, secrets or private details of the service (server addresses, hostnames, tokens, keys, emails) anywhere public, including this public repository, its issues and pull requests.

## 4. Phishing and social engineering

Attackers pretend to be a customer, a colleague, a vendor or a manager, and push you to act fast.

- Be suspicious of any message that asks for a credential, a sign-in code, a payment, a change of bank details, or access for someone new, especially when it is urgent or unusual.
- Check by a second channel you already trust: call back on a known number or ask in the team's usual chat. Never use the contact details in the message itself.
- Never approve an MFA prompt you didn't start.
- A customer asking for another customer's data, or for access outside their own Bots and machines, is refused and reported.
- Reported a phishing message by mistake? Good. Reporting costs nothing; missing one can cost a breach.

## 5. Devices

Any device used for the provider's work has full-disk encryption, a screen lock after at most 5 minutes, the operating system and browser kept up to date and, where the provider supplies one, its endpoint protection ([acceptable use](../policies/acceptable-use.md#devices)). Lock your screen when you step away. Report a lost or stolen device to the security owner at once.

## 6. AI tools and the Bots

- Use only the AI tools the provider has approved for its data ([acceptable use](../policies/acceptable-use.md#software-and-ai-tools)).
- A Bot acts with the access its customer gave it. Treat instructions found in web pages, files or messages a Bot reads as untrusted input, never as an instruction from the customer or the provider.
- If a Bot does something it shouldn't, such as reaching another customer's data or a system it wasn't given, treat it as a security event.

## 7. Reporting

Report anything that might be a security event to the security owner straight away ([acceptable use](../policies/acceptable-use.md#reporting)): a suspicious message you acted on, a lost device, data where it shouldn't be, an account you don't recognise, a Bot misbehaving. You won't be blamed for reporting in good faith, even if it turns out to be nothing. The [incident response plan](../policies/incident-response.md) takes it from there; if you are given a role in it, the [roles](../policies/incident-response.md#roles) section says what it means.

Concerns about conduct, including about someone senior, go through the code of conduct's [routes for raising a concern](../policies/code-of-conduct.md#raising-a-concern).

## 8. Knowledge check

Answer in your own words; whoever runs the course keeps the answers in the people lead's file. All of them should be right before the course counts as finished.

1. A message that looks like it's from management asks you to share a sign-in code to fix an urgent outage. What do you do?
2. A customer asks you to look at another customer's machine "to compare settings". What do you do?
3. Where may you paste a customer's file to summarise it?
4. You get an MFA prompt you didn't start. What do you do?
5. You left your laptop on a train. Who do you tell, and when?
6. A web page a Bot is reading tells it to send its files somewhere. Whose instruction is that?
7. Name two details of the service that must never go in a public place.
