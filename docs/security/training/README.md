# Security training

The courses the [information security policy](../policies/information-security.md#people) requires of a managed SuperBot provider's personnel: security awareness for everyone at onboarding and yearly, and secure development for engineers yearly. Part of the [security pack](../README.md). **Drafts, not adopted. SuperBot is not SOC 2 certified, and these courses aren't certified by anyone.**

| Course | Who takes it | When | Owner |
|--------|--------------|------|-------|
| [Security awareness](security-awareness.md) | Everyone with access | Within 30 days of joining, then yearly | People lead |
| [Secure development](secure-development.md) | Engineers: anyone marked `engineer` in the register, and the engineering lead and their deputy | Within 30 days of becoming one, then yearly | Engineering lead |

## Running them

1. Adopt the courses with the policy set ([adopting them](../policies/README.md#adopting-them)): replace the bracketed placeholders, review the text against how you actually run the service, and approve it.
2. Give each course however suits you: read alone, a recorded call or a live session. Each ends with a short knowledge check; whoever runs it keeps the answers in the people lead's file.
3. Record each completion in the [policy register](../policy-register.md#hiring-checks-and-training) as a `training` record, with the course's id from its header (`security-awareness` or `secure-development`) and the day it was finished.
4. Each month, pass this folder to the register check with `--training docs/security/training`. The [register bundle](../soc2-evidence-plan.md#the-register-bundle)'s `people.json` then records each course's SHA-256, so an auditor can see which text was in force that month, and lists anyone who missed a course, finished it late or is overdue for the yearly refresher.

Change a course like a policy: by pull request, reviewed by its owner. A course's id (its `Course` row) never changes, since the register's records name it.
