# 0053: Smarter command analysis

## Status

Accepted (20 Nov 2026). Approvals follow-up 7 ([list](../approvals-followups.md), tracking issue [#13](https://github.com/CG-Labs/superbot/issues/13), M1). It builds on [ADR 0007](0007-approvals.md) (approvals and the policy engine), [ADR 0036](0036-bots-on-the-users-machine.md) (Bots on the user's machine) and [ADR 0051](0051-approve-once-per-run.md) (approve for the rest of a run).

## Context

The policy engine parses each shell command like `bash` would (`server/src/shell.rs`) and classifies every command it finds. It did not look past the command line:

- A Bot could write `git push` into `deploy.sh` and run `./deploy.sh`, `bash deploy.sh`, `source deploy.sh`, or put it in `python x.py` or `node x.js`. None of that asked.
- Decoded or piped code was only caught for `curl … | sh`. `echo Z2l0IHB1c2g= | base64 -d | sh`, `xxd -r -p x | sh`, `printf '\x67…' | sh`, `python3 <<< "$CODE"`, or `make print | sh` ran as harmless.

A prompt-injected Bot finds these first. We wanted to close them without a sandbox, keep the classifier the single source of truth, and keep "Approve for this run" from covering code nobody saw.

## Decision

### Scripts are read and classified like the command line that runs them

When a command runs a script file, the server reads it and classifies its contents with the same rules:

- **What counts as running a script**: a path as the program (`./x.sh`, `scripts/x`, `/abs/path`), `source`/`.`, an interpreter with a file (`bash x.sh`, `sh -e x.sh`, `python3 x.py`, `node x.js`, `ruby`, `perl`, `php`, `deno run`, `bun`, ...), `cat x | sh`, and `sh < x`.
- **Shell scripts** are parsed and classified like a command line, including scripts they run in turn. A file run by path without a `#!` line is a shell script, as bash treats it; a `#!` line picks the language (`#!/usr/bin/env python3`).
- **Other languages** (Python, JavaScript/TypeScript, Ruby, Perl, PHP) are scanned, not parsed: a tokenizer skips comments, reads strings, and finds calls that run commands (`subprocess.run`, `os.system`, `execSync`, `system`, backticks, ...), run code (`eval`, `exec`, `Function`), load code by a run-time name, delete files (`shutil.rmtree`, `fs.rmSync`, `FileUtils.rm_rf`, `unlink`), or send email (`smtplib`, `nodemailer`, `Net::SMTP`). A command written out in full (`subprocess.run(['git', 'push'])`) is classified like any command. One built at run time asks, and so does one given options that change where or what it runs (`cwd`, `chdir`, `executable`, `env`). Every path a delete call names is checked. A risky API used under another name (`from subprocess import run as r`, `f = os.system`, `getattr(os, 'system')`, PHP's `$f(…)`) asks, since its calls can't be followed.
- **Files loaded first** are read too: `node --require`/`-r`/`--import`/`--loader`, `ruby -r`, and PHP's `auto_prepend_file` when they name a file (an installed package like `dotenv/config` isn't read). `python -m name` reads `name.py` or `name/__main__.py` when one is in the workspace.
- **Inline code** gets the same treatment: `bash -c '…'`, `python3 -c '…'`, `node -e '…'`, every `ruby -e`, here-documents and here-strings into an interpreter, and text piped in from `echo`/`printf`.
- **Findings say where they came from**: "Pushes to a git remote (in deploy.sh)". The label is the script's path inside the workspace, so `./deploy.sh` and `bash deploy.sh` match the same run grant, while a grant for a bare `git push` never covers a script, and the other way round. Scripts are read again on every check, so a changed script asks again.

### Reading is bounded and stays in the workspace

- Only files inside the Bot's workspace are read. Links are followed only while they stay inside. The file is then opened from the workspace folder one name at a time (`openat` with `O_NOFOLLOW`), so a folder swapped for a link after the check can't lead outside, and its type and size are checked on the opened file. FIFOs, devices and folders aren't read.
- A script run again in the same call is checked again (its input may differ); one that runs itself, directly or through others, asks. Compiled code given to an interpreter (`python3 x.pyc`) asks.
- At most 256 KiB per file and 32 files per call, inside the parser's existing limits (depth 16, 1 MiB per call in total).
- A compiled program (ELF or Mach-O header, or a NUL in its first line, as bash decides) is classified by its name, as before. So is a program outside the workspace without a script extension (`/usr/bin/git`, a virtualenv's `python` link).

### What can't be checked asks

These ask as `shell_destructive`, with a plain reason:

- The script is missing everywhere it could be ("doesn't exist yet"), too big, unreadable, a link out of the workspace, outside the workspace (a script extension, `/tmp`, or run by an interpreter), or names a language SuperBot can't read (`#!/usr/bin/env lua`).
- The same command line may change it first: the script's name appears elsewhere in it other than in read-only programs (`echo … > x.sh && ./x.sh`, `curl -o x.sh … && ./x.sh`), or something writes to a path only known when it runs.
- The Bot runs on the owner's machine (ADR 0036): the server can't read that disk, so every script there asks. Inline code is still checked.
- The script's name or the code is only known when it runs (`bash "$S"`, `python3 -c "$CODE"`).

### Decoded and piped code is its own reason, approved one call at a time

- **Decode and run**: something in the same command line decodes data (`base64 -d`, `base32 -d`, `basenc -d`, `xxd -r`, `openssl … -d`, `uudecode`, `gunzip`/`zcat`/`xz -d`/..., `rev`, `tr`, `printf` with `\x`/octal escapes or `%b`, `echo -e`) and the result reaches an interpreter, `eval`, or `-c`: "Decodes hidden code and runs it (base64 -d | sh)".
- **Command output run as code**: `eval "$(…)"`, `sh -c "$(…)"`, or a program we don't know piped into an interpreter: "Runs the output of a command as code (make | sh)".
- **Downloads** keep their reason, "Runs a downloaded script", now also for `bash <(curl …)` and `sh -c "$(curl …)"`.
- **Evasion**: wrappers that run strings (`env -S`, `script -c`, `watch`, `flock -c`, `busybox sh`), `find -exec`, `xargs` into an interpreter or an argument-sensitive program, functions, groups and nested `-c` are all unwrapped or ask. A here-document on another file descriptor (`sh 3<<EOF`) isn't the shell's input, so the shell reading its real input asks.

These are in `shell_destructive`, not a new class, so ADR 0051's one-at-a-time rule applies unchanged: their approval has no `runScope`, and the client shows no "Approve for this run". A new class would have needed a migration, a client change and a policy setting someone could flip to `allow`, which would defeat the point.

## Consequences

- Scripts and hidden code that used to slip through now ask, with a reason that says what and where.
- More asks. Wrapper scripts that end in `exec "$JAVA" "$@"` (`./gradlew`) ask every time, since what they run is only known then; so does any script on a user's machine. A remembered rule (`./gradlew build`) stops the asking for one exact call.
- The folder model stays order-blind: `cd scripts && ./x.sh` looks for `x.sh` in every folder the command could be in. A place where it's missing is skipped while another place has it.
- The scan of other languages is a heuristic. It catches the obvious calls and errs towards asking, but code can still hide a command from it (reflection, `getattr(os, name)`). This is still a guard against mistakes and prompt injection, not a sandbox (ADR 0007).
- A script can change between the check and the run. The check reads it as it is when asked; the next check reads it again.

## Alternatives considered

- **A new `obfuscated_code` class.** Clearer in the policy editor, but it could be set to `allow`, and every client and the console would need it. `shell_destructive` already means "one call at a time".
- **Parse other languages properly.** A parser per language is a lot of code to keep safe on hostile input; a bounded scan that asks when unsure gives most of the value.
- **Deny instead of ask** for decoded code. Some installers do this legitimately; a person can still approve one call.
- **Read scripts on the user's machine.** Needs a new machine-agent call on every check; asking is the safe default until then.
