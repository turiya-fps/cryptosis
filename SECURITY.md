# Security policy

## Reporting a vulnerability

Report privately via GitHub: **Security → Report a vulnerability** on this repository
(private vulnerability reporting). Please do not open a public issue.

Include what you did, what happened, the cryptosis version (`cryptosis --version`),
`gpg --version`, and the OS. Expect an acknowledgement within a week.

## Supported versions

Only the latest release receives fixes.

## Scope

In scope: anything that makes cryptosis less safe than running the same `gpg`
commands by hand. For example, a command differing from its preview, terminal
escape injection, an import that skips the preview, a file written where it
shouldn't be, or a release-integrity problem.

Out of scope: vulnerabilities in GnuPG, gpg-agent, pinentry or the OS. Report
those upstream. See the threat model in the [README](README.md#security-model).
