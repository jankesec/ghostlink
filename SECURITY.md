# Security policy

## Supported code

Security fixes are applied to the default branch and, when appropriate, the latest GitHub
release. Older snapshots may not receive backports.

## Reporting a vulnerability

Do not open a public issue containing exploit code, credentials, sensitive captures, or a
working bypass. Use GitHub's private vulnerability-reporting flow for this repository when
available. If it is unavailable, open a minimal issue requesting a private contact channel
without including technical details.

Include:

- the affected commit or release;
- the operating system and Go version;
- the smallest safe reproduction using synthetic data;
- the observed impact and expected boundary;
- a suggested remediation, if known.

Reports are evaluated against the documented security model. A transport being observable,
blocked, or unsuitable for a network is not by itself a vulnerability: Ghostlink does not
promise evasion. Issues that expose local data unexpectedly, weaken cryptographic handling,
escape loopback defaults, permit path traversal, or broaden file permissions are security
relevant.

## Operator responsibilities

Run Ghostlink only on systems and networks you own or have explicit authorization to test.
Use synthetic inputs, isolate experiments, select ECDHE or a strong pre-shared key for
network tests, and remove received artifacts when the exercise is complete.
