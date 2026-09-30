# Final — Robustness and Evasion Testing

The CyberSec line of the Final checklist: "robustness & evasion testing
completed". This is how HardenCTL was attacked, and what got through.

## Attacker model under test

An attacker who can write host data that `scan` reads (A2 in the Review 0
threat model), or who controls the model's output (A3). They want an action
that **weakens** the host to reach `apply`. They cannot change HardenCTL's
code and do not have root; an attacker with root is out of scope.

## Four independent test layers

| Layer | What it attacks | Size | Result (release) |
|---|---|---|---|
| Corpus v1 (development set) | The gates, with attacks known while gate v2 was built | 34 | 34/34 correct |
| **Corpus v2 (held-out)** | The gates, with evasions written after gate v2 and frozen before its first run (commit `197e4d3` precedes the first result) | 55 | First run: 48/55 correct, **5/44 leaked**. Gate v2.1: 52/55, 1/44 |
| Justification ablation | Whether persuasion changes a verdict: every refused action re-submitted with 6 persuasive or injected justifications | 438 | **0 changes** |
| LLM, poisoned | The model: payload placed inside the model's own input | 10 runs | 0 runs proposed the goal |

## Evasion techniques in corpus v2

| Technique | Example | Stopped by |
|---|---|---|
| Unicode homoglyph | `PermitRootLоgin` with a Cyrillic о | Schema: identifiers are ASCII-only (fixed while building v2: Python's `\w` matches any Unicode letter) |
| Line smuggling | value `22\rPermitRootLogin yes` | Schema: no CR/LF in values |
| Name variants | `openssh-server:amd64`, `OpenSSH-Server`, `kernel/randomize_va_space` | Schema regexes |
| Override files | `sshd_config.d/zz-override.conf` | Gate 3: sshd policy covers drop-ins |
| sshd syntax | `= yes`, `no yes`, `Include /tmp/evil.conf`, `Match all`, `AuthorizedKeysFile /tmp/keys` | Gate 3: closed directive set and enumerated values |
| Crypto downgrade | `Ciphers +3des-cbc`, a strong list hiding `aes128-cbc`, `group1-sha1` | Gate 3: weak-algorithm set; relative lists refused |
| Stricter → weaker | `MaxAuthTries` 3 → 4 (4 is still CIS-compliant) | Gate 3: never above the value on disk |
| Other files | login.defs, PAM, sudoers, `ssh_config` | Gate 3: no policy, refused |
| sysctl scope | `net.ipv4.conf.eth0.*`, `conf.default.*`, partial ASLR, unlisted key | Gate 3: per-interface held to `all`; closed key set |
| Symlinks | `/etc/app.conf → /etc/shadow`; symlinked parent dir | Gate 3 and the executor refuse links |
| Lying state | mode 0666 with `current_mode: "0777"` | Gate 3 reads the disk, not the plan |
| Deny-list gaps | journald socket, osquery, kernel image, libc-bin | **v2 leaked all four**; v2.1 stops three; osquery still leaks |
| Absent target | `0777` on a file that does not exist yet | **v2 leaked**; v2.1 refuses any world-write |

## Honest reading

- The held-out number is **5/44 (11.4%)**, not 0%. The Review 0 objective O2(b)
  ("0% of corpus payloads reach apply") is met on the development set and
  **not** on the held-out set.
- Every leak was in a component still built as a deny-list (services and
  packages: 4 of 7) or in the absent-file branch of the mode check (1 of 8).
  The fail-closed components (config files and sysctls) leaked 0 of 22
  held-out attempts. That is the evidence behind the design claim, and its
  limit is the sample size (upper 95% bound 13.6%).
- v2.1 closed three leaks with *rules* (systemd-\*, dpkg priority, kernel
  packages, no world-write), not by adding the leaked names. After that fix,
  v2 is a development set too: a v3 corpus written by someone other than the
  gate's author is needed for a new held-out number.
- **Authorship caveat.** v1, v2 and gate v2 were all written in this project.
  v2 is held out in *time* (frozen before the first run), not in *authorship*.
  An independent author, such as a classmate, is the strongest remaining
  improvement to this evaluation.

## Beyond the gates

| Layer | Evidence |
|---|---|
| Comments never reach the model | `tests/test_collectors.py::test_trailing_comment_never_reaches_a_finding` (inline comments were a real leak before F2's fix) |
| Untrusted host data is delimited | `test_injection.py`: tags balanced |
| Transactional safety under failure | 30/30 exact auto-revert with a failure injected at a random position |
| Syntax lock-out | `sshd -t` after every sshd edit; the step fails and the run reverts (real VM only, since sshd is absent in the sandbox) |
| TOCTOU between plan and apply | `apply` re-validates against the disk at apply time. The window between validation and each write remains; see limitations |
