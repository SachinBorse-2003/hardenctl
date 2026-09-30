# Final — Error Analysis

Real failures found by the harness, not constructed after the fact. Each one
has a result file that shows it, a cause, and a fix (with the commit) or a
stated limitation. F1–F5 were measured on the Review 1 code (`v0.1-baseline`,
commit `7ba8438`). F6–F10 came from the held-out corpus and the LLM runs.

| # | Failure | Evidence | Root cause | Resolution |
|---|---|---|---|---|
| F1 | sshd weaknesses written in lower case (`passwordauthentication yes`) were never found, so never fixed | `v0.1-baseline-rollback.json`: `missed_by_kind` includes `sshd:maxauthtries` 7, part of `passwordauthentication` 17 | `SSHD_CHECKS` was looked up with the exact spelling; sshd keywords are case-insensitive | Fixed `f847481`: keywords matched case-insensitively |
| F2 | On Ubuntu-style labs with `Include /etc/ssh/sshd_config.d/*.conf`, the tool reported PasswordAuthentication as fixed while sshd still used `yes` | `remediation_by_lab_type.with_dropin` 83.7% vs 91.5% without | The collector read only the main file. sshd expands Include in place and keeps the first value, so the drop-in wins. The plan edited a file sshd ignores for that setting | Fixed `f847481`: Include expanded in sshd order; the finding carries the file the value came from, so the plan edits that file |
| F3 | `/etc/shadow` at 0604 was left weak: the rules plan was refused | `missed_by_kind` `mode:etc/shadow` 7 | The rules proposer always proposed the CIS value 0640. On a 0604 file that adds group-read, and the gate correctly refused it as looser than current | Fixed `f847481`: propose `CIS ∩ current` (0604 → 0600). The LLM makes the same mistake (F9) |
| F4 | `MaxAuthTries 3` would have been "fixed" to 4 | Code review during F1; later corpus v2 case "MaxAuthTries raised 3 -> 4" | String comparison with the CIS value; 3 is stricter than 4 | Fixed `f847481`: numeric comparison in the collector; gate v2 refuses raising a value above the one on disk |
| F5 | DRIFT missed in 6/30 hosts: a declared-loopback port that was also bound on 0.0.0.0 showed as INTENDED | `v0.1-baseline-intent.json`: single-bind 14/14, dual-bind 10/16 | Socket findings were identified by `proto-port`, so the loopback and public sockets collided and the last one won | Fixed `f847481`: ids include the bind address; each socket gets its own verdict |
| F6 | Gate v1 let 9 of 11 weakening coverage probes through (drop-in, Ciphers, sudoers, unlisted sysctl, apparmor, …) | `v0.1-baseline-injection.json`, v1 coverage 3/12 | A deny-list only covers what its author thought of | Fixed `f847481`: gate v2 fails closed for config files and sysctls (Review 1 design option C) |
| F7 | Held-out v2, first run: 5/44 weakening actions accepted (journald socket, osquery agent, kernel image, libc-bin, `0777` on a not-yet-existing file) | `v2-heldout-first-run-injection.json` | All five in the parts of gate v2 still built as deny-lists, or in the absent-file branch | Partly fixed `3b45cfe` (gate v2.1): systemd-\* units protected, dpkg Essential/required/important and kernel packages protected, world-write never allowed. **Remaining:** security agents such as osquery (limitation) |
| F8 | Gate v2 refuses two legitimate CIS changes (`Banner`, `kernel.modules_disabled=1`) | same file, controls 9/11 | Fail-closed policy: anything without an ordering rule is refused | `Banner`: accepted cost, could be added with a path policy. `modules_disabled`: **kept refused on purpose**, since it cannot be reverted without a reboot and every applied change must be revertible |
| F9 | The LLM proposes `/etc/shadow` 0640 on a 0604 file (6/132 actions) | `v1.0-final-llm-rerun-llm.json` | The model applies the CIS number without reasoning about bits, the same as F3 | Not a gate failure: gate v2's on-disk mode check refused all six. Keeps LLM plan validity at 95.4%, below the 98% target |
| F10 | The LLM rewrote sandbox paths as real host paths (`/etc/passwd`) in 8 clean-run actions | `v1.0-final-llm-rerun-llm.json` `paths_rerooted` | The model "normalises" a long temporary path it was given | Harness guard `_assert_sandboxed` refused to act on them. The harness now re-roots and counts them. On a real host the paths are already real, so this is an eval artefact, reported so it is not mistaken for a gate result |
| F11 | 9 of 20 LLM calls failed in the first final run | `v1.0-final-llm.json` `error`: "Network is unreachable" | The VM lost its network mid-run | Re-run completed 20/20. Both files are kept |
| F12 | The installed `hardenctl` and `sudo hardenctl` ran an old copy in `~/hardenctl` (dated 3 Sep), not the repo | `pip show hardenctl` pointed to `/home/sachin/hardenctl` | Editable install made before the repo moved to `~/Desktop/HardenCTL/hardenctl` | User install re-pointed. The root install needs `sudo pip install -e .` from the repo (see [README](README.md)). `eval/run_baselines.sh` runs the repo code directly |

## What the failures have in common

- **F1, F2, F4: the tool's model of sshd was simpler than sshd.** The fix was
  to implement sshd's own resolution rules (case, Include, first value,
  Match), then check them against an oracle written independently in the
  harness *before* the fix.
- **F6, F7: deny-lists leak; fail-closed components did not.** This is the
  main design lesson, and it is measured, not argued: 0 leaks in the
  fail-closed categories of the held-out set.
- **F3, F9: "set it to the CIS value" is not monotone.** A CIS value can be
  looser than the current value in some bits. The correct operation is
  intersection, and only a gate that reads the disk catches this.
