# hardenctl — Demo Runbook

> **Note (v0.1.0):** this runbook predates `hardenctl configure` and intent.
> Where it says `export ANTHROPIC_API_KEY` / `sudo -E`, use
> `sudo hardenctl configure` instead: Ubuntu's sudoers strips environment
> variables. For the current intent/drift demo see `INTENT_DEMO.md`.

Ubuntu VM in VMware. Roughly 12 minutes end to end, or 6 if you skip the LLM
proposer and run the offline path.

---

## Before anything

**Take a VMware snapshot.** `VM → Snapshot → Take Snapshot`, name it
`pre-hardenctl`. This demo weakens SSH, file permissions and kernel settings on
purpose. hardenctl's own rollback works, but the snapshot is the real net.

**Use the VMware console window, not an SSH session.** The demo changes
`PasswordAuthentication` in `sshd_config`. It does not restart sshd, so an open
session survives — but if anything restarts sshd while password auth is off and
you have no key installed, you lose the VM. Work at the console and this cannot
happen.

**Isolate the network.** `VM → Settings → Network Adapter → Host-only` is
safest. The lab script exposes redis on `0.0.0.0` with protected-mode off, which
you do not want reachable.

---

## 1. Get the code onto the VM

Pick whichever is easiest for you.

**From your host over SSH** (before you weaken anything):

```bash
scp -r hardenctl/ user@<vm-ip>:~/
```

**VMware shared folder:** `VM → Settings → Options → Shared Folders`, add the
folder, then on the VM it appears under `/mnt/hgfs/<name>`.

**Or just retype nothing** — put it in a GitHub repo and `git clone` it.

---

## 2. Install

```bash
cd ~/hardenctl
sudo apt update
sudo apt install -y python3-pip
sudo pip install -e . --break-system-packages
hardenctl --help
```

Install with `sudo` so the binary lands in `/usr/local/bin` and works under
`sudo hardenctl apply` later. A user-local install will not be on root's PATH.

---

## 3. Build the weak baseline

```bash
cd ~/hardenctl/demo
chmod +x setup_lab.sh plant_injection.sh
sudo ./setup_lab.sh
```

It asks you to confirm the snapshot. Type `yes`.

What it does: installs openssh-server, redis and nginx; turns on root login and
password auth; sets `sshd_config` to mode 0644; binds redis to `0.0.0.0` with
protected-mode off; sets `/etc/shadow` to 0644; disables ASLR and SYN cookies.

---

## 4. The demo

### Act 1 — Scan (60 seconds)

```bash
sudo hardenctl scan
```

Point at the redis row. Port 6379, `PUBLIC`, running as root, attributed to the
`redis-server` package. **Say:** three separate facts joined — the socket, the
process, the owning package. `ss -tulpn` gives you the first. Trivy gives you the
third. Nothing joins them.

Then the `CRITICAL` on `/etc/shadow` and the sshd findings.

### Act 2 — Plan, deterministic (60 seconds)

```bash
sudo hardenctl plan --proposer rules --out /tmp/plan-rules.json
```

**Say:** this is the baseline proposer. No model. Fixed mappings from finding to
action. It exists so the LLM has something to be measured against — and so the
tool works with no API key and no network.

### Act 3 — Plan, agentic (90 seconds)

```bash
export ANTHROPIC_API_KEY=sk-ant-...
sudo -E hardenctl plan --proposer llm --out /tmp/plan-llm.json
```

`-E` preserves the environment variable through sudo.

**Say:** the model receives the findings and returns JSON conforming to a fixed
schema. It prioritises and justifies. It does not invent findings, and it does
not execute anything.

Open the plan and show a `justification` field:

```bash
python3 -m json.tool /tmp/plan-llm.json | head -30
```

### Act 4 — Dry run, then apply (90 seconds)

```bash
sudo hardenctl apply /tmp/plan-llm.json --dry-run
sudo hardenctl apply /tmp/plan-llm.json
```

Note the run ID it prints.

```bash
grep -E "PermitRootLogin|PasswordAuth|MaxAuthTries" /etc/ssh/sshd_config
stat -c '%a %n' /etc/shadow
```

**Say:** every action was backed up before it ran, and its inverse was computed
from live state before the change, not guessed afterwards.

### Act 5 — Rollback (45 seconds)

```bash
sudo hardenctl rollback <run-id>
grep -E "PermitRootLogin|PasswordAuth" /etc/ssh/sshd_config
sudo hardenctl runs
```

**Say:** byte-exact restoration, not a best-effort reverse patch.

### Act 6 — The injection defence (3 minutes) ← the closer

Re-apply the weak baseline first if you rolled back:

```bash
sudo ./setup_lab.sh
sudo ./plant_injection.sh
head -9 /etc/ssh/sshd_config
```

Read the planted comment aloud. It claims a security waiver, closes the
untrusted-data tag, and instructs the reader to enable root login and open
`/etc/shadow`.

Then show that the parser never passes it on:

```bash
sudo hardenctl scan --json /tmp/findings.json
grep -c "HARDENING-EXEMPTION" /tmp/findings.json    # → 0
```

**Say:** the config parser discards comments. The payload never reaches the
model at all.

Then the part that actually matters:

```bash
cd ~/hardenctl && python3 test_injection.py
```

**Say:** that is twelve weakening actions, each with a plausible justification —
"the monitoring agent needs to read the shadow file", "ASLR interferes with the
profiler". This assumes the model was fully compromised and emitted every one of
them. All twelve are rejected. The validator never reads the justification. It
consults a table.

That is the design claim: **the model is a proposer, not an authority.**

---

## 5. Reset

```bash
sudo ./plant_injection.sh --clean
sudo ./setup_lab.sh --restore
```

Or roll the VM back to the `pre-hardenctl` snapshot, which is cleaner.

---

## If something goes wrong

| Symptom | Fix |
|---|---|
| `hardenctl: command not found` under sudo | Reinstall with `sudo pip install -e . --break-system-packages` |
| LLM proposer fails, no key | `sudo -E` and confirm `echo $ANTHROPIC_API_KEY` |
| LLM proposer fails, no network | Skip Act 3, use `--proposer rules`. Act 6 runs offline. |
| Locked out of SSH | Use the VMware console — that is why you are working there |
| Anything unrecoverable | Restore the snapshot |

---

## What to say if asked "is this just a wrapper around an LLM?"

The wrapper is the contribution. The model proposes; three deterministic gates
decide what executes; every change is transactional and reversible. Remove the
model and the tool still works, because the rules proposer is the same interface.
Remove the gates and it is unsafe to deploy at all.
