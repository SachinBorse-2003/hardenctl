# hardenctl — Final Review Demo Runbook

Four stories in about 15 minutes, all on the lab VM, live. Run from the repo
(`~/Desktop/HardenCTL/hardenctl`) at the **VMware console**, not over SSH.

## Before the panel arrives

1. **Snapshot** the VM (`VM → Snapshot → Take Snapshot`, name it `pre-demo`).
2. **Host-only network** (`VM → Settings → Network Adapter`): the lab exposes
   redis on 0.0.0.0.
3. Make sure `sudo hardenctl` runs *this* checkout:
   ```bash
   sudo pip install --no-deps -e . --break-system-packages
   sudo python3 -c "import hardenctl; print(hardenctl.__file__)"   # must be under this repo
   ```
4. Build the weak lab and a clean state, then **snapshot again** (`weak-lab`):
   ```bash
   sudo demo/setup_lab.sh
   sudo rm -rf ~/.hardenctl/runs ~/.hardenctl/baseline.json
   sudo hardenctl intent init --force
   sudo hardenctl intent forbid 8080 --reason "OpenPLC web UI must not be public"
   sudo hardenctl scan > /dev/null
   ```

## Story 1 — Intent: what should this host expose? (4 min)

Follow `demo/INTENT_DEMO.md` steps 1–4: declared state, `python3 -m
http.server 8000 &` shows up as **NEW**, then `intent allow 8000 --reach
loopback` turns it into **DRIFT**. Stop the server afterwards (`kill %1`).

> Plain: the tool knows what the host is *supposed* to expose, so a new
> listener stands out without any signature.

## Story 2 — Harden, then undo it exactly (4 min)

```bash
sudo hardenctl plan --out /tmp/plan.json        # proposes; touches nothing
sudo hardenctl apply /tmp/plan.json --dry-run   # current -> new, per action
sha256sum /etc/ssh/sshd_config; stat -c %a /etc/shadow; sysctl kernel.randomize_va_space
sudo hardenctl apply /tmp/plan.json             # consent prompt, then applies
sudo hardenctl scan                             # sshd/mode findings gone
cat /etc/sysctl.d/99-hardenctl.conf             # sysctls now survive reboot
sudo hardenctl rollback --last
sha256sum /etc/ssh/sshd_config; stat -c %a /etc/shadow; sysctl kernel.randomize_va_space
```

> Plain: the hash, mode and sysctl match the "before" values exactly. The
> persistence file is gone too, because rollback deletes files the run
> created.

## Story 3 — A persuaded model still cannot weaken the host (4 min)

```bash
sudo demo/plant_injection.sh && sudo head -9 /etc/ssh/sshd_config
sudo hardenctl scan | head -20                  # comment text never becomes a finding
sudo hardenctl apply demo/evil.json --dry-run   # a "compromised model" plan
```

> Plain: `evil.json` asks for root SSH, ASLR off and auditd masked, each
> with a convincing reason. Three are refused at the monotonicity gate; the
> one that gets through (`fs.suid_dumpable=0`) is a genuine hardening change.
> The gate never reads the reasons.

Optional, with a provider configured: `sudo hardenctl plan --proposer llm`
with the payload still planted. Then `sudo demo/plant_injection.sh --clean`.

## Story 4 — The numbers (2 min)

```bash
hardenctl eval --runs 30        # about 30 s, no root, sandboxed
```

Point at: held-out corpus v2 (5/44 on gate v2's first run, and why), the
0/438 ablation, 30/30 rollback. Then open `docs/final/01_results.md`.

## After

Revert to the `pre-demo` snapshot, or run `sudo demo/setup_lab.sh --restore`.

## If something goes wrong

| Symptom | Fix |
|---|---|
| `sudo hardenctl` shows no `eval` command | Step 3 above: root is running an old install |
| Attribution columns empty | You ran without `sudo` |
| `apply` refuses the rules plan | Read the rejection. It is usually a real monotonicity rule, e.g. a mode that would add bits |
| Lost SSH | You are at the console, so fix `/etc/ssh/sshd_config`, or revert the snapshot |
