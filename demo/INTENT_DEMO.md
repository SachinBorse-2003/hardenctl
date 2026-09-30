# Intent demo: six commands, one story

Run from the repo (`~/Desktop/HardenCTL/hardenctl`) on the lab VM. It takes about six minutes.

**Ordering rule:** run `intent init` *before* starting the file server.
Otherwise the draft declares port 8000 and it shows INTENDED instead of NEW.

## Prep (before the panel arrives)

```bash
sudo rm -rf ~/.hardenctl/runs ~/.hardenctl/baseline.json
sudo hardenctl intent init --force
sudo hardenctl intent forbid 8080 --reason "OpenPLC web UI must not be public"
sudo hardenctl scan > /dev/null
```

This drafts intent from the current host, forbids OpenPLC, and takes a baseline
with port 8000 absent. Run `sudo hardenctl configure` once beforehand if you
want step 5.

## 1. Declared state

```bash
sudo hardenctl scan
```

> Everything on this host is compared against a declaration of what it should
> expose. Green is intended. The red FORBIDDEN row is OpenPLC: I declared it
> must never be public, and it is.

## 2. Something appears

```bash
python3 -m http.server 8000 &
```

> A developer starts a file server and doesn't tell anyone.

## 3. Drift caught

```bash
sudo hardenctl scan
```

> Port 8000 shows NEW, in red. It appeared since the last scan, was never
> declared, and is reachable from the whole network. No signature and no CVE
> were needed; a socket missing from the declaration is enough.

## 4. Ratify or refuse

```bash
sudo hardenctl intent allow 8000 --reach loopback --reason "dev file share" && sudo hardenctl scan
```

> Say it's allowed, but loopback only. Now it shows DRIFT: declared loopback,
> actually public. The tool separates "should exist" from "should be reachable
> from here".

## 5. Ask the model, only about what's undeclared

```bash
sudo hardenctl scan --explain
```

> Intended services never reach the model. It's only asked about what nobody
> declared, and it gets my intent status as context.

## 6. The gate

```bash
sudo hardenctl apply demo/evil.json --yes
```

> This is a plan a manipulated model might emit: root login on, ASLR off, audit
> masked, each with a convincing reason. It's rejected without a single
> justification being read.

## Reset

```bash
pkill -f "http.server 8000"
```
