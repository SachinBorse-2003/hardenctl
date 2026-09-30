# Final — Future Work (genuine next steps)

Ordered by how much each one strengthens the core claim.

1. **An independent held-out corpus (v3).** Written by someone who has not
   read `validator.py`, frozen before the first run. This is the single
   largest improvement to the evidence (limitation 1).
2. **Close the remaining deny-list.** Let the operator declare protected
   units and packages in `intent.yaml` (`protect:`), so security agents are
   covered by the host's own declaration instead of a global list. This fits
   the intent model: the operator already declares what must listen.
3. **Wider ordering rules.** `Banner`, `pam_pwquality`, `auditd` rules,
   `/etc/security/limits.conf`. Each needs a proven order and a test, and each
   widens the trusted code, so add them one at a time.
4. **Reachability by probing.** Probe each listener from a separate network
   namespace and from the host's routed interfaces, so a 0.0.0.0 service
   behind a firewall is no longer reported as PUBLIC (Review 0 promise).
5. **Blast radius.** For each exposed service: which credentials, sockets,
   groups (docker, adm) and sudo rules its user reaches.
6. **Attribution ground truth.** A VM with a labelled list of every listener →
   process → package → unit, to measure the ≥ 95% attribution goal.
7. **Local-model runs.** Ollama with an open-weights model, so the LLM path
   runs with no data leaving the host. Compare validity and injection
   behaviour with the hosted model.
8. **Reload and health-check after apply.** Reload sshd (and any edited
   service), probe the declared intended services, and roll back
   automatically if one goes down. This turns service preservation from a
   measurement into a guarantee.
9. **Vulnerability enrichment** (OSV, CISA KEV, EPSS) on attributed packages,
   with a local cache.
10. **Token site and relay** (cut from this phase), for users without their
    own model key; no billing.
