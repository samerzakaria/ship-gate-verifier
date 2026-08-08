# External policies

One signed `shipgate.authority.policy/1` document per target repository, plus its cosign
bundle, plus `policy-root.pub` — the PUBLIC half of the org policy root.

These land here in STEP 3 (`install-policy-root.sh`). The policy root's PRIVATE key never
appears in this repository, or in any repository. It is the trust root; it stays offline.
