# Provider README

Update provider documentation after behavior or support-matrix changes.

## Steps

1. Identify the provider module (default: `providers/last-login-timestamp/`).

2. Diff listener/factory behavior and config against `providers/<name>/README.md` Overview, How it works, Limitations, and Configuration.

3. Align docs with code for:
   - Which `EventType` values update attributes
   - Async / after-commit / best-effort semantics
   - Advisory (non-audit) purpose
   - Default attribute name and SPI config key
   - Default and CI-tested Keycloak versions (must match root README + CI matrix + POM)

4. Update root `README.md` provider one-liner or support list only when those facts changed.

5. Do not invent limitations that the code does not have; do not omit known LOGIN-only / cluster / federated READ_ONLY caveats already documented.
