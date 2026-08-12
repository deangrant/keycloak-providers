# Lint

Run project lint the same way CI does, applying format first.

## Steps

1. From the repository root, apply Spotless:

```bash
mvn -B spotless:apply
```

2. Run verify without tests:

```bash
mvn -B verify -DskipTests
```

3. Summarize the result for the user:
   - On success: note that Enforcer, Error Prone compile, and Spotless check passed.
   - On failure: quote the failing plugin/module and the first actionable error lines. Do not paste the entire Maven log.

Do not skip Spotless apply before verify unless the user explicitly asks to check-only.
