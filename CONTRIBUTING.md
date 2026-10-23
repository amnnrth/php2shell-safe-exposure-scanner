# Contributing

Thank you for helping improve the scanner while keeping it safe and useful for defenders.

## Before opening a pull request

1. Open an issue for substantial changes so the scope and expected behavior can be discussed.
2. Keep changes within authorized, defensive assessment use. Do not add exploit payloads, destructive requests, credential attacks, stealth, or evasion features.
3. Prefer low-noise checks, explicit opt-in behavior for features that increase traffic, and clear caps for concurrency and request counts.
4. Never commit real target lists, credentials, client/employer data, inventories, scan reports, or unredacted logs.
5. Update the README when behavior, options, limitations, or interpretation changes.
6. Add or update tests. Tests must not scan live public hosts.

## Local checks

```bash
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python -m py_compile php2shell_scan.py
```

## Pull request expectations

Explain the problem, the implementation, any traffic or data-handling implications, how you tested it, and any compatibility impact. Keep changes focused and avoid introducing dependencies without a clear need.
