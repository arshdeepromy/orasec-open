# Contributing

Thank you for helping.

## Before you start

- For a bug, open an issue with the steps to reproduce it and what you expected.
- For a larger change, open an issue first so we can agree on the approach.
- For a security problem, do **not** open an issue. See [SECURITY.md](../SECURITY.md).

## Rules for a pull request

1. **Nothing site-specific in the code.** No real host names, addresses, people, account ids or keys, in code,
   tests, comments or screenshots. Use `example.com`, the documentation address ranges (`192.0.2.0/24`,
   `198.51.100.0/24`, `203.0.113.0/24`) and invented names. Anything that differs per organisation belongs in the
   [site profile](SITE-PROFILE.md) or a setting.
2. **Every integration is a plugin.** A new connector or channel is registered in `orasec/plugins/registry.py` and
   must do nothing when its plugin is off.
3. **Tests.** Add or update unit tests (`unittests/` for the server, `mobile/src/**/__tests__` for the app) and run
   them before you push.
4. **Migrations.** `python manage.py makemigrations --check` must be clean.
5. **Plain words** in the interface and the docs. Many users read English as a second language.
6. **No secrets**, ever. `.env`, `.env.store`, key stores, `google-services.json` and push keys stay out of git.

## Running the tests

```sh
./run-unittest.sh --test-case unittests.test_plugins
cd mobile && npm ci && npm test && npx tsc --noEmit
```

## Licence

By contributing you agree that your work is published under the project's [BSD 3-Clause licence](../LICENSE.md).

