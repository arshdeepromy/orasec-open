# OraSec

OraSec is a security operations console you host yourself. It keeps your vulnerabilities, assets, attacks, risks and
ISO/IEC 27001 work in one place, and it comes with a free mobile app (Android and iOS).

It is free and open source (BSD 3-Clause).

> **Where it comes from.** OraSec is a fork of [DefectDojo](https://github.com/DefectDojo/django-DefectDojo)
> (© DefectDojo, Inc., BSD 3-Clause). The vulnerability management core is DefectDojo's work; names in the code were
> changed from DefectDojo to OraSec. OraSec is **not** affiliated with or endorsed by DefectDojo, Inc. or OWASP.
> Some older files still carry links that came out of that rename (for example `orasec.com`, `docs.orasec.com`,
> `hub.docker.com/u/orasec`). Those addresses are not ours and are not part of this project; build the images
> yourself as shown below.

## What OraSec adds

| Area | What you get |
|---|---|
| Posture | One score and a command centre: open, known-exploited (CISA KEV) and likely-exploited (EPSS) findings, SLA, fix-first list |
| Connectors | Wazuh, PatchMon, Beszel, UniFi, OPNsense, Check Point, AWS, Plerion, Tenable, Cloudflare, GitHub, a policy tool; each is a **plugin** you turn on or off |
| Assets | Live asset inventory with owners, classification and locations (ISO/IEC 27001 A.5.9), Excel and PDF export |
| Attacks | Blocked and suspicious events on a map and a timeline, security alerts from Wazuh |
| Network | Live topology: your documented network with live health, VPN, firewall and tunnel state on top |
| GRC | Risk register, exceptions, suppliers, objectives, change register, leavers, ISO/IEC 27001 control checks with evidence |
| Assistant | "Ora", an AI assistant over your own data, with prompt-injection guardrails; optional MCP server for AI clients |
| Sign-in | Local accounts; optional OpenID Connect, Microsoft Entra ID, Okta and Active Directory sign-in |
| Mobile app | Android and iOS app (`mobile/`): posture, vulnerabilities, attacks, risks, phone notifications for security alerts |

## Quick start (Docker Compose)

You need Docker with Compose and about 4 GB of free memory.

```sh
git clone https://github.com/arshdeepromy/orasec-open.git
cd orasec-open

# secrets of your own; keep this file private
DBPW=$(openssl rand -hex 16)
cat > .env <<EOF
ORASEC_SECRET_KEY=$(openssl rand -hex 32)
ORASEC_CREDENTIAL_AES_256_KEY=$(openssl rand -hex 16)
ORASEC_DATABASE_PASSWORD=$DBPW
ORASEC_DATABASE_URL=postgresql://orasec:$DBPW@postgres:5432/orasec
EOF

docker compose build        # builds the two images from this source
docker compose up -d
docker compose logs -f initializer                          # wait until it finishes (first start: a few minutes)
docker compose exec uwsgi ./manage.py changepassword admin  # choose the admin password
```

Open <http://localhost:8080> and sign in as `admin` with the password you chose. More options, production advice and the development mode are in [readme-docs/DOCKER.md](readme-docs/DOCKER.md).

**Before you use it for real:** serve it over https, set `ORASEC_ALLOWED_HOSTS` to your host name, and keep `.env` and
your site file out of version control.

## Tell OraSec about your organisation (site profile)

Nothing about one organisation's network or people is in the code. OraSec reads one optional JSON file, the
**site profile**: your organisation's name, security contact, office networks, default asset owners and the network
drawing for the topology page. Without the file you get neutral defaults and an example network.

See [readme-docs/SITE-PROFILE.md](readme-docs/SITE-PROFILE.md).

## Plugins

Every integration is a plugin. An administrator turns each one on or off under **Automation → Plugins**: data sources
(one per connector kind), threat intelligence (KEV, EPSS), the Ora assistant, single sign-on, the mobile app, phone
notifications, the MCP server, and the notification channels. A plugin that is off does not run, and the mobile app
hides what depends on it.

Set-up notes for each connector and each way to sign in, and how far each one is tested, are in
[readme-docs/INTEGRATIONS.md](readme-docs/INTEGRATIONS.md).

## Mobile app

The app in `mobile/` (Capacitor, React) works with any OraSec server: on its first screen you enter the address of
your own server. Phones are linked with a one-time code from the web console; no passwords are stored in the app.
Build and store notes are in [mobile/README.md](mobile/README.md).

If your console sits behind an access proxy, let the path `/api/v2/orasec/mobile` through; the device token is then
the only gate on that path.

## Tests

```sh
./run-unittest.sh --test-case unittests.test_plugins        # server (Django)
cd mobile && npm ci && npm test                             # app (vitest)
```

## Security

Please report security problems privately. See [SECURITY.md](SECURITY.md).

## Contributing

Issues and pull requests are welcome. See [readme-docs/CONTRIBUTING.md](readme-docs/CONTRIBUTING.md).

## Licence

[BSD 3-Clause](LICENSE.md). The DefectDojo copyright notice is kept as the licence requires; OraSec's additions are
published under the same licence. Third-party notices are in [NOTICE](NOTICE).

