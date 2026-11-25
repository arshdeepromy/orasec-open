# Integrations

Every integration is a plugin. An administrator turns each one on or off under **Automation → Plugins**. A plugin
that is off does not run; what it already collected stays.

This page covers the data sources and the ways to sign in. Connectors are added under **Automation → Connectors**;
the form shows set-up notes for the kind you pick. Secrets are encrypted at rest and never shown again.

## Data sources

| Connector | What it brings | Access it needs |
|---|---|---|
| Wazuh | Agents, inventory, vulnerabilities, failed hardening checks, security alerts | A read-only API user and indexer user |
| OPNsense | Package vulnerabilities, firmware, certificates, accounts without MFA, blocked traffic | An API key limited to a few pages |
| UniFi Network | Devices and firmware, clients, Wi-Fi security, firewall policies, WAN and VPN | An integration API key |
| Cloudflare | DNS, TLS, WAF, e-mail records, tunnels, blocked threats | A read-only API token |
| AWS | Inventory, security groups, IAM, S3, RDS, CloudTrail, GuardDuty, Security Hub, Inspector | SecurityAudit + ViewOnlyAccess |
| Plerion | Cloud inventory and failed posture checks from every connected cloud account | A read-only tenant API key |
| Tenable Vulnerability Management | Assets and open vulnerabilities (bulk export) | API keys of a user that can view all assets |
| Check Point | What the firewall policy lets the internet reach, broad rules, gateways | A Read Only administrator |
| GitHub | Repositories, Dependabot, code scanning, secret scanning | A fine-grained read-only token |
| PatchMon, Semaphore, Beszel | Outstanding updates, patch runs, host health | See the form |

Findings from a connector are keyed on an id from the source, so a finding the source no longer reports is closed by
the next run. For that reason a connector never imports a partial read: a failed page, a lost export chunk or a list
that changes size while it is read fails the whole run and leaves the last good state in place.

### Plerion

- **Base URL**: the region host of your tenant, `https://{region}.api.plerion.com` (for example `au`, `us`, `eu`).
- **Secret**: a read-only tenant API key (Plerion: Settings, API keys).
- **Options**: `providers` (default `["AWS"]`), `resource_types` (default `["AWS::EC2::Instance"]`), `findings`
  (default `true`), `severities` (default `["CRITICAL", "HIGH"]`), `product_name`.

Only failed checks that are not exempted in Plerion become findings.

### Tenable Vulnerability Management

- **Base URL**: `https://cloud.tenable.com`. **Username**: API access key. **Secret**: API secret key.
- **Options**: `days` (default 90), `severities` (default critical to low), `plugin_output` (default `false`),
  `timeout_minutes` (default 30), `product_name`.

Each run exports the assets assessed in the last `days` days and the vulnerabilities in state OPEN or REOPENED. An
asset that has not been assessed for `days` days drops out, and its findings are closed with it.

### Check Point

The connector reads the management API of a Smart-1 Cloud tenant or an on-prem Security Management or Multi-Domain
server. It never talks to a gateway.

Read-only, three ways:

1. Give the administrator a **Read Only** permission profile with *Management API Login*.
2. Every session is opened read-only. A session that is not read-only is closed and the run stops.
3. Only `login`, `logout`, `keepalive` and `show-*` commands are ever sent.

TLS is always verified for this connector. An on-prem server with a private certificate needs a certificate the
OraSec server trusts.

| Way in | Base URL | Credentials |
|---|---|---|
| Direct (default) | The Management API URL, `https://<server>/web_api` | Secret `api_key`, or Username + secret `password` |
| Portal (`"auth_mode": "portal"`) | The Authentication URL from the Portal API Keys page | Option `client_id`, secret `portal_secret`, and the management administrator as above |

Other options: `packages` (blank reads all), `domain` (Multi-Domain servers), `management_url` (portal mode, to
override the address built from the service details), `product_name`.

What a run reports:

- **High**: an administration or database port of a known asset that anyone on the internet can reach.
- **Info**: the other internet-facing ports of each asset, one finding per asset.
- **High, Medium or Low**: broad rules that accept traffic from outside to Any destination.
- Assets the internet can reach are marked *internet exposed*. The run's details list every way in with its rule.

Known limits: only the first ordered layer of each package is read (a later layer can still block a port shown
open, it cannot open one shown closed); every package is read against every asset; time objects, install-on, VPN
columns and access roles are ignored.

### AWS: other accounts and other ways to sign in

- Temporary credentials: add the secret `session_token`.
- No key: leave the user name and the secret blank; the server's own identity is used (instance profile, task role).
- Another account: `{"role_arn": "arn:aws:iam::<account id>:role/OraSecReadOnly", "external_id": "..."}`. Add one
  connector for each account.

## Signing in

Local accounts always work. Every other way in follows the same rules: only a person who already has an active
OraSec account can sign in, the account is found by e-mail address, no account is created and no permission is
changed. Settings are environment variables of the web container.

| Way in | Plugin | Settings |
|---|---|---|
| OpenID Connect (any provider) | Single sign-on | `ORASEC_OIDC_ENABLED`, `ORASEC_OIDC_ISSUER`, `ORASEC_OIDC_CLIENT_ID`, `ORASEC_OIDC_CLIENT_SECRET`, `ORASEC_OIDC_ALLOWED_GROUP` |
| Microsoft Entra ID | Microsoft Entra ID sign-in | `ORASEC_ENTRA_ENABLED`, `ORASEC_ENTRA_TENANT_ID`, `ORASEC_ENTRA_CLIENT_ID`, `ORASEC_ENTRA_CLIENT_SECRET` |
| Okta | Okta sign-in | `ORASEC_OKTA_ENABLED`, `ORASEC_OKTA_DOMAIN`, `ORASEC_OKTA_CLIENT_ID`, `ORASEC_OKTA_CLIENT_SECRET` |
| Active Directory | Active Directory sign-in | `ORASEC_LDAP_ENABLED`, `ORASEC_LDAP_HOST`, `ORASEC_LDAP_BASE_DN`, `ORASEC_LDAP_BIND_DN`, `ORASEC_LDAP_BIND_PASSWORD` |

### Microsoft Entra ID

Register a web application and add the redirect URI `https://<your server>/sso/entra/callback/`.

- `ORASEC_ENTRA_TENANT_ID`: the directory (tenant) id, or a verified domain.
- For a multi-tenant registration (`common` or `organizations`) you must list the tenants that may sign in in
  `ORASEC_ENTRA_ALLOWED_TENANTS`. Without the list the provider stays off.
- `ORASEC_ENTRA_ALLOWED_GROUP` (optional): a group object id or an app role value. A person in too many groups for
  the token is refused with a clear message; use an app role in that case.
- `ORASEC_ENTRA_REDIRECT_URI`: set it when the server sits behind a proxy.

### Okta

Create an OIDC web application (authorization code flow) with the redirect URI
`https://<your server>/sso/okta/callback/`.

- `ORASEC_OKTA_DOMAIN`: `example.okta.com`, not the `-admin` host.
- `ORASEC_OKTA_AUTH_SERVER`: `default` (the built-in custom authorization server), `org`, or the id of another
  custom server. It must match the application, because it changes the issuer.
- `ORASEC_OKTA_ALLOWED_GROUP` (optional): needs a `groups` claim in the ID token of the application.

### Active Directory

People type their directory user name (logon name, user principal name or e-mail address) and password on the
normal login form. A read-only service account finds the person; the person's own bind proves the password.

- The password never travels in clear text: LDAPS by default, StartTLS when `ORASEC_LDAP_USE_SSL=False`. The
  certificate is always verified (name and authority); `ORASEC_LDAP_CA_CERTS` names a CA bundle for a private
  certificate authority. The certificate must carry an Authority Key Identifier, as certificates from a certificate
  authority do; the one Samba generates for itself does not and is refused.
- `ORASEC_LDAP_ALLOWED_GROUP` (optional): a group name or DN; the person must be a direct member.
- A disabled directory account is refused. Local accounts are tried first, so the break-glass login keeps working
  when the domain controller cannot be reached.
- The directory account is matched to the OraSec account by e-mail address only, never by logon name.

## How well each one is tested

All of them have unit tests that run without a network. Beyond that:

| Integration | Tested against the real service |
|---|---|
| Wazuh, OPNsense, UniFi, Cloudflare, AWS (key pair), GitHub, OpenID Connect (Authentik) | Yes |
| Plerion, Tenable, Check Point | The request and paging rules come from an earlier tool that ran against live tenants; this code has not been run against one yet |
| AWS role assumption, Microsoft Entra ID, Okta | Not yet |
| Active Directory | Yes, against a Samba 4.22 Active Directory domain controller (LDAPS and StartTLS); not yet against Windows Server |

If you run one of these against a real tenant and something does not match, please open an issue with the run log
(it never contains secrets).

