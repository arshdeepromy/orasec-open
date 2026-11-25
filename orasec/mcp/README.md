# OraSec connector endpoint (`/mcp`)

An assistant client uses OraSec **as the person who signed in**, with exactly that person's role and
permissions. Off unless `ORASEC_MCP_ENABLED=True`.

## How to connect

You need: a single sign-on account (in the allowed group, with MFA), an OraSec account with the same
e-mail address, and a client that is on the allow-list of the SSO application for the connector.

1. Add a connector in your assistant client with the OraSec address ending in `/mcp`
   (your **Connected clients** page in OraSec shows it).
2. Enter the **client ID** of the SSO application for the connector. The identity provider cannot
   register clients by itself, so this is typed in once.
   - Command line client: `<client> mcp add --transport http --client-id <client id> --callback-port 8765 orasec <address>`
   - Clients with a connector form: paste the client ID under the advanced settings.
3. The client opens your single sign-on page. Sign in with your user name, password and MFA code.
   The password is typed on the sign-in page only, never into the client.
4. The client now lists the tools your role allows.

To stop a client: OraSec → Configuration → **Connected clients** → Block. To stop everything for
yourself: "Switch my connector access off" on the same page.

## Rules

- Identity comes only from the token. No service account, no "act as" argument.
- Every call checks: token signature, issuer, audience, expiry; the identity provider is asked about the
  token on every call; the OraSec account must be active. A disabled person is refused on the next call.
- `tools/list` shows only what the role allows, and `tools/call` checks again.
- Changes are two steps: a propose tool returns a preview and a proposal id (one person, one use,
  10 minutes); `confirm_action` runs it through the same helpers as the web pages.
- No one approves or reviews their own change. Through the connector, requester, approver and reviewer
  must be three different people.
- Evidence: titles only, never file contents. Restricted evidence titles stay inside unless switched on.
- Text from findings, assets and notes passes the injection guard, secrets and addresses are removed,
  results are size-limited and paged.
- Every call is logged (Configuration → **Connector call log**, admins).

## Settings

| Setting | Default | Meaning |
|---|---|---|
| `ORASEC_MCP_ENABLED` | `False` | Switch the endpoint on |
| `ORASEC_MCP_RESOURCE_URL` | empty | Public address of the endpoint; pin it behind a proxy |
| `ORASEC_MCP_OIDC_ISSUER` | empty | Issuer of the SSO application for the connector |
| `ORASEC_MCP_OIDC_CLIENT_IDS` | empty | Accepted token audiences (client IDs), comma separated |
| `ORASEC_MCP_USERINFO_CHECK` | `True` | Ask the identity provider on every call |
| `ORASEC_MCP_ALLOW_API_TOKEN` | `False` | Also accept a person's own API token, only if it has an expiry |
| `ORASEC_MCP_DATA_LEVELS` | `status,grc` | What may leave OraSec: `status`, `grc`, `findings`, `people` |
| `ORASEC_MCP_RESTRICTED_EVIDENCE_TITLES` | `False` | Return titles of Restricted evidence |
| `ORASEC_MCP_RATE_PER_MINUTE` | `60` | Calls per person per minute |
| `ORASEC_MCP_PROPOSAL_MINUTES` | `10` | Lifetime of a proposal id |
| `ORASEC_MCP_MAX_RESULT_CHARS` | `20000` | Size limit of one result |
| `ORASEC_MCP_ALLOWED_ORIGINS` | empty | Browser-based clients allowed to call the endpoint |

The allowed SSO group is the one of SSO sign-in (`ORASEC_OIDC_ALLOWED_GROUP`).

## Protocol

Streamable HTTP, stateless, plain JSON answers. Protocol revision 2026-07-28 (per-request metadata,
`server/discover`) and the earlier revisions that start with `initialize` (2025-11-25, 2025-06-18,
2025-03-26), without sessions. Sign-in metadata: `/.well-known/oauth-protected-resource/mcp`.

## Tests

`unittests/test_mcp_protocol.py`, `test_mcp_auth.py`, `test_mcp_roles.py`, `test_mcp_writes.py`
(shared set-up in `unittests/mcp_testing.py`).

