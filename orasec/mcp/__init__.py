"""
Connector endpoint (Model Context Protocol) for OraSec.

A connected assistant client uses OraSec as the person who signed in, with exactly
that person's role and permissions. Identity comes only from the access token.

- ``views``     the HTTP endpoint (Streamable HTTP, stateless, plain JSON), metadata, pages
- ``auth``      sign-in: OAuth access tokens from the identity provider, or an expiring API token
- ``registry``  the tools a person may see and call
- ``guard``     what leaves OraSec: injection guard, secret scrubbing, size limit
- ``models``    proposals (two-step writes), connected clients, call log

Off unless ``ORASEC_MCP_ENABLED`` is set.
"""
