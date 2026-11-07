# Freshdesk MCP Server
[![LightNow](https://lightnow.ai/badge/io.github.effytech/freshdesk_mcp)](https://lightnow.ai/servers/io.github.effytech/freshdesk_mcp)

[![Trust Score](https://archestra.ai/mcp-catalog/api/badge/quality/effytech/freshdesk_mcp)](https://archestra.ai/mcp-catalog/effytech__freshdesk_mcp)

An MCP server implementation that integrates with Freshdesk, enabling AI models to interact with Freshdesk modules and perform various support operations.

## Features

- **Freshdesk Integration**: Seamless interaction with Freshdesk API endpoints
- **AI Model Support**: Enables AI models to perform support operations through Freshdesk
- **Automated Ticket Management**: Handle ticket creation, updates, and responses

## Components

### Tools

The server offers several tools for Freshdesk operations:

- `create_ticket`: Create new support tickets
  - **Inputs**:
    - `subject` (string, required): Ticket subject
    - `description` (string, required): Ticket description
    - `source` (number, required): Ticket source code
    - `priority` (number, required): Ticket priority level
    - `status` (number, required): Ticket status code
    - `email` (string, optional): Email of the requester
    - `requester_id` (number, optional): ID of the requester
    - `custom_fields` (object, optional): Custom fields to set on the ticket
    - `additional_fields` (object, optional): Additional top-level fields

- `update_ticket`: Update existing tickets
  - **Inputs**:
    - `ticket_id` (number, required): ID of the ticket to update
    - `ticket_fields` (object, required): Fields to update

- `delete_ticket`: Delete a ticket
  - **Inputs**:
    - `ticket_id` (number, required): ID of the ticket to delete

- `search_tickets`: Search for tickets based on criteria
  - **Inputs**:
    - `query` (string, required): Search query string

- `get_ticket_fields`: Get all ticket fields
  - **Inputs**:
    - None

- `get_tickets`: Get all tickets
  - **Inputs**:
    - `page` (number, optional): Page number to fetch
    - `per_page` (number, optional): Number of tickets per page

- `get_ticket`: Get a single ticket
  - **Inputs**:
    - `ticket_id` (number, required): ID of the ticket to get

- `get_ticket_conversation`: Get conversation for a ticket
  - **Inputs**:
    - `ticket_id` (number, required): ID of the ticket

- `create_ticket_reply`: Reply to a ticket
  - **Inputs**:
    - `ticket_id` (number, required): ID of the ticket
    - `body` (string, required): Content of the reply
    - `cc_emails` (array of strings, optional): Additional email addresses added to the 'cc' field of the outgoing email. These supplement the ticket requester, who always remains the primary recipient
    - `bcc_emails` (array of strings, optional): Additional email addresses added to the 'bcc' field of the outgoing email. These supplement the ticket requester, who always remains the primary recipient
    - `from_email` (string, optional): Email address the reply is sent from
    - `user_id` (number, optional): ID of the agent who is adding the reply

- `create_ticket_note`: Add a note to a ticket
  - **Inputs**:
    - `ticket_id` (number, required): ID of the ticket
    - `body` (string, required): Content of the note

- `update_ticket_conversation`: Update a conversation
  - **Inputs**:
    - `conversation_id` (number, required): ID of the conversation
    - `body` (string, required): Updated content

- `view_ticket_summary`: Get the summary of a ticket
  - **Inputs**:
    - `ticket_id` (number, required): ID of the ticket

- `update_ticket_summary`: Update the summary of a ticket
  - **Inputs**:
    - `ticket_id` (number, required): ID of the ticket
    - `body` (string, required): New summary content

- `delete_ticket_summary`: Delete the summary of a ticket
  - **Inputs**:
    - `ticket_id` (number, required): ID of the ticket

- `get_agents`: Get all agents
  - **Inputs**:
    - `page` (number, optional): Page number
    - `per_page` (number, optional): Number of agents per page

- `view_agent`: Get a single agent
  - **Inputs**:
    - `agent_id` (number, required): ID of the agent

- `create_agent`: Create a new agent
  - **Inputs**:
    - `agent_fields` (object, required): Agent details

- `update_agent`: Update an agent
  - **Inputs**:
    - `agent_id` (number, required): ID of the agent
    - `agent_fields` (object, required): Fields to update

- `search_agents`: Search for agents
  - **Inputs**:
    - `query` (string, required): Search query

- `list_contacts`: Get all contacts
  - **Inputs**:
    - `page` (number, optional): Page number
    - `per_page` (number, optional): Contacts per page

- `get_contact`: Get a single contact
  - **Inputs**:
    - `contact_id` (number, required): ID of the contact

- `search_contacts`: Search for contacts
  - **Inputs**:
    - `query` (string, required): Search query

- `update_contact`: Update a contact
  - **Inputs**:
    - `contact_id` (number, required): ID of the contact
    - `contact_fields` (object, required): Fields to update

- `list_companies`: Get all companies
  - **Inputs**:
    - `page` (number, optional): Page number
    - `per_page` (number, optional): Companies per page

- `view_company`: Get a single company
  - **Inputs**:
    - `company_id` (number, required): ID of the company

- `search_companies`: Search for companies
  - **Inputs**:
    - `query` (string, required): Search query

- `find_company_by_name`: Find a company by name
  - **Inputs**:
    - `name` (string, required): Company name

- `list_company_fields`: Get all company fields
  - **Inputs**:
    - None

## Getting Started

### Installing via Smithery

To install freshdesk_mcp for Claude Desktop automatically via [Smithery](https://smithery.ai/server/@effytech/freshdesk_mcp):

```bash
npx -y @smithery/cli install @effytech/freshdesk_mcp --client claude
```

### Prerequisites

- A Freshdesk account (sign up at [freshdesk.com](https://freshdesk.com))
- Freshdesk API key
- `uvx` installed (`pip install uv` or `brew install uv`)

### Configuration

1. Generate your Freshdesk API key from the Freshdesk admin panel
2. Set up your domain and authentication details

### Usage with Claude Desktop

1. Install Claude Desktop if you haven't already
2. Add the following configuration to your `claude_desktop_config.json`:

```json
"mcpServers": {
  "freshdesk-mcp": {
    "command": "uvx",
    "args": [
        "freshdesk-mcp"
    ],
    "env": {
      "FRESHDESK_API_KEY": "<YOUR_FRESHDESK_API_KEY>",
      "FRESHDESK_DOMAIN": "<YOUR_FRESHDESK_DOMAIN>"
    }
  }
}
```

**Important Notes**:
- Replace `YOUR_FRESHDESK_API_KEY` with your actual Freshdesk API key
- Replace `YOUR_FRESHDESK_DOMAIN` with your Freshdesk domain (e.g., `yourcompany.freshdesk.com`)

## Public deployment with per-user OAuth (Claude custom connector)

Besides the local stdio mode above, the server can run on a public HTTPS URL. There is then
**no central API key**: every user connects with their own Freshdesk API key through an
OAuth consent screen, and every tool call runs with that user's own Freshdesk permissions.

### How it works

1. An organisation Owner adds the server once as a custom connector in Claude, using the URL
   `https://<your-host>/mcp`. Claude registers itself automatically via Dynamic Client Registration.
2. Each member clicks **Connect**. Claude opens the server's consent page, where the member enters
   their Freshdesk API key (Freshdesk → profile picture → *Profile settings* → *View API key*).
3. The server checks the key with `GET /api/v2/agents/me`, then shows who is signed in and the domain
   the user will be redirected to (for example `claude.ai`). It also lists the user's existing
   connections, each with a **Revoke** button.
4. After **Approve**, Claude receives an access token (8 h) and a rotating refresh token (90 days,
   sliding). Claude never sees the API key.

Users can review and revoke their connections at any time at `https://<your-host>/grants`.
If a user regenerates their Freshdesk API key, the old connection is removed on its next failed
call and Claude asks them to reconnect.

### How the API keys are stored

Each connection is a file in `FRESHDESK_MCP_DATA_DIR/grants/`. The API key and all metadata
(redirect URI and domain, user name and email, date granted, date last used) are encrypted
with AES-256-GCM under a random per-connection data key. That data key is stored only in
wrapped (encrypted) form, under keys derived from:

- the OAuth access token and the refresh token (used on every MCP request and on token refresh);
- the Freshdesk API key itself, through scrypt (used when the user comes back to list or revoke
  their connections);
- the one-time authorization code, briefly, until Claude exchanges it.

Tokens and codes are never stored, not even as hashes. Every key derivation also mixes in
`FRESHDESK_MCP_SECRET`, so a copy of the data directory alone is not enough. Revoking a connection
deletes its file.

This protects the keys at rest (disk, backups). It does not protect against someone who can change
the code of the running server, because the server necessarily handles the key in memory while it
calls Freshdesk.

### Configuration

| Variable | Required | Description |
|---|---|---|
| `FRESHDESK_MCP_TRANSPORT` | yes | `http` (or pass `--transport http`) |
| `FRESHDESK_DOMAIN` | yes | Your Freshdesk domain, e.g. `yourcompany.freshdesk.com` (fixed for all users) |
| `PUBLIC_BASE_URL` | yes | Public HTTPS URL of the server, without a path, e.g. `https://freshdesk-mcp.example.com` |
| `FRESHDESK_MCP_SECRET` | yes | At least 32 random characters (`openssl rand -base64 48`). Keep it stable: changing it invalidates all connections |
| `FRESHDESK_MCP_DATA_DIR` | no | Grant store directory (default `./data`, `/data` in Docker). Must be persistent |
| `HOST` / `PORT` | no | Listen address (default `127.0.0.1:8000`, `0.0.0.0:8000` in Docker) |
| `ACCESS_TOKEN_TTL` / `REFRESH_TOKEN_TTL` | no | Seconds (default 28800 / 7776000) |
| `ALLOWED_REDIRECT_URIS` | no | Comma-separated OAuth redirect URIs that clients may register. The default is Claude's `https://claude.ai/api/mcp/auth_callback` and `https://claude.com/api/mcp/auth_callback`, plus `http://localhost/callback` and `http://127.0.0.1/callback` (any port) for Claude Code. Loopback redirects get a warning on the consent page |
| `FORWARDED_ALLOW_IPS` | no | IPs of the reverse proxy whose `X-Forwarded-*` headers are trusted (uvicorn) |

### Running with Docker behind a reverse proxy

See [`docker-compose.example.yml`](docker-compose.example.yml) for a complete example with Caddy
providing HTTPS:

```bash
cp docker-compose.example.yml docker-compose.yml   # edit domain and host names
export FRESHDESK_MCP_SECRET=$(openssl rand -base64 48)   # store it safely
docker compose up -d
```

Requirements:

- The URL configured in Claude must be exactly `PUBLIC_BASE_URL` + `/mcp`.
- The reverse proxy must pass `/mcp`, `/.well-known/*`, `/register`, `/authorize`, `/token`,
  `/revoke`, `/consent` and `/grants` through unchanged, including the `Host` header.
- Claude's servers connect from `160.79.104.0/21`. Users' browsers must also be able to reach the
  consent page.
- Run a single instance. Consent requests in progress are held in memory, so a restart only means
  a user who is on the consent page at that moment has to try again.

Then an organisation Owner adds a custom connector in Claude's admin settings (Connectors) with the URL
`https://<your-host>/mcp`, leaving the optional OAuth client ID and secret empty.

## Example Operations

Once configured, you can ask Claude to perform operations like:

- "Create a new ticket with subject 'Payment Issue for customer A101' and description as 'Reaching out for a payment issue in the last month for customer A101', where customer email is a101@acme.com and set priority to high"
- "Update the status of ticket #12345 to 'Resolved'"
- "List all high-priority tickets assigned to the agent John Doe"
- "List previous tickets of customer A101 in last 30 days"


## Testing

For testing purposes, you can start the server manually:

```bash
uvx freshdesk-mcp --env FRESHDESK_API_KEY=<your_api_key> --env FRESHDESK_DOMAIN=<your_domain>
```

Automated tests, including an end-to-end test of the OAuth flow with Freshdesk mocked:

```bash
uv run --group dev pytest
```

## Troubleshooting

- Verify your Freshdesk API key and domain are correct
- Ensure proper network connectivity to Freshdesk servers
- Check API rate limits and quotas
- Verify the `uvx` command is available in your PATH

## License

This MCP server is licensed under the MIT License. See the LICENSE file in the project repository for full details.
