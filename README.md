# Supabase Connection Manager

Backend-only FastAPI service for testing, encrypting, and storing Supabase
connections. SQLite is the local credential store for this phase; clients keep
only the returned connection and workspace IDs.

It includes:
- Supabase secret-key and project-URL validation
- Connection testing before persistence
- Fernet encryption at rest
- SQLite storage in `workflow_connections.db`
- Workspace-scoped connection listing and retrieval
- Secret-key rotation without returning plaintext keys
- SSRF and redirect protection.

## Local setup

Install the locked dependencies:

```powershell
uv sync
```

Generate a persistent backend encryption key:

```powershell
uv run python supabase_connection_manager.py generate-key
```

Store the generated value in the ignored `.env` file:

```dotenv
WORKFLOW_CREDENTIAL_ENCRYPTION_KEY="replace-with-the-generated-key"
# Optional: WORKFLOW_CONNECTION_DATABASE="workflow_connections.db"
```

The API loads this local `.env` automatically and does not replace environment
variables already supplied by the host. Start it with:

```powershell
uv run uvicorn main:app --reload
```

## Create and save a connection

`POST /api/v1/supabase/connections` tests the credentials, encrypts the secret,
commits the record to SQLite, and returns `201 Created`. The workspace header is
optional on this endpoint:

- Omit `X-Workspace-ID` to generate a new workspace UUID.
- Supply a nonblank `X-Workspace-ID` to add the connection to an existing
  workspace.
- An explicitly blank header returns `422` and nothing is saved.

The response includes `id` and `workspace_id`, but never includes `secret_key`.
Persist the returned `workspace_id` in the caller and send it on later requests:

```http
GET /api/v1/supabase/connections
X-Workspace-ID: returned-workspace-id
```

Listing, retrieving, and rotating stored connections continue to require the
workspace header. If credential testing or storage configuration fails, the
connection is not inserted.

## List tables in the stored schema

Use the connection ID and its workspace ID to discover the table-like resources
exposed through the Supabase Data API:

```http
GET /api/v1/supabase/connections/connection-id/tables
X-Workspace-ID: returned-workspace-id
```

The response includes the connection, workspace, and schema identifiers plus a
sorted `tables` array. PostgREST exposes tables, foreign tables, and views through
the same resource paths, so views can also appear in this list. RPC functions are
excluded. Tables that exist in Postgres but are not exposed or granted to the
stored key do not appear.

## Storage notes

The default database path is `workflow_connections.db`, relative to the server's
working directory. Set `WORKFLOW_CONNECTION_DATABASE` to use another SQLite
path. Keep `WORKFLOW_CREDENTIAL_ENCRYPTION_KEY` stable: changing or losing it
makes existing encrypted credentials unreadable.

For production, use a backend secret manager for the encryption key and derive
workspace scope from authenticated tenant context instead of trusting a public
client header.
