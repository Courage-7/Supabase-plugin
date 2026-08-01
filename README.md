# Supabase Connection Manager

This handles the backend connection lifecycle, but it does not create the frontend credentials form; that form should submit credentials to this module and store only the returned `connection_id`.

[Download the Python script](sandbox:/workspace/scratch/3d9970b078fe/supabase_connection_manager.py)

It includes:

- Secret-key and project-URL validation
- Supabase connection testing
- Fernet encryption at rest
- SQLite storage for an MVP
- Workspace-level connection isolation
- Safe connection listing without exposing keys
- Key rotation
- Reusable `get_supabase_client()` method
- SSRF and redirect protection
- CLI commands for testing

## Run it on Windows

```powershell
uv add cryptography supabase
```

Generate your encryption key:

```powershell
uv run python supabase_connection_manager.py generate-key
```

Set the generated key:

```powershell
$env:WORKFLOW_CREDENTIAL_ENCRYPTION_KEY = AEu1jPsXNhGV6SqGelM5jGhf7EbDr5cDk1BywHPVXqI
```

Test credentials without saving:

```powershell
uv run python supabase_connection_manager.py test
```

Save a tested connection:

```powershell
uv run python supabase_connection_manager.py add
```

List saved connections:

```powershell
uv run python supabase_connection_manager.py list
```

The Supabase key is requested through a hidden terminal prompt and never supplied as a command argument.
