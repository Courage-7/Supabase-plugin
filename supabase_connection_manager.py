"""Securely manage encrypted Supabase credentials for workflow backends."""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import socket
import sqlite3
import ssl
import sys
import urllib.error
import urllib.request
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from getpass import getpass
from pathlib import Path
from typing import Any, Final
from urllib.parse import urlsplit, urlunsplit

from cryptography.fernet import Fernet, InvalidToken


ENCRYPTION_KEY_ENV: Final = "WORKFLOW_CREDENTIAL_ENCRYPTION_KEY"
DEFAULT_DATABASE_PATH: Final = Path("workflow_connections.db")
DEFAULT_TIMEOUT_SECONDS: Final = 10.0
PROVIDER: Final = "supabase"


class SupabaseConnectionError(RuntimeError):
    """Base exception for connection validation and storage failures."""


class SupabaseCredentialError(SupabaseConnectionError):
    """Raised when stored credentials cannot be decrypted or located."""


@dataclass(frozen=True, slots=True)
class ConnectionTestResult:
    ok: bool
    message: str
    status_code: int
    project_url: str
    tested_at: str


@dataclass(frozen=True, slots=True)
class SupabaseConnectionRecord:
    id: str
    workspace_id: str
    provider: str
    name: str
    project_url: str
    schema_name: str
    key_hint: str
    status: str
    last_tested_at: str | None
    created_at: str
    updated_at: str


@dataclass(frozen=True, slots=True)
class SupabaseCredentials:
    """Internal runtime value. Never serialize this object into an API response."""

    project_url: str
    secret_key: str
    schema_name: str


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Prevent a user-controlled URL redirecting the backend to an internal host."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


class SupabaseConnectionManager:
    """Validate, encrypt, store, and retrieve Supabase connections.

    Workflow definitions should store only the returned connection ID. Only a
    trusted backend worker should call ``get_credentials`` or
    ``get_supabase_client``.
    """

    def __init__(
        self,
        database_path: str | Path = DEFAULT_DATABASE_PATH,
        *,
        encryption_key: str | bytes | None = None,
        allow_custom_domains: bool = False,
        allow_local_development: bool = False,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        key = encryption_key or os.getenv(ENCRYPTION_KEY_ENV)
        if not key:
            raise SupabaseCredentialError(
                f"Missing {ENCRYPTION_KEY_ENV}. Generate one with "
                "`python supabase_connection_manager.py generate-key` and store "
                "it in your backend secret manager."
            )

        try:
            self._cipher = Fernet(key.encode() if isinstance(key, str) else key)
        except (TypeError, ValueError) as exc:
            raise SupabaseCredentialError(
                f"{ENCRYPTION_KEY_ENV} is not a valid Fernet encryption key."
            ) from exc

        self.database_path = Path(database_path)
        self.allow_custom_domains = allow_custom_domains
        self.allow_local_development = allow_local_development
        self.timeout_seconds = timeout_seconds
        self._initialize_database()

    @staticmethod
    def generate_encryption_key() -> str:
        """Generate a key to store outside the application database."""

        return Fernet.generate_key().decode("ascii")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _initialize_database(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS workflow_connections (
                    id TEXT PRIMARY KEY,
                    workspace_id TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    name TEXT NOT NULL,
                    project_url TEXT NOT NULL,
                    schema_name TEXT NOT NULL,
                    encrypted_secret BLOB NOT NULL,
                    key_fingerprint TEXT NOT NULL,
                    key_hint TEXT NOT NULL,
                    status TEXT NOT NULL,
                    last_tested_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE (workspace_id, provider, name)
                )
                """
            )

    @staticmethod
    def _utc_now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _validate_schema_name(schema_name: str) -> str:
        candidate = schema_name.strip()
        if not candidate:
            raise SupabaseConnectionError("Schema name cannot be empty.")
        if not candidate.replace("_", "a").isalnum() or candidate[0].isdigit():
            raise SupabaseConnectionError(
                "Schema name may contain only letters, numbers, and underscores, "
                "and cannot begin with a number."
            )
        return candidate

    @staticmethod
    def _is_local_hostname(hostname: str) -> bool:
        return hostname in {"localhost", "127.0.0.1", "::1"} or hostname.endswith(
            ".localhost"
        )

    @staticmethod
    def _assert_public_destination(hostname: str, port: int) -> None:
        """Resolve a host and reject loopback, private, link-local, or reserved IPs."""

        try:
            addresses = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise SupabaseConnectionError(
                "The Supabase hostname could not be resolved."
            ) from exc

        if not addresses:
            raise SupabaseConnectionError("The Supabase hostname has no IP address.")

        for address_info in addresses:
            raw_ip = address_info[4][0]
            ip = ipaddress.ip_address(raw_ip)
            if not ip.is_global:
                raise SupabaseConnectionError(
                    "The project URL resolves to a private, local, or reserved address."
                )

    def normalize_project_url(self, project_url: str) -> str:
        """Normalize a project URL and apply an SSRF-oriented allow-list."""

        raw_url = project_url.strip().rstrip("/")
        parsed = urlsplit(raw_url)

        if not parsed.hostname:
            raise SupabaseConnectionError("A complete Supabase project URL is required.")
        if parsed.username or parsed.password:
            raise SupabaseConnectionError("Credentials must not be embedded in the URL.")
        if parsed.query or parsed.fragment:
            raise SupabaseConnectionError("Query strings and fragments are not allowed.")
        if parsed.path not in {"", "/"}:
            raise SupabaseConnectionError(
                "Use the project root URL, not a REST, Auth, Storage, or table URL."
            )

        try:
            port = parsed.port
        except ValueError as exc:
            raise SupabaseConnectionError(
                "The project URL contains an invalid port."
            ) from exc

    def _validate_project_url_destination(
        self, scheme: str, hostname: str, port: int | None
    ) -> None:
        if self._is_local_hostname(hostname):
            self._validate_local_project_url(scheme)
            return

        self._validate_hosted_project_url(scheme, hostname, port)

    def _validate_local_project_url(self, scheme: str) -> None:
        if not self.allow_local_development:
            raise SupabaseConnectionError(
                "Local Supabase URLs are disabled. Enable local development explicitly."
            )
        if scheme != "http":
            raise SupabaseConnectionError("Local Supabase should use an http URL.")

    def _validate_hosted_project_url(
        self, scheme: str, hostname: str, port: int | None
    ) -> None:
        if scheme != "https":
            raise SupabaseConnectionError("Hosted Supabase URLs must use HTTPS.")

        if not hostname.endswith(".supabase.co") and not self.allow_custom_domains:
            raise SupabaseConnectionError(
                "Only *.supabase.co URLs are allowed. Enable custom domains explicitly "
                "if your deployment requires them."
            )

        self._assert_public_destination(hostname, port or 443)

    def _build_normalized_project_url(
        self, scheme: str, hostname: str, port: int | None
    ) -> str:
        host = hostname
        if ":" in hostname and not hostname.startswith("["):
            host = f"[{hostname}]"
        netloc = f"{host}:{port}" if port else host
        return urlunsplit((scheme, netloc, "", "", ""))

    @staticmethod
    def _decode_legacy_key_role(secret_key: str) -> str | None:
        """Read an unverified legacy JWT role only for input-shape validation."""

        segments = secret_key.split(".")
        if len(segments) != 3:
            return None
        try:
            padded = segments[1] + "=" * (-len(segments[1]) % 4)
            payload = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            return None
        role = payload.get("role")
        return role if isinstance(role, str) else None

    @classmethod
    def validate_secret_key(cls, secret_key: str) -> str:
        """Accept modern secret keys and legacy service-role keys only."""

        candidate = secret_key.strip()
        if candidate.startswith("sb_publishable_"):
            raise SupabaseConnectionError(
                "A publishable key was supplied. This backend connector requires a "
                "dedicated server-side sb_secret_ key."
            )
        if candidate.startswith("sb_secret_") and len(candidate) >= 32:
            return candidate
        if cls._decode_legacy_key_role(candidate) == "service_role":
            return candidate
        raise SupabaseConnectionError(
            "Use a Supabase sb_secret_ key. A legacy service_role key is accepted "
            "temporarily for older projects."
        )

    @staticmethod
    def _key_fingerprint(secret_key: str) -> str:
        return hashlib.sha256(secret_key.encode("utf-8")).hexdigest()

    @staticmethod
    def _key_hint(secret_key: str) -> str:
        if secret_key.startswith("sb_secret_"):
            return f"sb_secret_…{secret_key[-4:]}"
        return f"service_role…{secret_key[-4:]}"

    def test_connection(
        self,
        project_url: str,
        secret_key: str,
    ) -> ConnectionTestResult:
        """Test the Data API without reading or modifying a user table."""

        normalized_url = self.normalize_project_url(project_url)
        validated_key = self.validate_secret_key(secret_key)
        tested_at = self._utc_now()
        request = urllib.request.Request(
            f"{normalized_url}/rest/v1/",
            method="GET",
            headers={
                "apikey": validated_key,
                "Accept": "application/openapi+json, application/json",
                "User-Agent": "workflow-supabase-connector/1.0",
            },
        )
        opener = urllib.request.build_opener(
            _NoRedirectHandler(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        )

        try:
            with opener.open(request, timeout=self.timeout_seconds) as response:
                status_code = int(response.status)
                response.read(1)
        except urllib.error.HTTPError as exc:
            status_code = int(exc.code)
            if 300 <= status_code < 400:
                message = "Supabase redirected the connection test; redirects are blocked."
            elif status_code in {401, 403}:
                message = "Supabase rejected the secret key."
            elif status_code == 404:
                message = "The Data API was not found; check the project URL and Data API settings."
            else:
                message = f"Supabase returned HTTP {status_code} during the connection test."
            raise SupabaseConnectionError(message) from exc
        except urllib.error.URLError as exc:
            reason = exc.reason
            if isinstance(reason, TimeoutError):
                message = "The Supabase connection test timed out."
            else:
                message = "The Supabase project could not be reached securely."
            raise SupabaseConnectionError(message) from exc
        except TimeoutError as exc:
            raise SupabaseConnectionError(
                "The Supabase connection test timed out."
            ) from exc

        if not 200 <= status_code < 300:
            raise SupabaseConnectionError(
                f"Unexpected HTTP {status_code} from the Supabase Data API."
            )

        return ConnectionTestResult(
            ok=True,
            message="Supabase connection successful.",
            status_code=status_code,
            project_url=normalized_url,
            tested_at=tested_at,
        )

    def create_connection(
        self,
        *,
        workspace_id: str,
        name: str,
        project_url: str,
        secret_key: str,
        schema_name: str = "public",
        test_before_save: bool = True,
    ) -> SupabaseConnectionRecord:
        """Validate, optionally test, encrypt, and store a connection."""

        workspace = workspace_id.strip()
        connection_name = name.strip()
        if not workspace:
            raise SupabaseConnectionError("workspace_id is required.")
        if not connection_name:
            raise SupabaseConnectionError("Connection name is required.")

        normalized_url = self.normalize_project_url(project_url)
        validated_key = self.validate_secret_key(secret_key)
        schema = self._validate_schema_name(schema_name)
        now = self._utc_now()

        if test_before_save:
            test_result = self.test_connection(normalized_url, validated_key)
            status = "connected"
            last_tested_at = test_result.tested_at
        else:
            status = "untested"
            last_tested_at = None

        connection_id = str(uuid.uuid4())
        encrypted_secret = self._cipher.encrypt(validated_key.encode("utf-8"))

        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO workflow_connections (
                        id, workspace_id, provider, name, project_url,
                        schema_name, encrypted_secret, key_fingerprint, key_hint,
                        status, last_tested_at, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        connection_id,
                        workspace,
                        PROVIDER,
                        connection_name,
                        normalized_url,
                        schema,
                        encrypted_secret,
                        self._key_fingerprint(validated_key),
                        self._key_hint(validated_key),
                        status,
                        last_tested_at,
                        now,
                        now,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise SupabaseConnectionError(
                "A Supabase connection with this name already exists in the workspace."
            ) from exc

        return self.get_connection(connection_id, workspace_id=workspace)

    def get_connection(
        self,
        connection_id: str,
        *,
        workspace_id: str,
    ) -> SupabaseConnectionRecord:
        """Return safe connection metadata without the secret key."""

        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT id, workspace_id, provider, name, project_url, schema_name,
                       key_hint, status, last_tested_at, created_at, updated_at
                FROM workflow_connections
                WHERE id = ? AND workspace_id = ? AND provider = ?
                """,
                (connection_id, workspace_id, PROVIDER),
            ).fetchone()
        if row is None:
            raise SupabaseCredentialError("Supabase connection not found.")
        return SupabaseConnectionRecord(**dict(row))

    def list_connections(self, *, workspace_id: str) -> list[SupabaseConnectionRecord]:
        """List safe metadata for one workspace."""

        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, workspace_id, provider, name, project_url, schema_name,
                       key_hint, status, last_tested_at, created_at, updated_at
                FROM workflow_connections
                WHERE workspace_id = ? AND provider = ?
                ORDER BY name COLLATE NOCASE
                """,
                (workspace_id, PROVIDER),
            ).fetchall()
        return [SupabaseConnectionRecord(**dict(row)) for row in rows]

    def get_credentials(
        self,
        connection_id: str,
        *,
        workspace_id: str,
    ) -> SupabaseCredentials:
        """Decrypt credentials for a trusted worker; never return them to a client."""

        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT project_url, schema_name, encrypted_secret
                FROM workflow_connections
                WHERE id = ? AND workspace_id = ? AND provider = ?
                """,
                (connection_id, workspace_id, PROVIDER),
            ).fetchone()
        if row is None:
            raise SupabaseCredentialError("Supabase connection not found.")

        try:
            secret_key = self._cipher.decrypt(row["encrypted_secret"]).decode("utf-8")
        except (InvalidToken, UnicodeDecodeError) as exc:
            raise SupabaseCredentialError(
                "The Supabase credential could not be decrypted. Verify the backend "
                "encryption key has not changed."
            ) from exc

        return SupabaseCredentials(
            project_url=row["project_url"],
            secret_key=secret_key,
            schema_name=row["schema_name"],
        )

    def get_supabase_client(self, connection_id: str, *, workspace_id: str) -> Any:
        """Create a supabase-py client for a trusted workflow worker.

        Install and pin ``supabase`` in the application's dependency lockfile.
        This lazy import keeps credential management usable without the SDK.
        """

        try:
            from supabase import Client, create_client
            from supabase.client import ClientOptions
        except ImportError as exc:
            raise SupabaseConnectionError(
                "Install the `supabase` package and pin it in your lockfile before "
                "calling get_supabase_client()."
            ) from exc

        credentials = self.get_credentials(
            connection_id,
            workspace_id=workspace_id,
        )
        client: Client = create_client(
            credentials.project_url,
            credentials.secret_key,
            options=ClientOptions(
                postgrest_client_timeout=self.timeout_seconds,
                storage_client_timeout=self.timeout_seconds,
                schema=credentials.schema_name,
            ),
        )
        return client

    def rotate_secret_key(
        self,
        connection_id: str,
        *,
        workspace_id: str,
        new_secret_key: str,
    ) -> SupabaseConnectionRecord:
        """Test and replace a stored key without changing the connection ID."""

        metadata = self.get_connection(connection_id, workspace_id=workspace_id)
        validated_key = self.validate_secret_key(new_secret_key)
        test_result = self.test_connection(metadata.project_url, validated_key)
        encrypted_secret = self._cipher.encrypt(validated_key.encode("utf-8"))
        now = self._utc_now()

        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE workflow_connections
                SET encrypted_secret = ?, key_fingerprint = ?, key_hint = ?,
                    status = 'connected', last_tested_at = ?, updated_at = ?
                WHERE id = ? AND workspace_id = ? AND provider = ?
                """,
                (
                    encrypted_secret,
                    self._key_fingerprint(validated_key),
                    self._key_hint(validated_key),
                    test_result.tested_at,
                    now,
                    connection_id,
                    workspace_id,
                    PROVIDER,
                ),
            )
            if cursor.rowcount != 1:
                raise SupabaseCredentialError("Supabase connection not found.")

        return self.get_connection(connection_id, workspace_id=workspace_id)


def _print_json(value: Any) -> None:
    if hasattr(value, "__dataclass_fields__"):
        value = asdict(value)
    elif isinstance(value, list):
        value = [asdict(item) for item in value]
    print(json.dumps(value, indent=2))


def _build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Test and store encrypted Supabase workflow connections."
    )
    parser.add_argument(
        "--database",
        default=str(DEFAULT_DATABASE_PATH),
        help="SQLite credential database path (default: workflow_connections.db).",
    )
    parser.add_argument(
        "--allow-custom-domains",
        action="store_true",
        help="Allow HTTPS custom domains after public-IP validation.",
    )
    parser.add_argument(
        "--allow-local-development",
        action="store_true",
        help="Allow localhost Supabase URLs for local development only.",
    )

    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("generate-key", help="Generate a backend encryption key.")

    test_parser = commands.add_parser("test", help="Test credentials without saving.")
    test_parser.add_argument("--url", help="Supabase project URL; prompted if omitted.")

    add_parser = commands.add_parser("add", help="Test and save a connection.")
    add_parser.add_argument("--workspace", default="local")
    add_parser.add_argument("--name", help="Connection name; prompted if omitted.")
    add_parser.add_argument("--url", help="Supabase project URL; prompted if omitted.")
    add_parser.add_argument("--schema", default="public")

    list_parser = commands.add_parser("list", help="List connection metadata.")
    list_parser.add_argument("--workspace", default="local")

    rotate_parser = commands.add_parser("rotate", help="Test and rotate a stored key.")
    rotate_parser.add_argument("connection_id")
    rotate_parser.add_argument("--workspace", default="local")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_cli_parser()
    args = parser.parse_args(argv)

    if args.command == "generate-key":
        print(SupabaseConnectionManager.generate_encryption_key())
        return 0

    try:
        manager = SupabaseConnectionManager(
            args.database,
            allow_custom_domains=args.allow_custom_domains,
            allow_local_development=args.allow_local_development,
        )

        if args.command == "test":
            project_url = args.url or input("Supabase project URL: ").strip()
            secret_key = getpass("Supabase secret API key: ")
            _print_json(manager.test_connection(project_url, secret_key))
            return 0

        if args.command == "add":
            name = args.name or input("Connection name: ").strip()
            project_url = args.url or input("Supabase project URL: ").strip()
            secret_key = getpass("Supabase secret API key: ")
            record = manager.create_connection(
                workspace_id=args.workspace,
                name=name,
                project_url=project_url,
                secret_key=secret_key,
                schema_name=args.schema,
            )
            _print_json(record)
            return 0

        if args.command == "list":
            _print_json(manager.list_connections(workspace_id=args.workspace))
            return 0

        if args.command == "rotate":
            secret_key = getpass("New Supabase secret API key: ")
            record = manager.rotate_secret_key(
                args.connection_id,
                workspace_id=args.workspace,
                new_secret_key=secret_key,
            )
            _print_json(record)
            return 0

    except SupabaseConnectionError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    parser.error("Unknown command.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
