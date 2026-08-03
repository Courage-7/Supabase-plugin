from __future__ import annotations

import json
import sqlite3
import ssl
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest
from cryptography.fernet import Fernet

import supabase_connection_manager as manager_module
from supabase_connection_manager import (
    ENCRYPTION_KEY_ENV,
    ConnectionTestResult,
    SupabaseConnectionError,
    SupabaseConnectionManager,
    SupabaseCredentialError,
)


@pytest.fixture
def manager(tmp_path: Path) -> SupabaseConnectionManager:
    return SupabaseConnectionManager(
        tmp_path / "connections.db",
        encryption_key=Fernet.generate_key(),
        allow_local_development=True,
    )


def test_normalize_project_url_returns_validated_url(
    manager: SupabaseConnectionManager,
) -> None:
    assert manager.normalize_project_url("http://LOCALHOST.:54321/") == (
        "http://localhost:54321"
    )


@pytest.mark.parametrize(
    "project_url",
    [
        "http://localhost:not-a-port",
        "http://localhost:0",
        "http://localhost:65536",
    ],
)
def test_normalize_project_url_rejects_malformed_ports(
    manager: SupabaseConnectionManager,
    project_url: str,
) -> None:
    with pytest.raises(SupabaseConnectionError, match="invalid port"):
        manager.normalize_project_url(project_url)


def test_normalize_project_url_accepts_hosted_supabase_domain(
    manager: SupabaseConnectionManager,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checked_destinations: list[tuple[str, int]] = []

    def record_destination(hostname: str, port: int) -> None:
        checked_destinations.append((hostname, port))

    monkeypatch.setattr(manager, "_assert_public_destination", record_destination)

    assert manager.normalize_project_url("https://Example.Supabase.Co/") == (
        "https://example.supabase.co"
    )
    assert checked_destinations == [("example.supabase.co", 443)]


def test_normalize_project_url_requires_custom_domain_opt_in(
    manager: SupabaseConnectionManager,
) -> None:
    with pytest.raises(SupabaseConnectionError, match=r"Only \*\.supabase\.co"):
        manager.normalize_project_url("https://database.example.com")


def test_normalize_project_url_accepts_opted_in_public_custom_domain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager = SupabaseConnectionManager(
        tmp_path / "custom-connections.db",
        encryption_key=Fernet.generate_key(),
        allow_custom_domains=True,
    )
    checked_destinations: list[tuple[str, int]] = []

    def record_destination(hostname: str, port: int) -> None:
        checked_destinations.append((hostname, port))

    monkeypatch.setattr(manager, "_assert_public_destination", record_destination)

    assert manager.normalize_project_url("https://database.example.com:8443/") == (
        "https://database.example.com:8443"
    )
    assert checked_destinations == [("database.example.com", 8443)]


def test_validate_secret_key_rejects_malformed_legacy_payload(
    manager: SupabaseConnectionManager,
) -> None:
    with pytest.raises(SupabaseConnectionError, match="sb_secret_"):
        manager.validate_secret_key("header.@@@.signature")


def test_ssl_context_requires_authenticated_tls_1_2_or_newer(
    manager: SupabaseConnectionManager,
) -> None:
    context = manager._create_ssl_context()

    assert context.protocol == ssl.PROTOCOL_TLS_CLIENT
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2


def test_create_connection_encrypts_and_persists_credentials_in_sqlite(
    manager: SupabaseConnectionManager,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_key = "sb_secret_" + "a" * 32

    def successful_test(project_url: str, supplied_key: str) -> ConnectionTestResult:
        assert supplied_key == secret_key
        return ConnectionTestResult(
            ok=True,
            message="Supabase connection successful.",
            status_code=200,
            project_url=project_url,
            tested_at="2026-08-03T12:00:00+00:00",
        )

    monkeypatch.setattr(manager, "test_connection", successful_test)

    record = manager.create_connection(
        workspace_id="workspace-1",
        name="Production",
        project_url="http://localhost:54321",
        secret_key=secret_key,
    )

    with sqlite3.connect(manager.database_path) as connection:
        row = connection.execute(
            """
            SELECT workspace_id, encrypted_secret
            FROM workflow_connections
            WHERE id = ?
            """,
            (record.id,),
        ).fetchone()

    assert row is not None
    assert row[0] == "workspace-1"
    assert isinstance(row[1], bytes)
    assert secret_key.encode("utf-8") not in row[1]
    assert manager.get_credentials(
        record.id,
        workspace_id="workspace-1",
    ).secret_key == secret_key
    assert manager.list_connections(workspace_id="workspace-1") == [record]


def test_failed_connection_test_does_not_insert_sqlite_row(
    manager: SupabaseConnectionManager,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def failed_test(project_url: str, secret_key: str) -> ConnectionTestResult:
        raise SupabaseConnectionError("Supabase rejected the secret key.")

    monkeypatch.setattr(manager, "test_connection", failed_test)

    with pytest.raises(SupabaseConnectionError, match="rejected"):
        manager.create_connection(
            workspace_id="workspace-1",
            name="Production",
            project_url="http://localhost:54321",
            secret_key="sb_secret_" + "a" * 32,
        )

    with sqlite3.connect(manager.database_path) as connection:
        row_count = connection.execute(
            "SELECT COUNT(*) FROM workflow_connections"
        ).fetchone()[0]

    assert row_count == 0


def test_missing_encryption_configuration_does_not_create_sqlite_database(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "unconfigured.db"
    monkeypatch.delenv(ENCRYPTION_KEY_ENV, raising=False)

    with pytest.raises(SupabaseCredentialError, match=ENCRYPTION_KEY_ENV):
        SupabaseConnectionManager(database_path)

    assert not database_path.exists()


class FakeOpenAPIResponse:
    def __init__(self, payload: bytes, *, status: int = 200) -> None:
        self.payload = payload
        self.status = status

    def __enter__(self) -> FakeOpenAPIResponse:
        return self

    def __exit__(self, *args: Any) -> None:
        return None

    def read(self, limit: int) -> bytes:
        return self.payload[:limit]


class FakeOpenAPIOpener:
    def __init__(self, response: FakeOpenAPIResponse) -> None:
        self.response = response
        self.request: urllib.request.Request | None = None
        self.timeout: float | None = None

    def open(
        self,
        request: urllib.request.Request,
        *,
        timeout: float,
    ) -> FakeOpenAPIResponse:
        self.request = request
        self.timeout = timeout
        return self.response


def test_list_tables_uses_stored_schema_and_excludes_rpc_resources(
    manager: SupabaseConnectionManager,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_key = "sb_secret_" + "a" * 32
    record = manager.create_connection(
        workspace_id="workspace-1",
        name="Production",
        project_url="http://localhost:54321",
        secret_key=secret_key,
        schema_name="reporting",
        test_before_save=False,
    )
    payload = json.dumps(
        {
            "swagger": "2.0",
            "paths": {
                "/orders": {"get": {}},
                "/Customers": {"get": {}},
                "/customers": {"head": {}},
                "/sales%20summary": {"get": {}},
                "/rpc/search_orders": {"post": {}},
                "/nested/resource": {"get": {}},
                "/ignored": {"parameters": []},
                "/": {},
            },
        }
    ).encode("utf-8")
    opener = FakeOpenAPIOpener(FakeOpenAPIResponse(payload))
    monkeypatch.setattr(
        urllib.request,
        "build_opener",
        lambda *handlers: opener,
    )

    with pytest.raises(SupabaseCredentialError, match="not found"):
        manager.list_tables(record.id, workspace_id="workspace-2")
    assert opener.request is None

    tables = manager.list_tables(record.id, workspace_id="workspace-1")

    assert tables == ["Customers", "customers", "orders", "sales summary"]
    assert opener.request is not None
    headers = {name.lower(): value for name, value in opener.request.header_items()}
    assert opener.request.full_url == "http://localhost:54321/rest/v1/"
    assert headers["apikey"] == secret_key
    assert headers["accept"] == "application/openapi+json"
    assert headers["accept-profile"] == "reporting"
    assert opener.timeout == manager.timeout_seconds


def test_list_tables_rejects_invalid_openapi_response(
    manager: SupabaseConnectionManager,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = manager.create_connection(
        workspace_id="workspace-1",
        name="Production",
        project_url="http://localhost:54321",
        secret_key="sb_secret_" + "a" * 32,
        test_before_save=False,
    )
    opener = FakeOpenAPIOpener(FakeOpenAPIResponse(b"not-json"))
    monkeypatch.setattr(
        urllib.request,
        "build_opener",
        lambda *handlers: opener,
    )

    with pytest.raises(SupabaseConnectionError, match="invalid schema description"):
        manager.list_tables(record.id, workspace_id="workspace-1")


def test_list_tables_reports_unexposed_schema(
    manager: SupabaseConnectionManager,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = manager.create_connection(
        workspace_id="workspace-1",
        name="Production",
        project_url="http://localhost:54321",
        secret_key="sb_secret_" + "a" * 32,
        schema_name="private_reporting",
        test_before_save=False,
    )

    class ErrorOpener:
        def open(self, request: urllib.request.Request, *, timeout: float) -> None:
            raise urllib.error.HTTPError(
                request.full_url,
                406,
                "Not Acceptable",
                hdrs=None,
                fp=None,
            )

    monkeypatch.setattr(
        urllib.request,
        "build_opener",
        lambda *handlers: ErrorOpener(),
    )

    with pytest.raises(SupabaseConnectionError, match="not exposed"):
        manager.list_tables(record.id, workspace_id="workspace-1")


def test_list_tables_rejects_oversized_openapi_response(
    manager: SupabaseConnectionManager,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = manager.create_connection(
        workspace_id="workspace-1",
        name="Production",
        project_url="http://localhost:54321",
        secret_key="sb_secret_" + "a" * 32,
        test_before_save=False,
    )
    monkeypatch.setattr(manager_module, "MAX_OPENAPI_SPEC_BYTES", 10)
    opener = FakeOpenAPIOpener(FakeOpenAPIResponse(b"x" * 11))
    monkeypatch.setattr(
        urllib.request,
        "build_opener",
        lambda *handlers: opener,
    )

    with pytest.raises(SupabaseConnectionError, match="too large"):
        manager.list_tables(record.id, workspace_id="workspace-1")
