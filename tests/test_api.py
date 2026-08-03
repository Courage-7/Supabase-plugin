from __future__ import annotations

import sqlite3
from dataclasses import replace
from pathlib import Path
from typing import Any, AsyncIterator
from uuid import UUID

import pytest
from cryptography.fernet import Fernet
from httpx2 import ASGITransport, AsyncClient

from main import create_app
from supabase_connection_manager import (
    ConnectionTestResult,
    SupabaseConnectionRecord,
    SupabaseConnectionManager,
    SupabaseCredentialError,
)
from supabase_routes import get_connection_manager


WORKSPACE_HEADERS = {"X-Workspace-ID": "workspace-1"}


class FakeConnectionManager:
    def __init__(self) -> None:
        self.record = SupabaseConnectionRecord(
            id="connection-1",
            workspace_id="workspace-1",
            provider="supabase",
            name="Production",
            project_url="https://example.supabase.co",
            schema_name="public",
            key_hint="sb_secret_…1234",
            status="connected",
            last_tested_at="2026-08-02T10:00:00+00:00",
            created_at="2026-08-02T10:00:00+00:00",
            updated_at="2026-08-02T10:00:00+00:00",
        )
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def test_connection(self, project_url: str, secret_key: str) -> ConnectionTestResult:
        self.calls.append(
            ("test", {"project_url": project_url, "secret_key": secret_key})
        )
        return ConnectionTestResult(
            ok=True,
            message="Supabase connection successful.",
            status_code=200,
            project_url=project_url,
            tested_at="2026-08-02T10:00:00+00:00",
        )

    def create_connection(self, **kwargs: Any) -> SupabaseConnectionRecord:
        self.calls.append(("create", kwargs))
        return replace(
            self.record,
            workspace_id=kwargs["workspace_id"],
            name=kwargs["name"],
            project_url=kwargs["project_url"],
            schema_name=kwargs["schema_name"],
        )

    def list_connections(self, *, workspace_id: str) -> list[SupabaseConnectionRecord]:
        self.calls.append(("list", {"workspace_id": workspace_id}))
        return [replace(self.record, workspace_id=workspace_id)]

    def get_connection(
        self,
        connection_id: str,
        *,
        workspace_id: str,
    ) -> SupabaseConnectionRecord:
        self.calls.append(
            (
                "get",
                {"connection_id": connection_id, "workspace_id": workspace_id},
            )
        )
        if connection_id == "missing":
            raise SupabaseCredentialError("Supabase connection not found.")
        return replace(self.record, id=connection_id, workspace_id=workspace_id)

    def rotate_secret_key(
        self,
        connection_id: str,
        *,
        workspace_id: str,
        new_secret_key: str,
    ) -> SupabaseConnectionRecord:
        self.calls.append(
            (
                "rotate",
                {
                    "connection_id": connection_id,
                    "workspace_id": workspace_id,
                    "new_secret_key": new_secret_key,
                },
            )
        )
        return replace(self.record, id=connection_id, workspace_id=workspace_id)


@pytest.fixture
def anyio_backend() -> tuple[str, dict[str, bool]]:
    return "asyncio", {"use_uvloop": True}


@pytest.fixture
async def api() -> AsyncIterator[tuple[AsyncClient, FakeConnectionManager]]:
    app = create_app()
    manager = FakeConnectionManager()

    def override_connection_manager() -> FakeConnectionManager:
        return manager

    app.dependency_overrides[get_connection_manager] = override_connection_manager
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client, manager


@pytest.mark.anyio
async def test_health(api: tuple[AsyncClient, FakeConnectionManager]) -> None:
    client, _ = api
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.anyio
async def test_credentials_can_be_tested_without_being_returned(
    api: tuple[AsyncClient, FakeConnectionManager],
) -> None:
    client, manager = api
    response = await client.post(
        "/api/v1/supabase/connections/test",
        json={
            "project_url": "https://example.supabase.co",
            "secret_key": "sb_secret_not_returned_1234567890",
        },
    )

    assert response.status_code == 200
    assert "sb_secret_not_returned_1234567890" not in response.text
    assert manager.calls[-1][1]["secret_key"] == "sb_secret_not_returned_1234567890"


@pytest.mark.anyio
async def test_create_uses_workspace_header_and_hides_secret(
    api: tuple[AsyncClient, FakeConnectionManager],
) -> None:
    client, manager = api
    response = await client.post(
        "/api/v1/supabase/connections",
        headers=WORKSPACE_HEADERS,
        json={
            "name": "Production",
            "project_url": "https://example.supabase.co",
            "secret_key": "sb_secret_not_returned_1234567890",
            "schema_name": "public",
        },
    )

    assert response.status_code == 201
    assert response.json()["workspace_id"] == "workspace-1"
    assert "sb_secret_not_returned_1234567890" not in response.text
    assert manager.calls[-1][1]["workspace_id"] == "workspace-1"


@pytest.mark.anyio
async def test_create_generates_workspace_id_when_header_is_missing(
    api: tuple[AsyncClient, FakeConnectionManager],
) -> None:
    client, manager = api
    response = await client.post(
        "/api/v1/supabase/connections",
        json={
            "name": "Production",
            "project_url": "https://example.supabase.co",
            "secret_key": "sb_secret_not_returned_1234567890",
            "schema_name": "public",
        },
    )

    assert response.status_code == 201
    workspace_id = response.json()["workspace_id"]
    assert UUID(workspace_id).version == 4
    assert manager.calls[-1][1]["workspace_id"] == workspace_id


@pytest.mark.anyio
async def test_create_rejects_explicitly_blank_workspace_header(
    api: tuple[AsyncClient, FakeConnectionManager],
) -> None:
    client, manager = api
    response = await client.post(
        "/api/v1/supabase/connections",
        headers={"X-Workspace-ID": " "},
        json={
            "name": "Production",
            "project_url": "https://example.supabase.co",
            "secret_key": "sb_secret_not_returned_1234567890",
            "schema_name": "public",
        },
    )

    assert response.status_code == 422
    assert response.json()["detail"] == "X-Workspace-ID cannot be blank."
    assert not any(call[0] == "create" for call in manager.calls)


@pytest.mark.anyio
async def test_create_endpoint_persists_encrypted_connection_in_sqlite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "api-connections.db"
    manager = SupabaseConnectionManager(
        database_path,
        encryption_key=Fernet.generate_key(),
        allow_local_development=True,
    )
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
    app = create_app()
    app.dependency_overrides[get_connection_manager] = lambda: manager

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        create_response = await client.post(
            "/api/v1/supabase/connections",
            json={
                "name": "Production",
                "project_url": "http://localhost:54321",
                "secret_key": secret_key,
                "schema_name": "public",
            },
        )
        assert create_response.status_code == 201
        response_body = create_response.json()
        workspace_id = response_body["workspace_id"]
        assert UUID(workspace_id).version == 4
        assert secret_key not in create_response.text

        list_response = await client.get(
            "/api/v1/supabase/connections",
            headers={"X-Workspace-ID": workspace_id},
        )

    assert list_response.status_code == 200
    assert [item["id"] for item in list_response.json()] == [response_body["id"]]
    with sqlite3.connect(database_path) as connection:
        row = connection.execute(
            """
            SELECT workspace_id, encrypted_secret
            FROM workflow_connections
            WHERE id = ?
            """,
            (response_body["id"],),
        ).fetchone()

    assert row is not None
    assert row[0] == workspace_id
    assert secret_key.encode("utf-8") not in row[1]
    assert manager.get_credentials(
        response_body["id"],
        workspace_id=workspace_id,
    ).secret_key == secret_key


@pytest.mark.anyio
async def test_stored_connection_routes_require_workspace_header(
    api: tuple[AsyncClient, FakeConnectionManager],
) -> None:
    client, _ = api
    response = await client.get("/api/v1/supabase/connections")
    assert response.status_code == 422


@pytest.mark.anyio
async def test_list_and_get_are_scoped_to_workspace(
    api: tuple[AsyncClient, FakeConnectionManager],
) -> None:
    client, manager = api

    list_response = await client.get(
        "/api/v1/supabase/connections",
        headers=WORKSPACE_HEADERS,
    )
    get_response = await client.get(
        "/api/v1/supabase/connections/connection-2",
        headers=WORKSPACE_HEADERS,
    )

    assert list_response.status_code == 200
    assert len(list_response.json()) == 1
    assert get_response.status_code == 200
    assert get_response.json()["id"] == "connection-2"
    assert manager.calls[-1][1]["workspace_id"] == "workspace-1"


@pytest.mark.anyio
async def test_missing_connection_returns_404(
    api: tuple[AsyncClient, FakeConnectionManager],
) -> None:
    client, _ = api
    response = await client.get(
        "/api/v1/supabase/connections/missing",
        headers=WORKSPACE_HEADERS,
    )
    assert response.status_code == 404


@pytest.mark.anyio
async def test_rotate_passes_new_secret_without_returning_it(
    api: tuple[AsyncClient, FakeConnectionManager],
) -> None:
    client, manager = api
    response = await client.put(
        "/api/v1/supabase/connections/connection-1/secret",
        headers=WORKSPACE_HEADERS,
        json={"secret_key": "sb_secret_rotated_123456789012345"},
    )

    assert response.status_code == 200
    assert "sb_secret_rotated_123456789012345" not in response.text
    assert manager.calls[-1][1]["new_secret_key"] == (
        "sb_secret_rotated_123456789012345"
    )
