from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from supabase_connection_manager import (
    SupabaseConnectionError,
    SupabaseConnectionManager,
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
    assert manager.normalize_project_url("http://localhost:54321/") == (
        "http://localhost:54321"
    )


def test_normalize_project_url_rejects_invalid_port(
    manager: SupabaseConnectionManager,
) -> None:
    with pytest.raises(SupabaseConnectionError, match="invalid port"):
        manager.normalize_project_url("http://localhost:0")
