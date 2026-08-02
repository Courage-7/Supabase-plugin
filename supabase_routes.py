"""FastAPI routes for managing encrypted Supabase connections."""

from __future__ import annotations

import asyncio
import os
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from functools import lru_cache, partial
from typing import Annotated, Any, TypeVar

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field, SecretStr

from supabase_connection_manager import (
    DEFAULT_DATABASE_PATH,
    ConnectionTestResult,
    SupabaseConnectionError,
    SupabaseConnectionManager,
    SupabaseConnectionRecord,
    SupabaseCredentialError,
)


DATABASE_PATH_ENV = "WORKFLOW_CONNECTION_DATABASE"
ResultType = TypeVar("ResultType")
_MANAGER_EXECUTOR = ThreadPoolExecutor(
    max_workers=8,
    thread_name_prefix="supabase-connections",
)


class RequestModel(BaseModel):
    """Reject unexpected request properties instead of silently ignoring them."""

    model_config = ConfigDict(extra="forbid")


class ConnectionTestRequest(RequestModel):
    project_url: str = Field(min_length=1, max_length=2048)
    secret_key: SecretStr


class CreateConnectionRequest(ConnectionTestRequest):
    name: str = Field(min_length=1, max_length=128)
    schema_name: str = Field(default="public", min_length=1, max_length=63)


class RotateSecretRequest(RequestModel):
    secret_key: SecretStr


class ConnectionTestResponse(BaseModel):
    ok: bool
    message: str
    status_code: int
    project_url: str
    tested_at: str


class ConnectionResponse(BaseModel):
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


@lru_cache(maxsize=1)
def _build_connection_manager() -> SupabaseConnectionManager:
    database_path = os.getenv(DATABASE_PATH_ENV, str(DEFAULT_DATABASE_PATH))
    return SupabaseConnectionManager(database_path)


async def _run_blocking(
    function: Callable[..., ResultType],
    /,
    *args: Any,
    **kwargs: Any,
) -> ResultType:
    """Run blocking SQLite and HTTP work outside the ASGI event loop."""

    loop = asyncio.get_running_loop()
    call = partial(function, *args, **kwargs)
    return await loop.run_in_executor(_MANAGER_EXECUTOR, call)


async def get_connection_manager() -> SupabaseConnectionManager:
    """Build one process-local manager from backend environment settings."""

    try:
        manager = await _run_blocking(_build_connection_manager)
    except SupabaseCredentialError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Credential storage is not configured.",
        ) from exc
    return manager


async def get_workspace_id(
    x_workspace_id: Annotated[str, Header(alias="X-Workspace-ID", min_length=1)],
) -> str:
    """Read the caller's workspace scope supplied by the trusted backend."""

    workspace_id = x_workspace_id.strip()
    if not workspace_id:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="X-Workspace-ID cannot be blank.",
        )
    return workspace_id


ManagerDependency = Annotated[SupabaseConnectionManager, Depends(get_connection_manager)]
WorkspaceDependency = Annotated[str, Depends(get_workspace_id)]


router = APIRouter(
    prefix="/api/v1/supabase/connections",
    tags=["supabase-connections"],
)


def _test_response(result: ConnectionTestResult) -> ConnectionTestResponse:
    return ConnectionTestResponse(**asdict(result))


def _connection_response(record: SupabaseConnectionRecord) -> ConnectionResponse:
    return ConnectionResponse(**asdict(record))


def _raise_bad_request(exc: SupabaseConnectionError) -> None:
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=str(exc),
    ) from exc


@router.post("/test", response_model=ConnectionTestResponse)
async def test_connection(
    request: ConnectionTestRequest,
    manager: ManagerDependency,
) -> ConnectionTestResponse:
    """Validate credentials without storing them."""

    try:
        result = await _run_blocking(
            manager.test_connection,
            request.project_url,
            request.secret_key.get_secret_value(),
        )
    except SupabaseConnectionError as exc:
        _raise_bad_request(exc)
    return _test_response(result)


@router.post("", response_model=ConnectionResponse, status_code=status.HTTP_201_CREATED)
async def create_connection(
    request: CreateConnectionRequest,
    workspace_id: WorkspaceDependency,
    manager: ManagerDependency,
) -> ConnectionResponse:
    """Test, encrypt, and store a connection in one workspace."""

    try:
        record = await _run_blocking(
            manager.create_connection,
            workspace_id=workspace_id,
            name=request.name,
            project_url=request.project_url,
            secret_key=request.secret_key.get_secret_value(),
            schema_name=request.schema_name,
        )
    except SupabaseConnectionError as exc:
        _raise_bad_request(exc)
    return _connection_response(record)


@router.get("", response_model=list[ConnectionResponse])
async def list_connections(
    workspace_id: WorkspaceDependency,
    manager: ManagerDependency,
) -> list[ConnectionResponse]:
    """List non-secret connection metadata for one workspace."""

    records = await _run_blocking(
        manager.list_connections,
        workspace_id=workspace_id,
    )
    return [_connection_response(record) for record in records]


@router.get("/{connection_id}", response_model=ConnectionResponse)
async def get_connection(
    connection_id: str,
    workspace_id: WorkspaceDependency,
    manager: ManagerDependency,
) -> ConnectionResponse:
    """Return non-secret metadata for one workspace connection."""

    try:
        record = await _run_blocking(
            manager.get_connection,
            connection_id,
            workspace_id=workspace_id,
        )
    except SupabaseCredentialError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Supabase connection not found.",
        ) from exc
    return _connection_response(record)


@router.put("/{connection_id}/secret", response_model=ConnectionResponse)
async def rotate_secret_key(
    connection_id: str,
    request: RotateSecretRequest,
    workspace_id: WorkspaceDependency,
    manager: ManagerDependency,
) -> ConnectionResponse:
    """Test and replace a connection's secret without changing its ID."""

    try:
        record = await _run_blocking(
            manager.rotate_secret_key,
            connection_id,
            workspace_id=workspace_id,
            new_secret_key=request.secret_key.get_secret_value(),
        )
    except SupabaseCredentialError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Supabase connection not found.",
        ) from exc
    except SupabaseConnectionError as exc:
        _raise_bad_request(exc)
    return _connection_response(record)
