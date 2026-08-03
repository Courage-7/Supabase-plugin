"""FastAPI entry point for the Supabase connection manager."""

from __future__ import annotations

from pathlib import Path

import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI

from supabase_routes import router as supabase_router


LOCAL_ENV_FILE = Path(__file__).resolve().with_name(".env")


def load_local_environment() -> None:
    """Load local backend settings without replacing host-provided values."""

    load_dotenv(dotenv_path=LOCAL_ENV_FILE, override=False)


def create_app() -> FastAPI:
    """Create the HTTP application and register its routes."""

    load_local_environment()
    application = FastAPI(
        title="Supabase Connection Manager",
        version="0.1.0",
        description="Backend-only API for testing and storing Supabase connections.",
    )
    application.include_router(supabase_router)

    @application.get("/health", tags=["health"])
    def health() -> dict[str, str]:
        return {"status": "ok"}

    return application


app = create_app()


def main() -> None:
    """Serve the API on the local development interface."""

    uvicorn.run(app, host="127.0.0.1", port=8000)


if __name__ == "__main__":
    main()
