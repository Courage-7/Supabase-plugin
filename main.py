"""FastAPI entry point for the Supabase connection manager."""

from __future__ import annotations

import uvicorn
from fastapi import FastAPI

from supabase_routes import router as supabase_router


def create_app() -> FastAPI:
    """Create the HTTP application and register its routes."""

    application = FastAPI(
        title="Supabase Connection Manager",
        version="0.1.0",
        description="Backend-only API for testing and storing Supabase connections.",
    )
    application.include_router(supabase_router)

    @application.get("/health", tags=["health"])
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    return application


app = create_app()


def main() -> None:
    """Serve the API on the local development interface."""

    uvicorn.run(app, host="127.0.0.1", port=8000)


if __name__ == "__main__":
    main()
