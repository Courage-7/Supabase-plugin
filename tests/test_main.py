from __future__ import annotations

import os
from pathlib import Path

import pytest

import main


def test_local_environment_is_loaded_without_overriding_host_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "TEST_AUTO_LOADED_SETTING=from-file\n"
        "TEST_HOST_SETTING=from-file\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(main, "LOCAL_ENV_FILE", env_file)
    monkeypatch.delenv("TEST_AUTO_LOADED_SETTING", raising=False)
    monkeypatch.setenv("TEST_HOST_SETTING", "from-host")

    main.load_local_environment()

    assert os.getenv("TEST_AUTO_LOADED_SETTING") == "from-file"
    assert os.getenv("TEST_HOST_SETTING") == "from-host"
