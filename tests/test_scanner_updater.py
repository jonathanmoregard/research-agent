"""The boot updater must honor an immutable installed scanner revision."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import mcp_server.server as srv


class _Dist:
    def __init__(self, metadata_path):
        self._metadata_path = metadata_path
        self.files = [Path("injection_scanner-0.1.0.dist-info/direct_url.json")]

    def locate_file(self, _relative):
        return self._metadata_path


def _install_metadata(monkeypatch, tmp_path, *, revision, commit):
    metadata_path = tmp_path / "direct_url.json"
    metadata_path.write_text(
        json.dumps(
            {
                "vcs_info": {
                    "requested_revision": revision,
                    "commit_id": commit,
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "importlib.metadata.distribution",
        lambda name: _Dist(metadata_path),
    )


def test_configured_scanner_sha_reads_matching_immutable_metadata(
    monkeypatch, tmp_path
):
    sha = "d63b010127feab20ebad62b5867329cc80be4d66"
    _install_metadata(monkeypatch, tmp_path, revision=sha, commit=sha)

    assert srv._configured_scanner_sha() == sha


@pytest.mark.parametrize(
    "revision,commit",
    [
        ("main", "d63b010127feab20ebad62b5867329cc80be4d66"),
        ("d63b0101", "d63b010127feab20ebad62b5867329cc80be4d66"),
        (
            "d63b010127feab20ebad62b5867329cc80be4d66",
            "3386de819bda6ace20d8d45a74255959fd5c1ee9",
        ),
        ("z" * 40, "z" * 40),
    ],
)
def test_configured_scanner_sha_rejects_mutable_mismatched_or_invalid_metadata(
    monkeypatch, tmp_path, revision, commit
):
    _install_metadata(monkeypatch, tmp_path, revision=revision, commit=commit)

    assert srv._configured_scanner_sha() is None


def test_target_resolution_never_queries_main_for_an_immutable_install(monkeypatch):
    sha = "d63b010127feab20ebad62b5867329cc80be4d66"
    monkeypatch.setattr(srv, "_configured_scanner_sha", lambda: sha)
    monkeypatch.setattr(
        srv,
        "_resolve_scanner_remote_sha",
        lambda _log: pytest.fail("immutable install must not resolve main"),
    )

    assert srv._resolve_scanner_target_sha(object()) == sha
