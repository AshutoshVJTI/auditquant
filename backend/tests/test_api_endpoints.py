from pathlib import Path

import app.api.multi_tool as multi_tool_module


def test_upload_and_get_results(client, tmp_path):
    solidity_file = tmp_path / "sample.sol"
    solidity_file.write_text("pragma solidity ^0.8.0; contract X {}", encoding="utf-8")

    with solidity_file.open("rb") as handle:
        response = client.post(
            "/api/analyze",
            files={"file": ("sample.sol", handle, "text/plain")},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "queued"
    analysis_id = payload["analysis_id"]
    assert analysis_id in multi_tool_module._analysis_store

    # analysis runs async so it will still be pending (202) when we poll immediately
    result_response = client.get(f"/api/analysis/{analysis_id}")
    assert result_response.status_code in (200, 202)


def test_upload_rejects_non_solidity(client, tmp_path):
    text_file = tmp_path / "notes.txt"
    text_file.write_text("hello", encoding="utf-8")

    with text_file.open("rb") as handle:
        response = client.post(
            "/api/analyze",
            files={"file": ("notes.txt", handle, "text/plain")},
        )

    assert response.status_code == 400
