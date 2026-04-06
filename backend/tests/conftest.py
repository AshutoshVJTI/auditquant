import pytest
from fastapi.testclient import TestClient

import app.api.multi_tool as multi_tool_module
from app.config import settings
from app.main import app


@pytest.fixture()
def client(tmp_path):
    multi_tool_module._analysis_store.clear()
    settings.analysis_storage_path = str(tmp_path / "analysis")
    return TestClient(app)
