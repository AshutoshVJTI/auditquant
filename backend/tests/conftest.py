import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.main import app
from app.services.store import store


@pytest.fixture()
def client(tmp_path):
    store.analyses.clear()
    settings.analysis_storage_path = str(tmp_path / "analysis")
    return TestClient(app)
