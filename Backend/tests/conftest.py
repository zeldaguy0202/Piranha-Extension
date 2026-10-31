import os

os.environ["DATABASE_URL"] = "sqlite://"
os.environ.pop("URLHAUS_AUTH_KEY", None)
os.environ["HIBP_API_KEY"] = ""
os.environ["VIRUSTOTAL_API_KEY"] = ""
os.environ["PHISHTANK_ENABLED"] = "false"

import pytest
from fastapi.testclient import TestClient

from app.database import Base, engine
from app.main import app, report_attempts


@pytest.fixture(autouse=True)
def clean_database():
    report_attempts.clear()
    Base.metadata.create_all(engine)
    yield
    Base.metadata.drop_all(engine)


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def anyio_backend():
    return "asyncio"
