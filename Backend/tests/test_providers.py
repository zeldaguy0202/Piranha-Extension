import httpx
import pytest
from app.config import Settings
from app.providers import check_virustotal


class FakeClient:
    def __init__(self, response):
        self.response = response

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return None

    async def get(self, *_args, **_kwargs):
        return self.response


@pytest.mark.anyio
async def test_virustotal_consensus_is_malicious(monkeypatch):
    request = httpx.Request("GET", "https://www.virustotal.com/api/v3/urls/test")
    response = httpx.Response(200, request=request, json={"data": {"attributes": {"last_analysis_stats": {"malicious": 3, "suspicious": 1}}}})
    monkeypatch.setattr("app.providers.httpx.AsyncClient", lambda **_: FakeClient(response))
    evidence, provider = await check_virustotal("https://example.test/", Settings(virustotal_api_key="test-key"))
    assert evidence["category"] == "malware"
    assert evidence["score"] == 100
    assert provider["status"] == "checked"


@pytest.mark.anyio
async def test_virustotal_does_not_submit_unknown_url(monkeypatch):
    request = httpx.Request("GET", "https://www.virustotal.com/api/v3/urls/test")
    response = httpx.Response(404, request=request)
    monkeypatch.setattr("app.providers.httpx.AsyncClient", lambda **_: FakeClient(response))
    evidence, provider = await check_virustotal("https://unknown.example/", Settings(virustotal_api_key="test-key"))
    assert evidence is None
    assert "not submitted" in provider["detail"]
