def test_health(client):
    assert client.get("/health").json()["status"] == "ok"


def test_dashboard_home_and_private_stats(client):
    page = client.get("/")
    assert page.status_code == 200
    assert "Piranha Security Portal" in page.text
    stats = client.get("/api/dashboard/stats")
    assert stats.status_code == 200
    body = stats.json()
    assert body["reports"] == 0
    assert "recent_threats" in body
    assert "email" not in str(body).lower()


def test_password_test_page(client):
    response = client.get("/test/password")
    assert response.status_code == 200
    assert 'autocomplete="new-password"' in response.text


def test_scan_normalizes_and_does_not_claim_safe(client):
    response = client.post("/api/scan", json={"url": "Example.COM#tracking"})
    assert response.status_code == 200
    body = response.json()
    assert body["normalized_url"] == "https://example.com/"
    assert body["verdict"] == "unknown"
    assert body["providers"][0]["status"] == "not_configured"


def test_scan_rejects_dangerous_schemes_and_credentials(client):
    assert client.post("/api/scan", json={"url": "file:///etc/passwd"}).status_code == 422
    assert client.post("/api/scan", json={"url": "https://user:pass@example.com"}).status_code == 422


def test_report_then_community_signal(client):
    for index in range(2):
        response = client.post("/api/report", json={"name": f"Reporter {index}", "email": f"person{index}@example.com", "malicious_url": "https://reported.example/bad", "reason": "Suspicious login prompt"})
        assert response.status_code == 201
    scan = client.post("/api/scan", json={"url": "https://reported.example/bad"}).json()
    assert any(item["category"] == "community_reports" for item in scan["evidence"])
    assert client.get("/api/blocked-sites").json()["sites"] == []

    for index in range(2, 4):
        response = client.post("/api/report", json={"name": f"Reporter {index}", "email": f"person{index}@example.com", "malicious_url": "https://reported.example/bad", "reason": "Suspicious login prompt"})
        assert response.status_code == 201
    assert client.get("/api/blocked-sites").json()["sites"] == ["https://reported.example/bad"]


def test_duplicate_report_from_same_user_is_updated_not_duplicated(client):
    payload = {"name": "Reporter", "email": "person@example.com", "malicious_url": "https://reported.example/bad", "reason": "First reason"}
    first = client.post("/api/report", json=payload)
    payload["reason"] = "Updated reason"
    second = client.post("/api/report", json=payload)
    assert first.status_code == 201
    assert second.status_code == 201
    assert first.json()["report_id"] == second.json()["report_id"]
    assert client.get("/api/dashboard/stats").json()["reports"] == 1


def test_ip_and_phishing_words_are_suspicious(client):
    body = client.post("/api/scan", json={"url": "http://192.0.2.1/account/verify/login/password"}).json()
    assert body["verdict"] == "suspicious"
    assert body["risk_score"] >= 35


def test_hibp_requires_configuration(client):
    assert client.get("/api/breaches/person@example.com").status_code == 503


def test_confirmed_live_match_is_cached_but_unknown_is_not(client, monkeypatch):
    calls = {"phishtank": 0}

    async def no_match(*_):
        return None, {"provider": "Other", "status": "checked"}

    async def phishing_match(*_):
        calls["phishtank"] += 1
        return {"source": "PhishTank", "category": "phishing", "detail": "Verified phishing URL.", "score": 100}, {"provider": "PhishTank", "status": "checked"}

    monkeypatch.setattr("app.main.check_urlhaus", no_match)
    monkeypatch.setattr("app.main.check_phishtank", phishing_match)
    monkeypatch.setattr("app.main.check_threatfox", no_match)
    monkeypatch.setattr("app.main.check_google_safe_browsing", no_match)

    first = client.post("/api/scan", json={"url": "https://confirmed.example/login"}).json()
    second = client.post("/api/scan", json={"url": "https://confirmed.example/login"}).json()
    assert first["verdict"] == "malicious"
    assert second["verdict"] == "malicious"
    assert calls["phishtank"] == 1
    assert any(item.get("detail", "").startswith("Confirmed match loaded") for item in second["providers"])
    assert client.get("/api/blocked-sites").json()["sites"] == ["https://confirmed.example/login"]


def test_password_range_returns_only_hash_suffixes(client, monkeypatch):
    async def fake_range(prefix, _settings):
        assert prefix == "5BAA6"
        return {"1E4C9B93F3F0682250B6CF8331B7EE68FD8": 3861493}

    monkeypatch.setattr("app.main.get_pwned_password_range", fake_range)
    response = client.get("/api/password/range/5baa6")
    assert response.status_code == 200
    assert response.json()["matches"]["1E4C9B93F3F0682250B6CF8331B7EE68FD8"] == 3861493
    assert client.get("/api/password/range/not-a-hash").status_code == 422


def test_ip_reputation_uses_virustotal_result(client, monkeypatch):
    async def fake_ip_check(ip_address, _settings):
        assert ip_address == "8.8.8.8"
        return {"malicious": 3, "suspicious": 1, "country": "US", "network": "8.8.8.0/24", "owner": "Example"}

    monkeypatch.setattr("app.main.check_virustotal_ip", fake_ip_check)
    response = client.get("/api/ip/8.8.8.8")
    assert response.status_code == 200
    assert response.json()["verdict"] == "malicious"
    assert response.json()["source"] == "VirusTotal"
    assert client.get("/api/ip/not-an-ip").status_code == 422
