def test_logout_requires_login(client):
    res = client.get("/logout")
    assert res.status_code == 302
    assert "/login" in res.headers["Location"]
