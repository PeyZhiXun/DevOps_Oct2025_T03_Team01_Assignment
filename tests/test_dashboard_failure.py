def login(client, username, password):
    return client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=True
    )

def test_dashboard_requires_login(client):
    res = client.get("/dashboard")
    assert res.status_code == 302
    assert "/login" in res.headers["Location"]

def test_upload_without_file(client, seed_users):
    login(client, "alice", "AlicePass123!")

    res = client.post("/dashboard", data={})
    assert res.status_code == 302
