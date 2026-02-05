def login(client, username, password):
    return client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=True
    )

def test_admin_requires_login(client):
    res = client.get("/admin")
    assert res.status_code == 302
    assert "/login" in res.headers["Location"]

def test_user_cannot_access_admin(client, seed_users):
    login(client, "alice", "AlicePass123!")
    res = client.get("/admin")
    assert res.status_code == 403
