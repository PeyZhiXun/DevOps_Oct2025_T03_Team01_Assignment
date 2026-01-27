def test_home_ok(client):
    res = client.get("/")
    assert res.status_code == 200
    assert b"DevSecOps MVP is running" in res.data

def test_login_user_redirects_dashboard(client, seed_users):
    res = client.post("/login", data={"username": "alice", "password": "AlicePass123!"}, follow_redirects=False)
    assert res.status_code in (302, 303)
    assert "/dashboard" in res.headers["Location"]

def test_login_admin_redirects_admin(client, seed_users):
    res = client.post("/login", data={"username": "admin1", "password": "AdminPass123!"}, follow_redirects=False)
    assert res.status_code in (302, 303)
    assert "/admin" in res.headers["Location"]

def test_login_invalid_redirects_login(client, seed_users):
    res = client.post("/login", data={"username": "alice", "password": "wrong"}, follow_redirects=False)
    assert res.status_code in (302, 303)
    assert "/login" in res.headers["Location"]

def test_dashboard_requires_login(client):
    res = client.get("/dashboard", follow_redirects=False)
    assert res.status_code in (302, 303)
    assert "/login" in res.headers["Location"]
