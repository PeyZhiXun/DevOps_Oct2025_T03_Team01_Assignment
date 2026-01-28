# tests/test_unit.py

def test_guest_cannot_access_dashboard(client):
    res = client.get("/dashboard", follow_redirects=False)
    assert res.status_code in (302, 303)
    assert "/login" in res.headers["Location"]


def test_guest_cannot_access_admin(client):
    res = client.get("/admin", follow_redirects=False)
    assert res.status_code in (302, 303)
    assert "/login" in res.headers["Location"]


def test_non_admin_cannot_access_admin(client, seed_users):
    client.post(
        "/login",
        data={"username": "alice", "password": "AlicePass123!"},
        follow_redirects=False,
    )

    res = client.get("/admin", follow_redirects=False)
    assert res.status_code in (302, 303, 403)  # accept either redirect or forbidden

    # If it redirects, it should NOT stay in /admin
    if res.status_code in (302, 303):
        assert "/admin" not in res.headers["Location"]


def test_admin_can_access_admin(client, seed_users):
    client.post(
        "/login",
        data={"username": "admin1", "password": "AdminPass123!"},
        follow_redirects=False,
    )

    res = client.get("/admin", follow_redirects=False)
    assert res.status_code == 200
