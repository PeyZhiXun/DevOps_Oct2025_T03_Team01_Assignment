def login(client, username, password):
    return client.post("/login", data={"username": username, "password": password}, follow_redirects=False)

def test_admin_blocked_for_user(client, seed_users):
    login(client, "alice", "AlicePass123!")
    res = client.get("/admin")
    assert res.status_code == 403

def test_admin_can_create_user(client, seed_users):
    login(client, "admin1", "AdminPass123!")
    res = client.post(
        "/admin/create_user",
        data={"username": "charlie", "password": "CharPass123!", "role": "user"},
        follow_redirects=True
    )
    assert res.status_code == 200
    assert b"charlie" in res.data

def test_admin_cannot_delete_self(client, seed_users):
    login(client, "admin1", "AdminPass123!")
    admin_id = seed_users["admin_id"]
    res = client.post(f"/admin/delete_user/{admin_id}", follow_redirects=True)
    assert res.status_code == 200
    assert b"cannot delete your own" in res.data.lower()
