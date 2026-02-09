import io

def login(client, username, password):
    return client.post("/login", data={"username": username, "password": password}, follow_redirects=False)

def test_user_can_upload_and_see_own_file(client, seed_users):
    login(client, "alice", "AlicePass123!")

    data = {"file": (io.BytesIO(b"hello"), "alice.txt")}
    res = client.post("/dashboard", data=data, content_type="multipart/form-data", follow_redirects=True)
    assert res.status_code == 200
    assert b"alice.txt" in res.data

def test_user_cannot_download_other_users_file(client, seed_users, db_conn):
    # Alice uploads
    login(client, "alice", "AlicePass123!")
    data = {"file": (io.BytesIO(b"secret"), "secret.txt")}
    client.post("/dashboard", data=data, content_type="multipart/form-data", follow_redirects=True)

    # Get file_id
    with db_conn.cursor() as cur:
        cur.execute("SELECT id FROM files ORDER BY id DESC LIMIT 1;")
        file_id = cur.fetchone()[0]

    # Bob tries download
    client.get("/logout")
    login(client, "bob", "BobPass123!")
    res = client.get(f"/dashboard/download/{file_id}", follow_redirects=True)
    assert res.status_code == 200
    assert b"access denied" in res.data.lower()

def test_user_cannot_delete_other_users_file(client, seed_users, db_conn):
    # Alice uploads
    login(client, "alice", "AlicePass123!")
    data = {"file": (io.BytesIO(b"secret2"), "secret2.txt")}
    client.post("/dashboard", data=data, content_type="multipart/form-data", follow_redirects=True)

    with db_conn.cursor() as cur:
        cur.execute("SELECT id FROM files ORDER BY id DESC LIMIT 1;")
        file_id = cur.fetchone()[0]

    # Bob tries delete
    client.get("/logout")
    login(client, "bob", "BobPass123!")
    res = client.post(f"/dashboard/delete/{file_id}", follow_redirects=True)
    assert res.status_code == 200
    assert b"access denied" in res.data.lower() or b"not found" in res.data.lower()
