# tests/test_user_failure.py
import pytest

def login(client, username, password):
    return client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=False
    )

def test_login_invalid_username(client):
    res = login(client, "wronguser", "AlicePass123!")
    # App redirects to /login for invalid login
    assert res.status_code == 302
    assert "/login" in res.headers["Location"]

def test_login_invalid_password(client, seed_users):
    res = login(client, "alice", "WrongPass!")
    assert res.status_code == 302
    assert "/login" in res.headers["Location"]

def test_login_empty_fields(client):
    res = login(client, "", "")
    assert res.status_code == 302
    assert "/login" in res.headers["Location"]
