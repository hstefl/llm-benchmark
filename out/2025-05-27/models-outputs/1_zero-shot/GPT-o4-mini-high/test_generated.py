# test_register.py
import csv

import pytest
from fastapi.testclient import TestClient

# assume your application code is in main.py
import main
from main import RegisterUser, app, read_users_from_csv, write_user_to_csv

client = TestClient(app)

@pytest.fixture(autouse=True)
def temp_csv(tmp_path, monkeypatch):
    """
    Monkeypatch main.CSV_FILE to point at a tmp_path file for isolation.
    Cleans up after each test.
    """
    fake = tmp_path / "users.csv"
    monkeypatch.setattr(main, "CSV_FILE", str(fake))
    yield fake
    if fake.exists():
        fake.unlink()


def test_read_users_from_csv_no_file(temp_csv):
    # when file doesn't exist, reading yields empty list
    if temp_csv.exists():
        temp_csv.unlink()
    assert read_users_from_csv() == []


def test_write_and_read_user_directly(temp_csv):
    # write one user via write_user_to_csv(), then read back
    user = RegisterUser(username="alice", email="alice@example.com")
    write_user_to_csv(user)

    # file should exist and header + row should be present
    assert temp_csv.exists()
    with open(temp_csv, newline="", encoding="utf-8") as f:
        reader = list(csv.DictReader(f))
    assert reader == [{"username": "alice", "email": "alice@example.com"}]

    # read_users_from_csv returns list of emails
    emails = read_users_from_csv()
    assert emails == ["alice@example.com"]


def test_register_success_creates_file_and_returns_message(temp_csv):
    resp = client.post(
        "/register/",
        json={"username": "bob", "email": "bob@example.com"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"message": "User registered successfully"}

    # verify CSV contents
    with open(temp_csv, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert rows == [{"username": "bob", "email": "bob@example.com"}]


def test_register_duplicate_email_returns_400(temp_csv):
    # first registration succeeds
    resp1 = client.post(
        "/register/",
        json={"username": "carol", "email": "carol@example.com"},
    )
    assert resp1.status_code == 200

    # second with same email fails
    resp2 = client.post(
        "/register/",
        json={"username": "carol2", "email": "carol@example.com"},
    )
    assert resp2.status_code == 400
    assert resp2.json()["detail"] == "Email already registered"

    # file should only have the first entry
    with open(temp_csv, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 1
    assert rows[0]["username"] == "carol"


@pytest.mark.parametrize("payload,missing", [
    ({"email": "no_username@example.com"}, "username"),
    ({"username": "no_email"}, "email"),
    ({}, "both"),
])
def test_register_missing_fields_returns_422(temp_csv, payload, missing):
    resp = client.post("/register/", json=payload)
    # FastAPI/Pydantic will reject missing required fields as 422
    assert resp.status_code == 422
    # error body should mention the missing field(s)
    error_fields = {err["loc"][-1] for err in resp.json()["detail"]}
    if missing == "both":
        assert {"username", "email"} <= error_fields
    else:
        assert missing in error_fields


def test_register_invalid_email_format_returns_422(temp_csv):
    resp = client.post(
        "/register/",
        json={"username": "dave", "email": "not-an-email"},
    )
    assert resp.status_code == 422
    # ensure the error is about the email field
    details = resp.json()["detail"]
    assert any(err["loc"][-1] == "email" for err in details)


def test_multiple_distinct_users_can_be_registered(temp_csv):
    users = [
        {"username": "eve", "email": "eve@example.com"},
        {"username": "frank", "email": "frank@example.com"},
    ]
    for u in users:
        resp = client.post("/register/", json=u)
        assert resp.status_code == 200

    # CSV should have both entries in order
    with open(temp_csv, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert rows == [
        {"username": "eve", "email": "eve@example.com"},
        {"username": "frank", "email": "frank@example.com"},
    ]

    # read_users_from_csv returns both emails
    assert read_users_from_csv() == ["eve@example.com", "frank@example.com"]
