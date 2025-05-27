# tests/test_registration.py
import csv

import main  # ← change if your application file is named differently
import pytest
from fastapi.testclient import TestClient

# ---------- fixtures ---------------------------------------------------------

@pytest.fixture
def client(tmp_path, monkeypatch):
    """
    Creates a TestClient whose underlying app writes to a throw-away CSV
    located in pytest's tmp_path directory.
    """
    tmp_csv = tmp_path / "users.csv"
    monkeypatch.setattr(main, "CSV_FILE", str(tmp_csv))   # patch global
    return TestClient(main.app)


# ---------- happy-path -------------------------------------------------------

def test_register_success(client):
    payload = {"username": "alice", "email": "alice@example.com"}

    resp = client.post("/register/", json=payload)

    assert resp.status_code == 200
    assert resp.json() == {"message": "User registered successfully"}

    # Verify the user really landed in persistent storage
    with open(main.CSV_FILE, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))

    assert rows == [payload]


# ---------- validation errors ------------------------------------------------

@pytest.mark.parametrize(
    "payload,missing_field",
    [
        ({"email": "no_name@example.com"}, "username"),
        ({"username": "no_email"}, "email"),
    ],
)
def test_missing_field_returns_422(client, payload, missing_field):
    resp = client.post("/register/", json=payload)

    assert resp.status_code == 422
    # FastAPI includes a list of validation errors; make sure ours is there
    assert any(err["loc"][-1] == missing_field for err in resp.json()["detail"])


def test_invalid_email_returns_422(client):
    resp = client.post(
        "/register/", json={"username": "bob", "email": "not-an-email"},
    )

    assert resp.status_code == 422
    assert any(
        err["msg"].startswith("value is not a valid email")
        for err in resp.json()["detail"]
    )


# ---------- duplicate protection --------------------------------------------

def test_duplicate_email_returns_400(client):
    first = {"username": "charlie", "email": "charlie@example.com"}
    duplicate = {"username": "charlie2", "email": "charlie@example.com"}

    # first registration succeeds …
    assert client.post("/register/", json=first).status_code == 200
    # … second with same e-mail fails
    resp = client.post("/register/", json=duplicate)

    assert resp.status_code == 400
    assert resp.json() == {"detail": "Email already registered"}


# ---------- persistence corner-case -----------------------------------------

def test_csv_header_written_only_once(client):
    """
    Append two users and ensure the header row was not duplicated.
    """
    users = [
        {"username": "dana", "email": "dana@example.com"},
        {"username": "ed", "email": "ed@example.com"},
    ]
    for u in users:
        assert client.post("/register/", json=u).status_code == 200

    with open(main.CSV_FILE, newline="", encoding="utf-8") as fh:
        reader = csv.reader(fh)
        lines = list(reader)

    # Expect 1 header + 2 data rows
    assert len(lines) == len(users) + 1
    assert lines[0] == ["username", "email"]
