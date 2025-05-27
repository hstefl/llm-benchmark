import csv
import os

import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

@pytest.fixture(autouse=True)
def clear_csv(tmp_path, monkeypatch):
    # Patch CSV_FILE to use a temporary file for testing
    test_file = tmp_path / "users.csv"
    monkeypatch.setattr("main.CSV_FILE", str(test_file))
    # No need to cleanup, tmp_path handles it

def get_csv_content(file_path):
    if not os.path.exists(file_path):
        return []
    with open(file_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return list(reader)

def test_successful_registration():
    response = client.post("/register/", json={
        "username": "alice",
        "email": "alice@example.com",
    })
    assert response.status_code == 200
    assert response.json() == {"message": "User registered successfully"}

def test_registration_persists_to_csv(tmp_path):
    # The clear_csv fixture sets CSV_FILE to a temp file
    client.post("/register/", json={
        "username": "bob",
        "email": "bob@example.com",
    })
    # Check file contents
    with open(os.path.join(tmp_path, "users.csv"), newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert rows == [{"username": "bob", "email": "bob@example.com"}]

def test_missing_username():
    response = client.post("/register/", json={
        "email": "no_username@example.com",
    })
    assert response.status_code == 422
    # 422 Unprocessable Entity for validation error

def test_missing_email():
    response = client.post("/register/", json={
        "username": "no_email",
    })
    assert response.status_code == 422

def test_invalid_email_format():
    response = client.post("/register/", json={
        "username": "charlie",
        "email": "not-an-email",
    })
    assert response.status_code == 422

def test_duplicate_email():
    # First registration
    client.post("/register/", json={
        "username": "david",
        "email": "david@example.com",
    })
    # Attempt duplicate registration
    response = client.post("/register/", json={
        "username": "davey",
        "email": "david@example.com",
    })
    assert response.status_code == 400
    assert response.json() == {"detail": "Email already registered"}

#
# DISABLING - incorrect mocking
#
# def test_register_multiple_users():
#     users = [
#         {"username": "eve", "email": "eve@example.com"},
#         {"username": "frank", "email": "frank@example.com"},
#     ]
#     for user in users:
#         response = client.post("/register/", json=user)
#         assert response.status_code == 200
#     # Ensure both are in the CSV
#     csv_path = app.dependency_overrides.get("main.CSV_FILE", CSV_FILE)
#     with open(csv_path, newline="", encoding="utf-8") as f:
#         rows = [row for row in csv.DictReader(f)]
#     assert {"username": "eve", "email": "eve@example.com"} in rows
#     assert {"username": "frank", "email": "frank@example.com"} in rows

def test_extra_fields_ignored():
    response = client.post("/register/", json={
        "username": "gina",
        "email": "gina@example.com",
        "extra": "ignored",
    })
    # Extra fields are ignored by pydantic by default unless you set `extra=forbid`
    assert response.status_code == 200
    assert response.json() == {"message": "User registered successfully"}

def test_empty_payload():
    response = client.post("/register/", json={})
    assert response.status_code == 422

def test_blank_strings():
    response = client.post("/register/", json={
        "username": "",
        "email": "",
    })
    assert response.status_code == 422

#
# DISABLING - the assumption is wrong
#
# def test_email_case_sensitivity():
#     # Register with lowercase email
#     client.post("/register/", json={
#         "username": "casey",
#         "email": "casey@example.com",
#     })
#     # Try to register same email, different case
#     response = client.post("/register/", json={
#         "username": "casey2",
#         "email": "CASEY@example.com",
#     })
#     # Should allow since comparison is case-sensitive (unless you enforce lowercasing)
#     assert response.status_code == 200 or response.status_code == 400

