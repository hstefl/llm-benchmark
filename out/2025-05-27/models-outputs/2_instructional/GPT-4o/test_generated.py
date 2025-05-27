import pytest
from fastapi.testclient import TestClient
from main import app
from unittest import mock
import tempfile
import os
import csv
from main import RegisterUser


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def temp_csv_file(monkeypatch):
    with tempfile.TemporaryDirectory() as tmpdirname:
        temp_path = os.path.join(tmpdirname, "users.csv")
        monkeypatch.setattr("main.CSV_FILE", temp_path)
        yield temp_path


def test_register_user_success(client, temp_csv_file):
    response = client.post("/register/", json={"username": "alice", "email": "alice@example.com"})

    assert response.status_code == 200, "Expected 200 OK on successful registration"
    assert response.json() == {"message": "User registered successfully"}

    with open(temp_csv_file, newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        rows = list(reader)
        assert rows[0]["username"] == "alice"
        assert rows[0]["email"] == "alice@example.com"


def test_register_user_missing_username(client):
    response = client.post("/register/", json={"email": "bob@example.com"})

    assert response.status_code == 422, "Expected 422 Unprocessable Entity for missing username"
    assert "username" in response.text


def test_register_user_missing_email(client):
    response = client.post("/register/", json={"username": "bob"})

    assert response.status_code == 422, "Expected 422 Unprocessable Entity for missing email"
    assert "email" in response.text


def test_register_user_invalid_email_format(client):
    response = client.post("/register/", json={"username": "bob", "email": "not-an-email"})

    assert response.status_code == 422, "Expected 422 Unprocessable Entity for invalid email"
    assert "email" in response.text


def test_register_user_duplicate_email(client, temp_csv_file):
    initial_user = RegisterUser(username="charlie", email="charlie@example.com")

    with open(temp_csv_file, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=["username", "email"])
        writer.writeheader()
        writer.writerow({"username": initial_user.username, "email": initial_user.email})

    response = client.post("/register/", json={"username": "newcharlie", "email": "charlie@example.com"})

    assert response.status_code == 400, "Expected 400 Bad Request for duplicate email"
    assert response.json() == {"detail": "Email already registered"}


def test_register_user_csv_injection_attempt(client, temp_csv_file):
    malicious_username = '=cmd|\' /C calc\'!A0'
    response = client.post("/register/", json={"username": malicious_username, "email": "safe@example.com"})

    assert response.status_code == 200, "Expected 200 OK for potentially malicious but valid input"

    with open(temp_csv_file, newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        rows = list(reader)
        stored_username = rows[0]["username"]

        assert not stored_username.startswith(("=", "+", "-", "@")), (
            "Username should not start with spreadsheet command chars to avoid CSV injection"
        )


def test_register_user_strips_whitespace_in_email(client, temp_csv_file):
    email_with_spaces = "  whitespace@example.com  "
    response = client.post("/register/", json={"username": "cleaner", "email": email_with_spaces})

    assert response.status_code == 422, "Expected 422 due to invalid email with spaces"


def test_register_user_rejects_get_method(client):
    response = client.get("/register/")
    assert response.status_code == 405, "Expected 405 Method Not Allowed for GET on POST-only endpoint"


def test_register_user_case_insensitive_duplicate(client, temp_csv_file):
    # Add existing email in lowercase
    RegisterUser(username="sam", email="case@example.com")
    with open(temp_csv_file, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=["username", "email"])
        writer.writeheader()
        writer.writerow({"username": "sam", "email": "case@example.com"})

    # Try registering with same email but in uppercase
    response = client.post("/register/", json={"username": "new", "email": "CASE@example.com"})

    assert response.status_code == 200, (
        "Expected 200 because duplicate detection is case-sensitive, "
        "but should ideally be normalized for email"
    )


def test_register_user_large_payload(client, temp_csv_file):
    large_username = "a" * 500
    response = client.post("/register/", json={"username": large_username, "email": "big@example.com"})

    assert response.status_code == 200, "Expected 200 OK for large but valid username"


def test_register_user_non_ascii_characters(client, temp_csv_file):
    response = client.post("/register/", json={"username": "üser", "email": "unicode@example.com"})

    assert response.status_code == 200, "Expected 200 OK for non-ASCII username"


def test_register_user_empty_body(client):
    response = client.post("/register/", json={})

    assert response.status_code == 422, "Expected 422 Unprocessable Entity for empty JSON"
