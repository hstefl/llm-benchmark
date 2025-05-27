import os
import csv
import pytest
from fastapi.testclient import TestClient
from main import app, read_users_from_csv, write_user_to_csv, CSV_FILE
from pydantic import EmailStr

# List of dependencies and versions for pyproject.toml:
# [tool.poetry.dependencies]
# fastapi = "0.95.2"
# pydantic = "2.1.1"
#
# [tool.poetry.dev-dependencies]
# pytest = "7.4.0"
# pytest-asyncio = "0.21.0"
# httpx = "0.24.1"

@pytest.fixture(autouse=True)
def use_temp_csv(tmp_path, monkeypatch):
    """Redirect CSV_FILE to a temporary file for each test."""
    temp_file = tmp_path / "users.csv"
    monkeypatch.setattr("main.CSV_FILE", str(temp_file))
    yield

@pytest.fixture
def client():
    return TestClient(app)


def test_read_users_from_csv_returns_empty_when_file_missing():
    # CSV_FILE does not exist
    users = read_users_from_csv()
    assert users == [], f"Expected empty list when CSV file is missing, got {users}"


def test_write_user_to_csv_creates_file_with_header_and_row(tmp_path):
    temp_csv = tmp_path / "users.csv"
    # ensure file does not exist yet
    assert not temp_csv.exists(), "Temp CSV should not exist before writing"

    # Write a user
    class DummyUser:
        username = "alice"
        email = "alice@example.com"

    write_user_to_csv(DummyUser)

    # File should now exist
    assert temp_csv.exists(), "Temp CSV file should be created"

    # Validate contents
    with open(temp_csv, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    assert rows == [{"username": "alice", "email": "alice@example.com"}], (
        f"CSV content mismatch. Expected one row with alice, got: {rows}"
    )


def test_register_user_successful_registration(client, tmp_path):
    # Test successful registration via API
    response = client.post(
        "/register/", json={"username": "bob", "email": "bob@example.com"}
    )
    assert response.status_code == 200, f"Expected HTTP 200, got {response.status_code}"
    assert response.json() == {"message": "User registered successfully"}, (
        f"Unexpected response JSON: {response.json()}"
    )
    # Check CSV contents
    with open(CSV_FILE, encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    assert rows and rows[0]["email"] == "bob@example.com", (
        "Registered email not found in CSV"
    )


def test_register_user_duplicate_email_rejected(client, tmp_path):
    # Prepopulate CSV with an email
    with open(CSV_FILE, mode="w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["username", "email"])
        writer.writeheader()
        writer.writerow({"username": "eve", "email": "eve@example.com"})

    # Attempt to register same email
    response = client.post(
        "/register/", json={"username": "eve2", "email": "eve@example.com"}
    )
    assert response.status_code == 400, f"Expected HTTP 400 for duplicate email, got {response.status_code}"
    assert response.json().get("detail") == "Email already registered", (
        f"Unexpected error detail: {response.json()}"
    )


def test_register_user_missing_fields_returns_422(client):
    response = client.post("/register/", json={"username": "charlie"})
    assert response.status_code == 422, (
        f"Expected HTTP 422 for missing fields, got {response.status_code}"
    )


def test_register_user_invalid_email_format_returns_422(client):
    response = client.post(
        "/register/", json={"username": "dan", "email": "not-an-email"}
    )
    assert response.status_code == 422, (
        f"Expected HTTP 422 for invalid email, got {response.status_code}"
    )


def test_rejects_empty_username(client):
    # Empty username should be rejected by application requirements
    response = client.post(
        "/register/", json={"username": "", "email": "empty@example.com"}
    )
    assert response.status_code == 422, (
        f"Expected HTTP 422 for empty username, got {response.status_code}"
    )


def test_rejects_malicious_username_to_prevent_csv_injection(client):
    # CSV injection vectors often start with =+, etc.
    malicious = "=CMD|' /C calc'!A0"
    response = client.post(
        "/register/", json={"username": malicious, "email": "inject@example.com"}
    )
    # The application should sanitize or reject such input
    assert response.status_code == 400, (
        f"Expected HTTP 400 for malicious username injection, got {response.status_code}"
    )
