import csv
import io
import os

import pytest
from fastapi.testclient import TestClient

import main

@pytest.fixture(autouse=True)
def temp_csv_path(tmp_path, monkeypatch):
    """
    Redirect CSV_FILE to a temp path for each test, ensuring isolation.
    """
    temp_file = tmp_path / "users.csv"
    monkeypatch.setattr(main, "CSV_FILE", str(temp_file))
    # Ensure we start fresh each time
    if temp_file.exists():
        temp_file.unlink()
    return temp_file

client = TestClient(main.app)


def test_registration_success_creates_csv_and_returns_message(temp_csv_path):
    response = client.post(
        "/register/",
        json={"username": "alice", "email": "alice@example.com"},
    )
    assert response.status_code == 200, (
        f"Expected 200 OK, got {response.status_code}"
    )
    assert response.json() == {"message": "User registered successfully"}, (
        f"Unexpected JSON response: {response.json()}"
    )

    # Verify CSV header + row
    content = temp_csv_path.read_text(encoding="utf-8")
    reader = csv.DictReader(io.StringIO(content))
    rows = list(reader)
    assert rows == [{"username": "alice", "email": "alice@example.com"}], (
        f"CSV contents mismatch: {rows}"
    )


def test_registration_duplicate_email_returns_400(temp_csv_path):
    # Pre-populate with one user
    temp_csv_path.write_text("username,email\nbob,bob@example.com\n", encoding="utf-8")

    response = client.post(
        "/register/",
        json={"username": "alice", "email": "bob@example.com"},
    )
    assert response.status_code == 400, (
        f"Expected 400 Bad Request for duplicate email, got {response.status_code}"
    )
    assert response.json().get("detail") == "Email already registered", (
        f"Expected detail='Email already registered', got {response.json()}"
    )


def test_missing_username_returns_validation_error():
    response = client.post("/register/", json={"email": "alice@example.com"})
    assert response.status_code == 422, (
        f"Expected 422 Unprocessable Entity for missing username, got {response.status_code}"
    )
    assert "username" in response.json().get("detail")[0]["loc"], (
        "Validation error did not mention 'username' field"
    )


def test_invalid_email_returns_validation_error():
    response = client.post(
        "/register/",
        json={"username": "alice", "email": "not-an-email"},
    )
    assert response.status_code == 422, (
        f"Expected 422 Unprocessable Entity for invalid email, got {response.status_code}"
    )
    # Pydantic will flag email at index 1
    details = response.json().get("detail")
    assert any("email" in err["loc"] for err in details), (
        f"Validation error did not mention 'email'; details: {details}"
    )


def test_read_users_from_csv_with_no_file_returns_empty_list(temp_csv_path):
    # Ensure the file truly doesn't exist
    temp_csv_path.unlink(missing_ok=True)
    users = main.read_users_from_csv()
    assert users == [], (
        f"Expected empty list when CSV file is missing, got {users}"
    )


def test_write_user_to_csv_creates_header_when_file_missing(temp_csv_path):
    # Remove file if present
    temp_csv_path.unlink(missing_ok=True)
    user = main.RegisterUser(username="dave", email="dave@example.com")
    main.write_user_to_csv(user)

    content = temp_csv_path.read_text(encoding="utf-8")
    lines = content.splitlines()
    assert lines[0] == "username,email", (
        f"CSV header was wrong. Expected 'username,email', got '{lines[0]}'"
    )
    # And one data row
    reader = csv.DictReader(io.StringIO(content))
    rows = list(reader)
    assert rows == [{"username": "dave", "email": "dave@example.com"}], (
        f"CSV data row mismatch: {rows}"
    )


def test_write_user_to_csv_appends_to_existing_file(temp_csv_path):
    # Create initial file with one user
    temp_csv_path.write_text("username,email\njohn,john@example.com\n", encoding="utf-8")
    user = main.RegisterUser(username="mary", email="mary@example.com")
    main.write_user_to_csv(user)

    content = temp_csv_path.read_text(encoding="utf-8")
    reader = csv.DictReader(io.StringIO(content))
    emails = [row["email"] for row in reader]
    assert "john@example.com" in emails and "mary@example.com" in emails, (
        f"Emails not appended correctly, got {emails}"
    )


def test_username_csv_injection_sanitization(temp_csv_path):
    """
    CSV-injection: any field starting with =, +, -, @ should be sanitized or quoted.
    This test will fail until such protection is added.
    """
    malicious = "=2+CMD|' /C calc'!A0"
    response = client.post(
        "/register/",
        json={"username": malicious, "email": "evil@example.com"},
    )
    assert response.status_code == 200, (
        f"Expected successful registration even for malicious username, got {response.status_code}"
    )

    content = temp_csv_path.read_text(encoding="utf-8")
    # The data line should NOT start with '='
    data_line = content.splitlines()[1]
    assert not data_line.startswith("="), (
        "CSV-injection vulnerability: leading '=' was not sanitized or quoted"
    )


def test_username_script_injection_sanitization(temp_csv_path):
    """
    Script injection: fields containing HTML/script tags should be escaped or rejected.
    This test will fail until such protection is implemented.
    """
    malicious = "<script>alert('xss')</script>"
    response = client.post(
        "/register/",
        json={"username": malicious, "email": "evil2@example.com"},
    )
    assert response.status_code == 200, (
        f"Expected successful registration even for malicious username, got {response.status_code}"
    )

    content = temp_csv_path.read_text(encoding="utf-8")
    # The raw '<' and '>' should not persist
    assert "<script>" not in content and "</script>" not in content, (
        "Script-injection vulnerability: HTML tags were not escaped"
    )
