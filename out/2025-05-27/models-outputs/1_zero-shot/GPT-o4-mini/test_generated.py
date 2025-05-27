import csv

import main
import pytest
from fastapi.testclient import TestClient


# Use a temporary CSV file for tests
@pytest.fixture(autouse=True)
def setup_tmp_csv(tmp_path, monkeypatch):
    temp_file = tmp_path / "users.csv"
    # Monkey-patch the CSV_FILE path in the application module
    monkeypatch.setattr(main, "CSV_FILE", str(temp_file))
    # Ensure clean state
    if temp_file.exists():
        temp_file.unlink()
    yield
    # Cleanup after tests
    if temp_file.exists():
        temp_file.unlink()

client = TestClient(main.app)


def test_read_users_from_csv_empty():
    # No CSV file exists yet
    users = main.read_users_from_csv()
    assert users == []


def test_successful_registration():
    # Register a new user
    response = client.post(
        "/register/",
        json={"username": "alice", "email": "alice@example.com"},
    )
    assert response.status_code == 200
    assert response.json() == {"message": "User registered successfully"}

    # Verify the CSV file contains the new user
    with open(main.CSV_FILE, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    assert rows == [{"username": "alice", "email": "alice@example.com"}]


def test_missing_username():
    # Missing 'username' field
    response = client.post(
        "/register/",
        json={"email": "bob@example.com"},
    )
    assert response.status_code == 422
    assert any(err["loc"][-1] == "username" for err in response.json()["detail"])


def test_missing_email():
    # Missing 'email' field
    response = client.post(
        "/register/",
        json={"username": "bob"},
    )
    assert response.status_code == 422
    assert any(err["loc"][-1] == "email" for err in response.json()["detail"])


def test_invalid_email_format():
    # Invalid email format
    response = client.post(
        "/register/",
        json={"username": "bob", "email": "not-an-email"},
    )
    assert response.status_code == 422
    assert any(err["loc"][-1] == "email" for err in response.json()["detail"])


def test_duplicate_email_registration():
    # First registration should succeed
    first = client.post(
        "/register/",
        json={"username": "charlie", "email": "charlie@example.com"},
    )
    assert first.status_code == 200

    # Duplicate registration should fail
    response = client.post(
        "/register/",
        json={"username": "charlie2", "email": "charlie@example.com"},
    )
    assert response.status_code == 400
    assert response.json()["detail"] == "Email already registered"
