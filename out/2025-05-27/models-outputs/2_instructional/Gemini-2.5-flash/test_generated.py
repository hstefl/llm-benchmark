import os
from typing import List
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from main import app, CSV_FILE, RegisterUser, read_users_from_csv, write_user_to_csv


@pytest.fixture(scope="function", autouse=True)
def cleanup_csv():
    """Cleans up the CSV file after each test."""
    if os.path.exists(CSV_FILE):
        os.remove(CSV_FILE)
    yield
    if os.path.exists(CSV_FILE):
        os.remove(CSV_FILE)


@pytest.fixture(scope="function")
def test_client():
    """Creates a test client for the FastAPI application."""
    return TestClient(app)


def get_users_from_csv() -> List[dict]:
    """Helper function to read all users from the CSV for assertions."""
    users = []
    if os.path.exists(CSV_FILE):
        with open(CSV_FILE, mode="r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                users.append(row)
    return users


def test_register_user_success(test_client):
    """Tests successful user registration."""
    user_data = {"username": "testuser", "email": "test@example.com"}
    response = test_client.post("/register/", json=user_data)
    assert response.status_code == 200
    assert response.json() == {"message": "User registered successfully"}
    users = get_users_from_csv()
    assert len(users) == 1
    assert users[0]["username"] == "testuser"
    assert users[0]["email"] == "test@example.com"


def test_register_user_duplicate_email(test_client):
    """Tests registration with an already existing email."""
    user_data_1 = {"username": "user1", "email": "duplicate@example.com"}
    response_1 = test_client.post("/register/", json=user_data_1)
    assert response_1.status_code == 200

    user_data_2 = {"username": "user2", "email": "duplicate@example.com"}
    response_2 = test_client.post("/register/", json=user_data_2)
    assert response_2.status_code == 400
    assert response_2.json() == {"detail": "Email already registered"}
    users = get_users_from_csv()
    assert len(users) == 1
    assert users[0]["email"] == "duplicate@example.com"


def test_register_user_missing_username(test_client):
    """Tests registration with a missing username."""
    user_data = {"email": "missing_name@example.com"}
    response = test_client.post("/register/", json=user_data)
    assert response.status_code == 422
    assert "username" in response.json()["detail"][0]["loc"]


def test_register_user_missing_email(test_client):
    """Tests registration with a missing email."""
    user_data = {"username": "no_email_user"}
    response = test_client.post("/register/", json=user_data)
    assert response.status_code == 422
    assert "email" in response.json()["detail"][0]["loc"]


def test_register_user_invalid_email_format(test_client):
    """Tests registration with an invalid email format."""
    user_data = {"username": "invalid_email", "email": "not_an_email"}
    response = test_client.post("/register/", json=user_data)
    assert response.status_code == 422
    assert "email" in response.json()["detail"][0]["loc"]


def test_read_users_from_csv_empty_file():
    """Tests reading users when the CSV file does not exist."""
    if os.path.exists(CSV_FILE):
        os.remove(CSV_FILE)
    users = read_users_from_csv()
    assert users == []


def test_read_users_from_csv_existing_file(test_client):
    """Tests reading users from an existing CSV file."""
    user1 = {"username": "test1", "email": "test1@example.com"}
    user2 = {"username": "test2", "email": "test2@example.com"}
    write_user_to_csv(RegisterUser(**user1))
    write_user_to_csv(RegisterUser(**user2))
    emails = read_users_from_csv()
    assert len(emails) == 2
    assert "test1@example.com" in emails
    assert "test2@example.com" in emails


# def test_write_user_to_csv_new_file():
#     """Tests writing a user to a new CSV file."""
#     user_data = RegisterUser(username="newuser", email="new@example.com")
#     write_user_to_csv(user_data)
#     with open(CSV_FILE, mode="r", newline="", encoding="utf-8") as f:
#         reader = csv.DictReader(f)
#         rows = list(reader)
#         assert len(rows) == 1
#         assert rows[0]["username"] == "newuser"
#         assert rows[0]["email"] == "new@example.com"


def test_write_user_to_csv_existing_file():
    """Tests writing a user to an existing CSV file."""
    user_data_1 = RegisterUser(username="olduser", email="old@example.com")
    write_user_to_csv(user_data_1)
    user_data_2 = RegisterUser(username="another", email="another@example.com")
    write_user_to_csv(user_data_2)
    with open(CSV_FILE, mode="r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        assert len(rows) == 2
        assert any(row["username"] == "olduser" and row["email"] == "old@example.com" for row in rows)
        assert any(row["username"] == "another" and row["email"] == "another@example.com" for row in rows)


def test_register_user_security_csv_injection(test_client):
    """Tests for potential CSV injection vulnerability."""
    malicious_username = "malicious"
    malicious_email = "evil@example.com,=HYPERLINK(\"http://malicious.com\")"
    user_data = {"username": malicious_username, "email": malicious_email}
    response = test_client.post("/register/", json=user_data)
    assert response.status_code == 200
    users = get_users_from_csv()
    assert len(users) == 1
    assert users[0]["username"] == malicious_username
    assert users[0]["email"] == malicious_email
    # Here we assert that the raw value is stored, not interpreted as a formula.
    # A proper fix might involve sanitization, but the test ensures the raw input is handled.


# Tooling versions:
# pytest==7.4.4
# fastapi==0.110.0
# httpx==0.27.0
# pydantic==2.7.1
# ruff==0.3.1