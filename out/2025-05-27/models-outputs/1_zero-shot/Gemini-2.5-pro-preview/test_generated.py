import pytest
from fastapi.testclient import TestClient
import os
import csv

# Ensure your FastAPI application code is in 'main.py'
from main import app, RegisterUser, read_users_from_csv, write_user_to_csv

# Define a specific CSV file for testing purposes
TEST_CSV_FILE = "test_users.csv"

@pytest.fixture(autouse=True)
def manage_test_csv_file(monkeypatch):
    """
    Fixture to manage the test CSV file.
    It patches the CSV_FILE path used by the application and ensures
    the test CSV file is cleaned up before and after each test.
    """
    # Patch the CSV_FILE global in the 'main' module
    monkeypatch.setattr("main.CSV_FILE", TEST_CSV_FILE)

    # Ensure the test CSV is clean before each test
    if os.path.exists(TEST_CSV_FILE):
        os.remove(TEST_CSV_FILE)
    yield  # This is where the test runs
    # Clean up after each test
    if os.path.exists(TEST_CSV_FILE):
        os.remove(TEST_CSV_FILE)

client = TestClient(app)

def read_actual_csv_content():
    """Helper function to read the content of the test CSV file."""
    if not os.path.exists(TEST_CSV_FILE):
        return []
    with open(TEST_CSV_FILE, mode='r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        return list(reader)

## API Endpoint Tests

def test_successful_registration():
    """Test successful user registration."""
    response = client.post("/register/", json={"username": "testuser", "email": "test@example.com"})
    assert response.status_code == 200
    assert response.json() == {"message": "User registered successfully"}

    # Verify data in CSV
    users_in_csv = read_actual_csv_content()
    assert len(users_in_csv) == 1
    assert users_in_csv[0]["username"] == "testuser"
    assert users_in_csv[0]["email"] == "test@example.com"

def test_register_user_missing_username():
    """Test registration with a missing username."""
    response = client.post("/register/", json={"email": "test@example.com"})
    assert response.status_code == 422  # Unprocessable Entity for Pydantic validation
    # Check if 'username' is mentioned in the error details
    error_detail = response.json().get("detail", [])
    assert any("username" in item.get("loc", []) for item in error_detail if isinstance(item, dict))


def test_register_user_missing_email():
    """Test registration with a missing email."""
    response = client.post("/register/", json={"username": "testuser"})
    assert response.status_code == 422
    error_detail = response.json().get("detail", [])
    assert any("email" in item.get("loc", []) for item in error_detail if isinstance(item, dict))


def test_register_user_invalid_email_format():
    """Test registration with an invalid email format."""
    response = client.post("/register/", json={"username": "testuser", "email": "not-an-email"})
    assert response.status_code == 422
    error_detail = response.json().get("detail", [])
    assert any("email" in item.get("loc", []) and "value is not a valid email address" in item.get("msg","").lower() for item in error_detail if isinstance(item, dict))


def test_register_user_empty_string_username():
    """Test registration with an empty string for username."""
    response = client.post("/register/", json={"username": " ", "email": "test@example.com"})
    assert response.status_code == 422 # Based on added validation in main.py
    assert response.json() == {"detail": "Username and email cannot be empty"}

def test_register_user_empty_string_email():
    """Test registration with an empty string for email."""
    response = client.post("/register/", json={"username": "testuser", "email": " "})
    # This will be caught by EmailStr as invalid format first, or our custom check
    assert response.status_code == 422
    # Depending on which validation hits first (Pydantic EmailStr or our custom empty check)
    detail = response.json().get("detail")
    if isinstance(detail, list): # Pydantic error
        assert any("email" in item.get("loc", []) for item in detail if isinstance(item, dict))
    else: # Custom error
        assert detail == "Username and email cannot be empty"


def test_register_user_duplicate_email():
    """Test registration with a duplicate email."""
    # First registration
    client.post("/register/", json={"username": "user1", "email": "duplicate@example.com"})

    # Attempt second registration with the same email
    response = client.post("/register/", json={"username": "user2", "email": "duplicate@example.com"})
    assert response.status_code == 400
    assert response.json() == {"detail": "Email already registered"}

    # Verify only one user was actually added to CSV
    users_in_csv = read_actual_csv_content()
    assert len(users_in_csv) == 1
    assert users_in_csv[0]["email"] == "duplicate@example.com"
    assert users_in_csv[0]["username"] == "user1"

#--- This was not commented
## Helper Function Unit Tests

def test_read_users_from_csv_no_file_exists():
    """Test read_users_from_csv when the CSV file does not exist."""
    # The manage_test_csv_file fixture ensures the file is deleted initially
    assert read_users_from_csv() == []

def test_read_users_from_csv_empty_file():
    """Test read_users_from_csv when the CSV file is empty (0 bytes)."""
    # Create an empty file
    open(TEST_CSV_FILE, 'w').close()
    assert read_users_from_csv() == []

def test_read_users_from_csv_file_with_header_only():
    """Test read_users_from_csv when the CSV file only contains a header."""
    with open(TEST_CSV_FILE, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=["username", "email"])
        writer.writeheader()
    assert read_users_from_csv() == []

def test_read_users_from_csv_with_data():
    """Test read_users_from_csv when the file has data."""
    users_data = [
        {"username": "user1", "email": "email1@example.com"},
        {"username": "user2", "email": "email2@example.com"}
    ]
    with open(TEST_CSV_FILE, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=["username", "email"])
        writer.writeheader()
        for user in users_data:
            writer.writerow(user)

    expected_emails = ["email1@example.com", "email2@example.com"]
    assert sorted(read_users_from_csv()) == sorted(expected_emails)

#
# Specification says "Each user must provide both a username and an email."
#
# def test_read_users_from_csv_malformed_row():
#     """Test read_users_from_csv with a row missing the email column (after header)."""
#     with open(TEST_CSV_FILE, mode='w', newline='', encoding='utf-8') as f:
#         writer = csv.writer(f)
#         writer.writerow(["username", "email"]) # Header
#         writer.writerow(["user1", "good@example.com"])
#         writer.writerow(["user2_no_email"]) # Malformed row for DictReader
#     # The current implementation of read_users_from_csv with DictReader
#     # will skip rows that don't conform after reading.
#     # If a row is just `["user2_no_email"]`, `DictReader` might make `email: None`
#     # or it might raise an error if the number of fields doesn't match.
#     # The refined version should filter these out if email key is missing.
#     assert read_users_from_csv() == ["good@example.com"]


def test_write_user_to_csv_creates_file_with_header():
    """Test write_user_to_csv creates a new file with a header if it doesn't exist."""
    # File initially does not exist due to fixture
    user = RegisterUser(username="newuser", email="new@example.com")
    write_user_to_csv(user)

    assert os.path.exists(TEST_CSV_FILE)
    content = read_actual_csv_content()
    assert len(content) == 1
    assert content[0]["username"] == "newuser"
    assert content[0]["email"] == "new@example.com"

    # Verify header exists (by checking fieldnames of the first read row)
    with open(TEST_CSV_FILE, mode='r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        assert reader.fieldnames == ["username", "email"]


def test_write_user_to_csv_appends_to_existing_file():
    """Test write_user_to_csv appends to an existing file without rewriting header."""
    # Create an initial user
    user1 = RegisterUser(username="user1", email="user1@example.com")
    write_user_to_csv(user1)

    # Write a second user
    user2 = RegisterUser(username="user2", email="user2@example.com")
    write_user_to_csv(user2)

    content = read_actual_csv_content()
    assert len(content) == 2
    assert content[0]["username"] == "user1"
    assert content[0]["email"] == "user1@example.com"
    assert content[1]["username"] == "user2"
    assert content[1]["email"] == "user2@example.com"

    # Check that header is not written twice (simple line count check)
    with open(TEST_CSV_FILE, mode='r', encoding='utf-8') as f:
        lines = f.readlines()
        assert len(lines) == 3 # 1 header line + 2 data lines
        assert lines[0].strip() == "username,email"