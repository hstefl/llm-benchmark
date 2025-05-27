import os

from fastapi.testclient import TestClient

from main import CSV_FILE, app

client = TestClient(app)

def test_register_user_success():
    # Ensure the CSV file is clean before the test
    if os.path.exists(CSV_FILE):
        os.remove(CSV_FILE)

    response = client.post(
        "/register/",
        json={"username": "testuser", "email": "test@example.com"},
    )
    assert response.status_code == 200
    assert response.json() == {"message": "User registered successfully"}

    # Verify the user was written to the CSV
    with open(CSV_FILE, encoding="utf-8") as file:
        content = file.read()
        assert "testuser,test@example.com" in content

def test_register_user_duplicate_email():
    # Ensure a user with the same email is already registered
    if os.path.exists(CSV_FILE):
        os.remove(CSV_FILE)
    with open(CSV_FILE, mode="w", newline="", encoding="utf-8") as file:
        file.write("username,email\n")
        file.write("existinguser,existing@example.com\n")

    response = client.post(
        "/register/",
        json={"username": "anotheruser", "email": "existing@example.com"},
    )
    assert response.status_code == 400
    assert response.json() == {"detail": "Email already registered"}

def test_register_user_missing_username():
    response = client.post(
        "/register/",
        json={"email": "missing_user@example.com"},
    )
    assert response.status_code == 422
    assert "username" in response.json()["detail"][0]["loc"]

def test_register_user_missing_email():
    response = client.post(
        "/register/",
        json={"username": "noemailuser"},
    )
    assert response.status_code == 422
    assert "email" in response.json()["detail"][0]["loc"]

def test_register_user_invalid_email_format():
    response = client.post(
        "/register/",
        json={"username": "invaliduser", "email": "invalid_email"},
    )
    assert response.status_code == 422
    assert "email" in response.json()["detail"][0]["loc"]
    assert "value is not a valid email address" in response.json()["detail"][0]["msg"]

# Clean up the CSV file after all tests
def teardown_module():
    if os.path.exists(CSV_FILE):
        os.remove(CSV_FILE)
