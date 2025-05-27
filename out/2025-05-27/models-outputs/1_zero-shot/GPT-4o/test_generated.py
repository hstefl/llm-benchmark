from unittest.mock import mock_open, patch

import pytest
from fastapi.testclient import TestClient
from main import RegisterUser, app

client = TestClient(app)

@pytest.fixture
def sample_user():
    return {"username": "testuser", "email": "test@example.com"}

def test_successful_registration(sample_user):
    with patch("main.read_users_from_csv", return_value=[]), \
         patch("main.write_user_to_csv") as mock_write:
        response = client.post("/register/", json=sample_user)
        assert response.status_code == 200
        assert response.json() == {"message": "User registered successfully"}
        mock_write.assert_called_once()

def test_missing_username():
    data = {"email": "test@example.com"}
    response = client.post("/register/", json=data)
    assert response.status_code == 422
    assert "username" in response.text

def test_missing_email():
    data = {"username": "testuser"}
    response = client.post("/register/", json=data)
    assert response.status_code == 422
    assert "email" in response.text

def test_invalid_email_format():
    data = {"username": "testuser", "email": "not-an-email"}
    response = client.post("/register/", json=data)
    assert response.status_code == 422
    assert "value is not a valid email address" in response.text

def test_duplicate_email(sample_user):
    with patch("main.read_users_from_csv", return_value=[sample_user["email"]]):
        response = client.post("/register/", json=sample_user)
        assert response.status_code == 400
        assert response.json()["detail"] == "Email already registered"

def test_write_user_to_csv_creates_file():
    user = RegisterUser(username="newuser", email="new@example.com")
    mock_file = mock_open()
    with patch("builtins.open", mock_file), \
         patch("os.path.exists", return_value=False):
        from main import write_user_to_csv
        write_user_to_csv(user)
        mock_file.assert_called_once_with("users.csv", mode="a", newline="", encoding="utf-8")

def test_read_users_from_csv_file_not_exist():
    with patch("os.path.exists", return_value=False):
        from main import read_users_from_csv
        assert read_users_from_csv() == []
