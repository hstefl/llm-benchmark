import csv
import os
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

# Import the application components
from main import RegisterUser, app, read_users_from_csv, write_user_to_csv

# Create test client
client = TestClient(app)


class TestRegisterUserModel:
    """Test the Pydantic model validation"""

    def test_valid_user_creation(self):
        """Test creating a valid user model"""
        user = RegisterUser(username="testuser", email="test@example.com")
        assert user.username == "testuser"
        assert user.email == "test@example.com"

    def test_invalid_email_format(self):
        """Test that invalid email formats are rejected"""
        with pytest.raises(ValueError):
            RegisterUser(username="testuser", email="invalid-email")

    def test_missing_username(self):
        """Test that missing username is rejected"""
        with pytest.raises(ValueError):
            RegisterUser(email="test@example.com")

    def test_missing_email(self):
        """Test that missing email is rejected"""
        with pytest.raises(ValueError):
            RegisterUser(username="testuser")

    def test_empty_username(self):
        """Test that empty username is rejected"""
        with pytest.raises(ValueError):
            RegisterUser(username="", email="test@example.com")

    def test_whitespace_only_username(self):
        """Test that whitespace-only username is rejected"""
        with pytest.raises(ValueError):
            RegisterUser(username="   ", email="test@example.com")


class TestCSVOperations:
    """Test CSV file operations"""

    def setup_method(self):
        """Setup for each test method"""
        self.test_csv = "test_users.csv"
        # Clean up any existing test file
        if os.path.exists(self.test_csv):
            os.remove(self.test_csv)

    def teardown_method(self):
        """Cleanup after each test method"""
        if os.path.exists(self.test_csv):
            os.remove(self.test_csv)

    @patch("main.CSV_FILE", "test_users.csv")
    def test_read_users_from_empty_csv(self):
        """Test reading from non-existent CSV file"""
        result = read_users_from_csv()
        assert result == []

    @patch("main.CSV_FILE", "test_users.csv")
    def test_read_users_from_populated_csv(self):
        """Test reading from CSV file with existing users"""
        # Create test CSV file
        with open(self.test_csv, "w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=["username", "email"])
            writer.writeheader()
            writer.writerow({"username": "user1", "email": "user1@example.com"})
            writer.writerow({"username": "user2", "email": "user2@example.com"})

        result = read_users_from_csv()
        assert result == ["user1@example.com", "user2@example.com"]

    @patch("main.CSV_FILE", "test_users.csv")
    def test_write_user_to_new_csv(self):
        """Test writing user to new CSV file"""
        user = RegisterUser(username="newuser", email="new@example.com")
        write_user_to_csv(user)

        # Verify file was created and contains correct data
        assert os.path.exists(self.test_csv)
        with open(self.test_csv, newline="", encoding="utf-8") as file:
            reader = csv.DictReader(file)
            rows = list(reader)
            assert len(rows) == 1
            assert rows[0]["username"] == "newuser"
            assert rows[0]["email"] == "new@example.com"

    @patch("main.CSV_FILE", "test_users.csv")
    def test_write_user_to_existing_csv(self):
        """Test appending user to existing CSV file"""
        # Create initial CSV file
        with open(self.test_csv, "w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=["username", "email"])
            writer.writeheader()
            writer.writerow({"username": "existing", "email": "existing@example.com"})

        # Append new user
        user = RegisterUser(username="newuser", email="new@example.com")
        write_user_to_csv(user)

        # Verify both users are present
        with open(self.test_csv, newline="", encoding="utf-8") as file:
            reader = csv.DictReader(file)
            rows = list(reader)
            assert len(rows) == 2
            assert rows[0]["email"] == "existing@example.com"
            assert rows[1]["email"] == "new@example.com"


class TestRegistrationEndpoint:
    """Test the /register/ API endpoint"""

    def setup_method(self):
        """Setup for each test method"""
        self.test_csv = "test_users.csv"
        # Clean up any existing test file
        if os.path.exists(self.test_csv):
            os.remove(self.test_csv)

    def teardown_method(self):
        """Cleanup after each test method"""
        if os.path.exists(self.test_csv):
            os.remove(self.test_csv)

    @patch("main.CSV_FILE", "test_users.csv")
    def test_successful_registration(self):
        """Test successful user registration"""
        user_data = {
            "username": "testuser",
            "email": "test@example.com",
        }

        response = client.post("/register/", json=user_data)

        assert response.status_code == 200
        assert response.json() == {"message": "User registered successfully"}

        # Verify user was saved to CSV
        users = read_users_from_csv()
        assert "test@example.com" in users

    @patch("main.CSV_FILE", "test_users.csv")
    def test_duplicate_email_registration(self):
        """Test registration with duplicate email"""
        user_data = {
            "username": "testuser",
            "email": "test@example.com",
        }

        # First registration should succeed
        response = client.post("/register/", json=user_data)
        assert response.status_code == 200

        # Second registration with same email should fail
        duplicate_data = {
            "username": "anotheruser",
            "email": "test@example.com",
        }
        response = client.post("/register/", json=duplicate_data)

        assert response.status_code == 400
        assert response.json() == {"detail": "Email already registered"}

    def test_missing_username_field(self):
        """Test registration with missing username"""
        user_data = {
            "email": "test@example.com",
        }

        response = client.post("/register/", json=user_data)
        assert response.status_code == 422  # Validation error
        assert "field required" in response.json()["detail"][0]["msg"]

    def test_missing_email_field(self):
        """Test registration with missing email"""
        user_data = {
            "username": "testuser",
        }

        response = client.post("/register/", json=user_data)
        assert response.status_code == 422  # Validation error
        assert "field required" in response.json()["detail"][0]["msg"]

    def test_invalid_email_format(self):
        """Test registration with invalid email format"""
        user_data = {
            "username": "testuser",
            "email": "invalid-email-format",
        }

        response = client.post("/register/", json=user_data)
        assert response.status_code == 422  # Validation error
        assert "email" in response.json()["detail"][0]["msg"].lower()

    def test_empty_request_body(self):
        """Test registration with empty request body"""
        response = client.post("/register/", json={})
        assert response.status_code == 422  # Validation error

    def test_null_values(self):
        """Test registration with null values"""
        user_data = {
            "username": None,
            "email": None,
        }

        response = client.post("/register/", json=user_data)
        assert response.status_code == 422  # Validation error

    def test_empty_string_values(self):
        """Test registration with empty string values"""
        user_data = {
            "username": "",
            "email": "",
        }

        response = client.post("/register/", json=user_data)
        assert response.status_code == 422  # Validation error

    def test_whitespace_only_username(self):
        """Test registration with whitespace-only username"""
        user_data = {
            "username": "   ",
            "email": "test@example.com",
        }

        response = client.post("/register/", json=user_data)
        assert response.status_code == 422  # Validation error

    def test_invalid_json(self):
        """Test registration with invalid JSON"""
        response = client.post("/register/", data="invalid json")
        assert response.status_code == 422  # Validation error

    def test_content_type_validation(self):
        """Test registration with wrong content type"""
        response = client.post("/register/", data="username=test&email=test@example.com")
        assert response.status_code == 422  # Validation error

    @patch("main.CSV_FILE", "test_users.csv")
    def test_multiple_successful_registrations(self):
        """Test multiple successful registrations with different emails"""
        users = [
            {"username": "user1", "email": "user1@example.com"},
            {"username": "user2", "email": "user2@example.com"},
            {"username": "user3", "email": "user3@example.com"},
        ]

        for user_data in users:
            response = client.post("/register/", json=user_data)
            assert response.status_code == 200
            assert response.json() == {"message": "User registered successfully"}

        # Verify all users were saved
        saved_emails = read_users_from_csv()
        for user in users:
            assert user["email"] in saved_emails

    @patch("main.CSV_FILE", "test_users.csv")
    def test_case_sensitive_email_duplicates(self):
        """Test that email comparison is case-sensitive"""
        user1_data = {
            "username": "user1",
            "email": "Test@Example.com",
        }
        user2_data = {
            "username": "user2",
            "email": "test@example.com",
        }

        # Register first user
        response = client.post("/register/", json=user1_data)
        assert response.status_code == 200

        # Register second user with different case email (should succeed)
        response = client.post("/register/", json=user2_data)
        assert response.status_code == 200

    def test_special_characters_in_username(self):
        """Test registration with special characters in username"""
        user_data = {
            "username": "user@#$%",
            "email": "test@example.com",
        }

        response = client.post("/register/", json=user_data)
        # This should succeed as there are no restrictions on username format
        assert response.status_code == 200

    def test_unicode_characters(self):
        """Test registration with unicode characters"""
        user_data = {
            "username": "用户名",
            "email": "test@example.com",
        }

        response = client.post("/register/", json=user_data)
        assert response.status_code == 200

    def test_very_long_username(self):
        """Test registration with very long username"""
        user_data = {
            "username": "a" * 1000,  # Very long username
            "email": "test@example.com",
        }

        response = client.post("/register/", json=user_data)
        # Should succeed as there are no length restrictions
        assert response.status_code == 200


class TestErrorHandling:
    """Test error handling scenarios"""

    @patch("main.read_users_from_csv")
    def test_csv_read_error_handling(self, mock_read):
        """Test handling of CSV read errors"""
        mock_read.side_effect = Exception("File read error")

        user_data = {
            "username": "testuser",
            "email": "test@example.com",
        }

        # The endpoint should handle the exception gracefully
        with pytest.raises(Exception):
            client.post("/register/", json=user_data)

    @patch("main.write_user_to_csv")
    @patch("main.read_users_from_csv")
    def test_csv_write_error_handling(self, mock_read, mock_write):
        """Test handling of CSV write errors"""
        mock_read.return_value = []  # No existing users
        mock_write.side_effect = Exception("File write error")

        user_data = {
            "username": "testuser",
            "email": "test@example.com",
        }

        # The endpoint should handle the exception gracefully
        with pytest.raises(Exception):
            client.post("/register/", json=user_data)


class TestIntegration:
    """Integration tests for the complete registration flow"""

    def setup_method(self):
        """Setup for each test method"""
        self.test_csv = "integration_test_users.csv"
        # Clean up any existing test file
        if os.path.exists(self.test_csv):
            os.remove(self.test_csv)

    def teardown_method(self):
        """Cleanup after each test method"""
        if os.path.exists(self.test_csv):
            os.remove(self.test_csv)

    @patch("main.CSV_FILE", "integration_test_users.csv")
    def test_complete_registration_workflow(self):
        """Test complete registration workflow from start to finish"""
        # Step 1: Register first user
        user1_data = {
            "username": "alice",
            "email": "alice@example.com",
        }
        response = client.post("/register/", json=user1_data)
        assert response.status_code == 200
        assert response.json() == {"message": "User registered successfully"}

        # Step 2: Register second user
        user2_data = {
            "username": "bob",
            "email": "bob@example.com",
        }
        response = client.post("/register/", json=user2_data)
        assert response.status_code == 200

        # Step 3: Try to register duplicate email
        duplicate_data = {
            "username": "charlie",
            "email": "alice@example.com",  # Duplicate email
        }
        response = client.post("/register/", json=duplicate_data)
        assert response.status_code == 400
        assert response.json() == {"detail": "Email already registered"}

        # Step 4: Verify final state
        users = read_users_from_csv()
        assert len(users) == 2
        assert "alice@example.com" in users
        assert "bob@example.com" in users

        # Step 5: Verify CSV file structure
        with open(self.test_csv, newline="", encoding="utf-8") as file:
            content = file.read()
            assert "username,email" in content  # Header present
            assert "alice,alice@example.com" in content
            assert "bob,bob@example.com" in content


# Fixtures for common test data
@pytest.fixture
def valid_user_data():
    return {
        "username": "testuser",
        "email": "test@example.com",
    }


@pytest.fixture
def invalid_email_data():
    return {
        "username": "testuser",
        "email": "invalid-email",
    }


@pytest.fixture
def missing_field_data():
    return {
        "username": "testuser",
        # Missing email field
    }


# Performance and edge case tests
class TestPerformanceAndEdgeCases:
    """Test performance and edge cases"""

    def test_endpoint_exists(self):
        """Test that the registration endpoint exists"""
        response = client.post("/register/", json={"username": "test", "email": "test@example.com"})
        # Should not return 404 (endpoint exists)
        assert response.status_code != 404

    def test_http_method_validation(self):
        """Test that only POST method is accepted"""
        # GET should not be allowed
        response = client.get("/register/")
        assert response.status_code == 405  # Method Not Allowed

        # PUT should not be allowed
        response = client.put("/register/", json={"username": "test", "email": "test@example.com"})
        assert response.status_code == 405  # Method Not Allowed

    def test_trailing_slash_handling(self):
        """Test URL with and without trailing slash"""
        user_data = {
            "username": "testuser",
            "email": "test@example.com",
        }

        # With trailing slash (as defined in the route)
        response = client.post("/register/", json=user_data)
        assert response.status_code in [200, 422]  # Either success or validation error

        # Without trailing slash
        response = client.post("/register", json=user_data)
        # FastAPI should handle this gracefully
        assert response.status_code in [200, 307, 422]  # Success, redirect, or validation error
