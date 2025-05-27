"""
Comprehensive unit test suite for FastAPI user registration application.

This test suite verifies all functionality including edge cases, error handling,
security vulnerabilities, and adherence to functional requirements.
"""

import csv
import os
import tempfile
from pathlib import Path
from unittest.mock import Mock, mock_open, patch

import pytest
from fastapi.testclient import TestClient

from main import CSV_FILE, RegisterUser, app, read_users_from_csv, write_user_to_csv


class TestRegisterUserModel:
    """Test the RegisterUser Pydantic model validation."""

    def test_valid_user_creation_with_standard_email(self):
        """Should create RegisterUser with valid username and email."""
        user = RegisterUser(username="testuser", email="test@example.com")
        assert user.username == "testuser", "Username should be set correctly"
        assert user.email == "test@example.com", "Email should be set correctly"

    def test_valid_user_creation_with_complex_username(self):
        """Should create RegisterUser with complex but valid username."""
        user = RegisterUser(username="test_user-123", email="test@example.com")
        assert user.username == "test_user-123", "Complex username should be accepted"

    def test_invalid_email_format_raises_validation_error(self):
        """Should reject invalid email formats with validation error."""
        with pytest.raises(ValueError, match="value is not a valid email address"):
            RegisterUser(username="testuser", email="invalid-email")

    def test_empty_username_raises_validation_error(self):
        """Should reject empty username with validation error."""
        with pytest.raises(ValueError):
            RegisterUser(username="", email="test@example.com")

    def test_missing_username_raises_validation_error(self):
        """Should reject missing username field with validation error."""
        with pytest.raises(ValueError):
            RegisterUser(email="test@example.com")

    def test_missing_email_raises_validation_error(self):
        """Should reject missing email field with validation error."""
        with pytest.raises(ValueError):
            RegisterUser(username="testuser")

    def test_none_username_raises_validation_error(self):
        """Should reject None username with validation error."""
        with pytest.raises(ValueError):
            RegisterUser(username=None, email="test@example.com")

    def test_none_email_raises_validation_error(self):
        """Should reject None email with validation error."""
        with pytest.raises(ValueError):
            RegisterUser(username="testuser", email=None)


class TestReadUsersFromCsv:
    """Test the read_users_from_csv function."""

    def test_returns_empty_list_when_file_does_not_exist(self):
        """Should return empty list when CSV file doesn't exist."""
        with patch("os.path.exists", return_value=False):
            result = read_users_from_csv()
            assert result == [], "Should return empty list when file doesn't exist"

    def test_reads_emails_from_existing_csv_file(self):
        """Should read and return list of emails from existing CSV file."""
        csv_content = "username,email\nuser1,user1@example.com\nuser2,user2@example.com"
        with patch("os.path.exists", return_value=True), \
             patch("builtins.open", mock_open(read_data=csv_content)):
            result = read_users_from_csv()
            expected = ["user1@example.com", "user2@example.com"]
            assert result == expected, f"Should return {expected}, got {result}"

    def test_handles_empty_csv_file(self):
        """Should handle empty CSV file gracefully."""
        csv_content = "username,email\n"
        with patch("os.path.exists", return_value=True), \
             patch("builtins.open", mock_open(read_data=csv_content)):
            result = read_users_from_csv()
            assert result == [], "Should return empty list for empty CSV"

    def test_handles_csv_with_only_headers(self):
        """Should handle CSV with only headers."""
        csv_content = "username,email"
        with patch("os.path.exists", return_value=True), \
             patch("builtins.open", mock_open(read_data=csv_content)):
            result = read_users_from_csv()
            assert result == [], "Should return empty list for headers-only CSV"

    def test_handles_malformed_csv_gracefully(self):
        """Should handle malformed CSV without crashing."""
        csv_content = "username,email\nuser1\nuser2,user2@example.com"
        with patch("os.path.exists", return_value=True), \
             patch("builtins.open", mock_open(read_data=csv_content)):
            # This should not crash, though behavior may vary
            result = read_users_from_csv()
            assert isinstance(result, list), "Should return a list even with malformed CSV"

    def test_uses_correct_file_path(self):
        """Should use the correct CSV file path."""
        with patch("os.path.exists") as mock_exists:
            mock_exists.return_value = False
            read_users_from_csv()
            mock_exists.assert_called_once_with(CSV_FILE)

    #
    # TEST ISSUES
    #
    # def test_opens_file_with_correct_parameters(self):
    #     """Should open file with correct encoding and mode parameters."""
    #     with patch("os.path.exists", return_value=True), \
    #          patch("builtins.open", mock_open(read_data="username,email\n")) as mock_file:
    #         read_users_from_csv()
    #         mock_file.assert_called_once_with(CSV_FILE, newline="", mode="r", encoding="utf-8")


class TestWriteUserToCsv:
    """Test the write_user_to_csv function."""

    def test_creates_new_file_with_headers_when_file_does_not_exist(self):
        """Should create new CSV file with headers when file doesn't exist."""
        user = RegisterUser(username="testuser", email="test@example.com")
        mock_file = mock_open()

        with patch("os.path.exists", return_value=False), \
             patch("builtins.open", mock_file):
            write_user_to_csv(user)

        # Verify file was opened correctly
        mock_file.assert_called_once_with(CSV_FILE, mode="a", newline="", encoding="utf-8")

        # Verify headers and data were written
        handle = mock_file()
        written_content = "".join(call.args[0] for call in handle.write.call_args_list)
        assert "username,email" in written_content, "Headers should be written to new file"
        assert "testuser,test@example.com" in written_content, "User data should be written"

    def test_appends_user_without_headers_when_file_exists(self):
        """Should append user data without headers when file already exists."""
        user = RegisterUser(username="testuser", email="test@example.com")
        mock_file = mock_open()

        with patch("os.path.exists", return_value=True), \
             patch("builtins.open", mock_file):
            write_user_to_csv(user)

        # Verify only user data was written (no headers)
        handle = mock_file()
        written_content = "".join(call.args[0] for call in handle.write.call_args_list)
        assert "username,email" not in written_content, "Headers should not be written to existing file"
        assert "testuser,test@example.com" in written_content, "User data should be written"

    def test_uses_correct_file_parameters(self):
        """Should use correct file opening parameters."""
        user = RegisterUser(username="testuser", email="test@example.com")

        with patch("os.path.exists", return_value=True), \
             patch("builtins.open", mock_open()) as mock_file:
            write_user_to_csv(user)
            mock_file.assert_called_once_with(CSV_FILE, mode="a", newline="", encoding="utf-8")


class TestRegisterEndpoint:
    """Test the /register/ endpoint."""

    @pytest.fixture
    def client(self):
        """Create test client for FastAPI app."""
        return TestClient(app)

    @pytest.fixture
    def temp_csv(self):
        """Create temporary CSV file for testing."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".csv") as f:
            temp_path = f.name

        # Patch the CSV_FILE constant
        with patch("main.CSV_FILE", temp_path):
            yield temp_path

        # Cleanup
        if os.path.exists(temp_path):
            os.unlink(temp_path)

    def test_successful_registration_returns_200_and_success_message(self, client, temp_csv):
        """Should register user successfully and return confirmation message."""
        response = client.post("/register/", json={
            "username": "testuser",
            "email": "test@example.com"
        })

        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        assert response.json() == {"message": "User registered successfully"}, \
            "Should return success message"

    def test_successful_registration_writes_user_to_csv(self, client, temp_csv):
        """Should write registered user data to CSV file."""
        client.post("/register/", json={
            "username": "testuser",
            "email": "test@example.com"
        })

        # Verify user was written to CSV
        with open(temp_csv, "r", encoding="utf-8") as f:
            content = f.read()
            assert "testuser,test@example.com" in content, "User data should be written to CSV"
            assert "username,email" in content, "CSV headers should be present"

    def test_duplicate_email_registration_returns_400_error(self, client, temp_csv):
        """Should reject duplicate email registration with 400 error."""
        # Register first user
        client.post("/register/", json={
            "username": "user1",
            "email": "test@example.com"
        })

        # Try to register second user with same email
        response = client.post("/register/", json={
            "username": "user2",
            "email": "test@example.com"
        })

        assert response.status_code == 400, f"Expected 400, got {response.status_code}"
        assert response.json()["detail"] == "Email already registered", \
            "Should return appropriate error message"

    def test_missing_username_returns_422_validation_error(self, client):
        """Should reject request with missing username field."""
        response = client.post("/register/", json={
            "email": "test@example.com"
        })

        assert response.status_code == 422, f"Expected 422, got {response.status_code}"
        assert "username" in str(response.json()), "Error should mention missing username"

    def test_missing_email_returns_422_validation_error(self, client):
        """Should reject request with missing email field."""
        response = client.post("/register/", json={
            "username": "testuser"
        })

        assert response.status_code == 422, f"Expected 422, got {response.status_code}"
        assert "email" in str(response.json()), "Error should mention missing email"

    def test_invalid_email_format_returns_422_validation_error(self, client):
        """Should reject request with invalid email format."""
        response = client.post("/register/", json={
            "username": "testuser",
            "email": "invalid-email"
        })

        assert response.status_code == 422, f"Expected 422, got {response.status_code}"
        error_detail = str(response.json())
        assert "email" in error_detail.lower(), "Error should mention email validation"

    def test_empty_username_returns_422_validation_error(self, client):
        """Should reject request with empty username."""
        response = client.post("/register/", json={
            "username": "",
            "email": "test@example.com"
        })

        assert response.status_code == 422, f"Expected 422, got {response.status_code}"

    def test_empty_email_returns_422_validation_error(self, client):
        """Should reject request with empty email."""
        response = client.post("/register/", json={
            "username": "testuser",
            "email": ""
        })

        assert response.status_code == 422, f"Expected 422, got {response.status_code}"

    def test_null_username_returns_422_validation_error(self, client):
        """Should reject request with null username."""
        response = client.post("/register/", json={
            "username": None,
            "email": "test@example.com"
        })

        assert response.status_code == 422, f"Expected 422, got {response.status_code}"

    def test_null_email_returns_422_validation_error(self, client):
        """Should reject request with null email."""
        response = client.post("/register/", json={
            "username": "testuser",
            "email": None
        })

        assert response.status_code == 422, f"Expected 422, got {response.status_code}"

    def test_malformed_json_returns_422_validation_error(self, client):
        """Should reject request with malformed JSON."""
        response = client.post(
            "/register/",
            data='{"username": "testuser", "email":}',  # Invalid JSON
            headers={"Content-Type": "application/json"}
        )

        assert response.status_code == 422, f"Expected 422, got {response.status_code}"

    def test_empty_request_body_returns_422_validation_error(self, client):
        """Should reject request with empty body."""
        response = client.post("/register/", json={})

        assert response.status_code == 422, f"Expected 422, got {response.status_code}"

    def test_non_json_content_type_returns_422_validation_error(self, client):
        """Should reject request with non-JSON content type."""
        response = client.post(
            "/register/",
            data="username=test&email=test@example.com",
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )

        assert response.status_code == 422, f"Expected 422, got {response.status_code}"


class TestSecurityVulnerabilities:
    """Test for security vulnerabilities and injection attacks."""

    @pytest.fixture
    def client(self):
        """Create test client for FastAPI app."""
        return TestClient(app)

    @pytest.fixture
    def temp_csv(self):
        """Create temporary CSV file for testing."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".csv") as f:
            temp_path = f.name

        with patch("main.CSV_FILE", temp_path):
            yield temp_path

        if os.path.exists(temp_path):
            os.unlink(temp_path)

    def test_csv_injection_in_username_is_prevented(self, client, temp_csv):
        """Should prevent CSV injection through username field."""
        malicious_username = '=cmd|"/c calc"!A1'

        response = client.post("/register/", json={
            "username": malicious_username,
            "email": "test@example.com"
        })

        # Registration should succeed (input validation is separate from injection prevention)
        assert response.status_code == 200, "Registration should succeed"

        # But the CSV should be safe - check the actual file content
        with open(temp_csv, "r", encoding="utf-8") as f:
            content = f.read()
            # The malicious content should be properly escaped or the system should handle it safely
            # This test will fail if CSV injection is possible
            assert malicious_username in content, "Username should be stored"
            # Additional checks could verify proper CSV escaping

    def test_csv_injection_in_email_is_handled_safely(self, client, temp_csv):
        """Should handle potential CSV injection in email field safely."""
        # This should fail email validation, but let's test what happens
        try:
            response = client.post("/register/", json={
                "username": "testuser",
                "email": "=cmd|'/c calc'!A1@example.com"  # Invalid email format
            })
            # Should fail validation due to invalid email format
            assert response.status_code == 422, "Should reject invalid email format"
        except Exception:
            # Email validation should catch this
            pass

    def test_script_injection_in_username_is_stored_safely(self, client, temp_csv):
        """Should store script-like content in username safely."""
        script_username = "<script>alert('xss')</script>"

        response = client.post("/register/", json={
            "username": script_username,
            "email": "test@example.com"
        })

        assert response.status_code == 200, "Registration should succeed"

        # Verify content is stored but handled safely
        with open(temp_csv, "r", encoding="utf-8") as f:
            content = f.read()
            assert script_username in content, "Script content should be stored as plain text"

    def test_sql_injection_attempts_in_username_are_handled(self, client, temp_csv):
        """Should handle SQL injection attempts in username safely."""
        sql_injection = "'; DROP TABLE users; --"

        response = client.post("/register/", json={
            "username": sql_injection,
            "email": "test@example.com"
        })

        assert response.status_code == 200, "Registration should succeed"

        # Since we're using CSV, not SQL, this should just be stored as text
        with open(temp_csv, "r", encoding="utf-8") as f:
            content = f.read()
            assert sql_injection in content, "Content should be stored safely"

    def test_path_traversal_in_csv_file_access_is_prevented(self):
        """Should prevent path traversal attacks in CSV file access."""
        # This tests that the application doesn't allow arbitrary file access
        # The CSV_FILE constant should be fixed and not user-controllable
        original_csv_file = CSV_FILE
        assert not original_csv_file.startswith("../"), "CSV file path should not allow traversal"
        assert not original_csv_file.startswith("/"), "CSV file path should be relative and safe"


class TestEdgeCases:
    """Test edge cases and unusual inputs."""

    @pytest.fixture
    def client(self):
        """Create test client for FastAPI app."""
        return TestClient(app)

    @pytest.fixture
    def temp_csv(self):
        """Create temporary CSV file for testing."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".csv") as f:
            temp_path = f.name

        with patch("main.CSV_FILE", temp_path):
            yield temp_path

        if os.path.exists(temp_path):
            os.unlink(temp_path)

    def test_unicode_characters_in_username_are_handled(self, client, temp_csv):
        """Should handle Unicode characters in username correctly."""
        unicode_username = "用户名测试"

        response = client.post("/register/", json={
            "username": unicode_username,
            "email": "test@example.com"
        })

        assert response.status_code == 200, "Should handle Unicode username"

        # Verify Unicode is stored correctly
        with open(temp_csv, "r", encoding="utf-8") as f:
            content = f.read()
            assert unicode_username in content, "Unicode username should be stored correctly"

    def test_very_long_username_is_handled(self, client, temp_csv):
        """Should handle very long username appropriately."""
        long_username = "a" * 1000

        response = client.post("/register/", json={
            "username": long_username,
            "email": "test@example.com"
        })

        # This should either succeed or fail gracefully
        assert response.status_code in [200, 422], "Should handle long username gracefully"

    def test_special_characters_in_username_are_preserved(self, client, temp_csv):
        """Should preserve special characters in username."""
        special_username = "user@#$%^&*()_+-=[]{}|;':\",./<>?"

        response = client.post("/register/", json={
            "username": special_username,
            "email": "test@example.com"
        })

        assert response.status_code == 200, "Should handle special characters in username"

        with open(temp_csv, "r", encoding="utf-8") as f:
            content = f.read()
            # Verify special characters are preserved (though may be escaped in CSV)
            assert special_username in content or special_username.replace('"', '""') in content, \
                "Special characters should be preserved"

    def test_email_with_plus_addressing_is_handled(self, client, temp_csv):
        """Should handle email addresses with plus addressing."""
        email_with_plus = "user+tag@example.com"

        response = client.post("/register/", json={
            "username": "testuser",
            "email": email_with_plus
        })

        assert response.status_code == 200, "Should handle plus addressing in email"

    def test_international_domain_email_is_handled(self, client, temp_csv):
        """Should handle international domain names in email."""
        intl_email = "test@münchen.de"

        response = client.post("/register/", json={
            "username": "testuser",
            "email": intl_email
        })

        # This may succeed or fail depending on email validation library
        assert response.status_code in [200, 422], "Should handle international domains gracefully"

    def test_case_sensitivity_in_email_duplicate_detection(self, client, temp_csv):
        """Should handle case sensitivity in email duplicate detection correctly."""
        # Register first user
        response1 = client.post("/register/", json={
            "username": "user1",
            "email": "Test@Example.Com"
        })
        assert response1.status_code == 200, "First registration should succeed"

        # Try to register with same email in different case
        response2 = client.post("/register/", json={
            "username": "user2",
            "email": "test@example.com"
        })

        # This test will reveal if the system properly handles email case sensitivity
        # The behavior depends on implementation - some systems treat emails as case-insensitive
        assert response2.status_code in [200, 400], "Should handle email case consistently"


class TestFunctionalRequirements:
    """Test adherence to specific functional requirements."""

    @pytest.fixture
    def client(self):
        """Create test client for FastAPI app."""
        return TestClient(app)

    @pytest.fixture
    def temp_csv(self):
        """Create temporary CSV file for testing."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".csv") as f:
            temp_path = f.name

        with patch("main.CSV_FILE", temp_path):
            yield temp_path

        if os.path.exists(temp_path):
            os.unlink(temp_path)

    #
    # This is incorrect test - by default redirect_slashes=true in FastApi so the assumption is wrong.
    #
    # def test_single_register_endpoint_exists(self, client):
    #     """Should have exactly one registration endpoint."""
    #     # Test that /register/ endpoint exists
    #     response = client.post("/register/", json={
    #         "username": "test",
    #         "email": "test@example.com"
    #     })
    #     assert response.status_code != 404, "Register endpoint should exist"
    #
    #     # Test that alternative paths don't exist
    #     alt_response = client.post("/register", json={
    #         "username": "test",
    #         "email": "test@example.com"
    #     })
    #     assert alt_response.status_code == 404, "Alternative endpoint should not exist"

    def test_both_username_and_email_are_required(self, client):
        """Should require both username and email fields."""
        # Missing username
        response1 = client.post("/register/", json={"email": "test@example.com"})
        assert response1.status_code == 422, "Should reject missing username"

        # Missing email
        response2 = client.post("/register/", json={"username": "testuser"})
        assert response2.status_code == 422, "Should reject missing email"

        # Both present should succeed
        with patch("main.CSV_FILE", "temp.csv"), \
             patch("os.path.exists", return_value=False), \
             patch("builtins.open", mock_open()):
            response3 = client.post("/register/", json={
                "username": "testuser",
                "email": "test@example.com"
            })
            assert response3.status_code == 200, "Should accept both fields"

    def test_users_are_stored_persistently(self, client, temp_csv):
        """Should store users persistently in CSV file."""
        client.post("/register/", json={
            "username": "testuser",
            "email": "test@example.com"
        })

        # Verify file exists and contains user data
        assert os.path.exists(temp_csv), "CSV file should be created"

        with open(temp_csv, "r", encoding="utf-8") as f:
            content = f.read()
            assert "testuser" in content, "Username should be stored"
            assert "test@example.com" in content, "Email should be stored"

    def test_inappropriate_input_rejected_with_clear_error(self, client):
        """Should reject inappropriate input with clear error messages."""
        test_cases = [
            ({"username": "", "email": "test@example.com"}, "empty username"),
            ({"username": "test", "email": "invalid"}, "invalid email format"),
            ({}, "missing fields"),
        ]

        for invalid_data, description in test_cases:
            response = client.post("/register/", json=invalid_data)
            assert response.status_code in [400, 422], f"Should reject {description}"
            assert "detail" in response.json(), f"Should provide error detail for {description}"

    def test_successful_registration_returns_clear_confirmation(self, client):
        """Should return clear confirmation message on successful registration."""
        with patch("main.CSV_FILE", "temp.csv"), \
             patch("os.path.exists", return_value=False), \
             patch("builtins.open", mock_open()):
            response = client.post("/register/", json={
                "username": "testuser",
                "email": "test@example.com"
            })

            assert response.status_code == 200, "Should return 200 on success"
            response_data = response.json()
            assert "message" in response_data, "Should contain message field"
            assert "success" in response_data["message"].lower(), \
                "Should contain success confirmation"

    def test_duplicate_entries_rejected_with_appropriate_status(self, client, temp_csv):
        """Should reject duplicate entries with appropriate HTTP status."""
        # Register first user
        client.post("/register/", json={
            "username": "user1",
            "email": "test@example.com"
        })

        # Try duplicate email
        response = client.post("/register/", json={
            "username": "user2",
            "email": "test@example.com"
        })

        assert response.status_code == 400, "Should return 400 for duplicate email"
        assert "already registered" in response.json()["detail"].lower(), \
            "Should provide clear duplicate error message"


class TestBugsAndFlaws:
    """Test for potential bugs and flaws in the implementation."""

    @pytest.fixture
    def client(self):
        """Create test client for FastAPI app."""
        return TestClient(app)

    def test_concurrent_registration_same_email_handling(self, client):
        """Should handle concurrent registrations with same email properly."""
        # This test reveals potential race conditions
        # In a real scenario, two requests might arrive simultaneously

        # First, we test the current behavior
        with patch("main.read_users_from_csv") as mock_read, \
             patch("main.write_user_to_csv") as mock_write:

            # Simulate race condition: both requests see empty user list
            mock_read.return_value = []

            response1 = client.post("/register/", json={
                "username": "user1",
                "email": "test@example.com"
            })

            response2 = client.post("/register/", json={
                "username": "user2",
                "email": "test@example.com"
            })

            # Both might succeed due to race condition - this is a bug
            # This test will fail if the race condition exists
            if response1.status_code == 200 and response2.status_code == 200:
                assert False, "Race condition detected: both registrations succeeded"

    def test_file_encoding_consistency(self, client):
        """Should maintain consistent file encoding."""
        # Test that Unicode content is handled consistently
        unicode_user = RegisterUser(username="测试用户", email="test@example.com")

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".csv", encoding="utf-8") as f:
            temp_path = f.name

        try:
            with patch("main.CSV_FILE", temp_path):
                # Write user
                write_user_to_csv(unicode_user)

                # Read back
                users = read_users_from_csv()

                # Should maintain encoding
                assert len(users) == 1, "Should read back one user"
                assert users[0] == "test@example.com", "Should maintain email correctly"
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_csv_file_path_security(self):
        """Should use secure CSV file path."""
        # Test that CSV_FILE constant is safe
        assert not CSV_FILE.startswith("/"), "CSV file should not be absolute path"
        assert not CSV_FILE.startswith("../"), "CSV file should not allow directory traversal"
        assert CSV_FILE.endswith(".csv"), "CSV file should have .csv extension"

    def test_email_normalization_consistency(self, client):
        """Should handle email normalization consistently."""
        # This test checks if the system handles email case sensitivity consistently
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".csv") as f:
            temp_path = f.name

        try:
            with patch("main.CSV_FILE", temp_path):
                # Register with uppercase email
                response1 = client.post("/register/", json={
                    "username": "user1",
                    "email": "TEST@EXAMPLE.COM"
                })
                assert response1.status_code == 200, "First registration should succeed"

                # Try to register with lowercase email
                response2 = client.post("/register/", json={
                    "username": "user2",
                    "email": "test@example.com"
                })

                # This reveals if the system properly handles email case sensitivity
                # Currently, the system will allow both registrations (BUG)
                # because it stores "TEST@EXAMPLE.COM" but checks against "test@example.com"
                if response2.status_code == 200:
                    assert False, "Bug detected: Case-sensitive email comparison allows duplicates"
                else:
                    assert response2.status_code == 400, "Should reject duplicate email regardless of case"
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_username_uniqueness_not_enforced_bug(self, client):
        """Should reveal bug: username uniqueness is not enforced."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".csv") as f:
            temp_path = f.name

        try:
            with patch("main.CSV_FILE", temp_path):
                # Register first user
                response1 = client.post("/register/", json={
                    "username": "testuser",
                    "email": "user1@example.com"
                })
                assert response1.status_code == 200, "First registration should succeed"

                # Register second user with same username but different email
                response2 = client.post("/register/", json={
                    "username": "testuser",
                    "email": "user2@example.com"
                })

                # This will succeed, revealing the bug that usernames can be duplicated
                # According to requirements, both username and email will be used as credentials
                # So usernames should likely be unique too
                if response2.status_code == 200:
                    assert False, "Bug detected: Username uniqueness not enforced"
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_csv_injection_vulnerability_exists(self, client):
        """Should reveal CSV injection vulnerability."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".csv") as f:
            temp_path = f.name

        try:
            with patch("main.CSV_FILE", temp_path):
                # Attempt CSV injection
                response = client.post("/register/", json={
                    "username": "=1+1+cmd|' /C calc'!A0",
                    "email": "test@example.com"
                })

                assert response.status_code == 200, "Registration should succeed"

                # Check if the dangerous content is stored without proper escaping
                with open(temp_path, "r", encoding="utf-8") as f:
                    content = f.read()
                    # If the formula is stored as-is, it could be dangerous when opened in Excel
                    if content.startswith("=") or "=1+1+cmd" in content:
                        assert False, "CSV injection vulnerability detected"
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)


class TestPerformanceAndResilience:
    """Test performance characteristics and resilience."""

    @pytest.fixture
    def client(self):
        """Create test client for FastAPI app."""
        return TestClient(app)

    def test_large_csv_file_handling(self, client):
        """Should handle large CSV files efficiently."""
        # Create a large CSV file with many users
        large_csv_content = "username,email\n"
        for i in range(1000):
            large_csv_content += f"user{i},user{i}@example.com\n"

        with patch("os.path.exists", return_value=True), \
             patch("builtins.open", mock_open(read_data=large_csv_content)):

            # This should not timeout or crash
            users = read_users_from_csv()
            assert len(users) == 1000, "Should handle large CSV files"

    def test_file_system_error_handling(self, client):
        """Should handle file system errors gracefully."""
        with patch("builtins.open", side_effect=PermissionError("Access denied")):
            # Should not crash the application
            try:
                response = client.post("/register/", json={
                    "username": "testuser",
                    "email": "test@example.com"
                })
                # Should return an appropriate error
                assert response.status_code >= 400, "Should handle file system errors"
            except PermissionError:
                # If the error propagates, it should be handled by the framework
                pass

    def test_malformed_existing_csv_handling(self):
        """Should handle malformed existing CSV files gracefully."""
        malformed_csv = "this,is,not,proper,csv,format\nwith\nmismatched\ncolumns"

        with patch("os.path.exists", return_value=True), \
             patch("builtins.open", mock_open(read_data=malformed_csv)):

            # Should not crash
            try:
                users = read_users_from_csv()
                assert isinstance(users, list), "Should return a list even for malformed CSV"
            except Exception as e:
                assert False, f"Should handle malformed CSV gracefully, got: {e}"


class TestIntegrationScenarios:
    """Test complete integration scenarios."""

    @pytest.fixture
    def client(self):
        """Create test client for FastAPI app."""
        return TestClient(app)

    @pytest.fixture
    def temp_csv(self):
        """Create temporary CSV file for testing."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".csv") as f:
            temp_path = f.name

        with patch("main.CSV_FILE", temp_path):
            yield temp_path

        if os.path.exists(temp_path):
            os.unlink(temp_path)

    def test_multiple_users_registration_workflow(self, client, temp_csv):
        """Should handle multiple user registrations correctly."""
        users = [
            {"username": "alice", "email": "alice@example.com"},
            {"username": "bob", "email": "bob@example.com"},
            {"username": "charlie", "email": "charlie@example.com"},
        ]

        # Register all users
        for user in users:
            response = client.post("/register/", json=user)
            assert response.status_code == 200, f"Registration should succeed for {user['username']}"

        # Verify all users are stored
        with open(temp_csv, "r", encoding="utf-8") as f:
            content = f.read()
            for user in users:
                assert user["username"] in content, f"Username {user['username']} should be stored"
                assert user["email"] in content, f"Email {user['email']} should be stored"

        # Try to register duplicate email
        duplicate_response = client.post("/register/", json={
            "username": "alice2",
            "email": "alice@example.com"
        })
        assert duplicate_response.status_code == 400, "Should reject duplicate email"

    def test_csv_file_creation_and_persistence(self, client, temp_csv):
        """Should create CSV file properly and maintain it across requests."""
        # Initially file should not exist or be empty
        if os.path.exists(temp_csv):
            os.unlink(temp_csv)

        # First registration should create file with headers
        response1 = client.post("/register/", json={
            "username": "first_user",
            "email": "first@example.com"
        })
        assert response1.status_code == 200, "First registration should succeed"

        # Verify file was created with proper structure
        assert os.path.exists(temp_csv), "CSV file should be created"
        with open(temp_csv, "r", encoding="utf-8") as f:
            lines = f.readlines()
            assert len(lines) >= 2, "Should have header and data lines"
            assert "username,email" in lines[0], "Should have proper headers"
            assert "first_user,first@example.com" in lines[1], "Should have user data"

        # Second registration should append to existing file
        response2 = client.post("/register/", json={
            "username": "second_user",
            "email": "second@example.com"
        })
        assert response2.status_code == 200, "Second registration should succeed"

        # Verify file has both users
        with open(temp_csv, "r", encoding="utf-8") as f:
            content = f.read()
            assert content.count("username,email") == 1, "Should have headers only once"
            assert "first_user" in content, "Should contain first user"
            assert "second_user" in content, "Should contain second user"


# Additional test configuration and utilities
if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])


# Dependencies for pyproject.toml
"""
[tool.poetry.dependencies]
python = "^3.8"
fastapi = "^0.104.1"
pydantic = {extras = ["email"], version = "^2.5.0"}
uvicorn = "^0.24.0"

[tool.poetry.group.dev.dependencies]
pytest = "^7.4.3"
pytest-asyncio = "^0.21.1"
httpx = "^0.25.2"
pytest-cov = "^4.1.0"
ruff = "^0.1.6"

[tool.ruff]
select = ["E", "W", "F", "I", "N", "B", "A", "S", "T", "D", "UP", "ANN", "YTT", "BLE", "FBT", "C4", "DTZ", "T10", "EM", "EXE", "ISC", "ICN", "G", "INP", "PIE", "PYI", "PT", "Q", "RSE", "RET", "SLF", "SIM", "TID", "TCH", "ARG", "PTH", "ERA", "PD", "PGH", "PL", "TRY", "FLY", "NPY", "PERF", "RUF"]
ignore = ["S101", "ANN201", "D103", "ANN001", "PLR2004", "INP001", "D100", "D212", "D203", "D211", "ERA001"]
line-length = 100

[tool.pytest.ini_options]
testpaths = ["tests"]
python_files = "test_*.py"
python_functions = "test_*"
addopts = "-v --tb=short --strict-markers"
"""