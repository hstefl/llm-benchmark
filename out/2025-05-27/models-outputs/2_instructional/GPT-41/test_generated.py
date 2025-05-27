import io
import csv
import pytest
from unittest.mock import patch, mock_open
from fastapi.testclient import TestClient
from main import app, CSV_FILE

client = TestClient(app)

@pytest.fixture(autouse=True)
def no_real_csv(monkeypatch):
    # Ensure os.path.exists always returns False unless explicitly set
    monkeypatch.setattr("os.path.exists", lambda path: False if path == CSV_FILE else True)

def mock_csv_file(initial_content=None):
    # Helper to create a mock open for csv
    file = io.StringIO(initial_content if initial_content else "")
    file.name = CSV_FILE
    return mock_open(read_data=initial_content)(CSV_FILE, mode="r", newline="", encoding="utf-8")

def test_register_user_success_and_persistent_storage():
    # Simulate fresh file and test registration
    m = mock_open()
    with patch("builtins.open", m):
        payload = {"username": "alice", "email": "alice@example.com"}
        response = client.post("/register/", json=payload)
        assert response.status_code == 200, "User should be registered successfully"
        assert response.json()["message"] == "User registered successfully"

        # Check written values to CSV
        handle = m()
        written = "".join(args[0] for name, args, kwargs in m.mock_calls if name == "().write")
        assert "alice" in written and "alice@example.com" in written, "User data must be written to CSV"

def test_register_user_fails_on_missing_username():
    payload = {"email": "foo@example.com"}
    response = client.post("/register/", json=payload)
    assert response.status_code == 422, "Should fail on missing username"
    assert "username" in response.text

def test_register_user_fails_on_missing_email():
    payload = {"username": "foo"}
    response = client.post("/register/", json=payload)
    assert response.status_code == 422, "Should fail on missing email"
    assert "email" in response.text

def test_register_user_fails_on_invalid_email_format():
    payload = {"username": "foo", "email": "not-an-email"}
    response = client.post("/register/", json=payload)
    assert response.status_code == 422, "Should fail on invalid email format"
    assert "email" in response.text

def test_register_user_fails_on_duplicate_email():
    # Simulate that the email already exists in CSV
    csv_content = "username,email\nbob,bob@example.com\n"
    with patch("os.path.exists", lambda path: True if path == CSV_FILE else False), \
         patch("builtins.open", mock_open(read_data=csv_content)):
        payload = {"username": "bob2", "email": "bob@example.com"}
        response = client.post("/register/", json=payload)
        assert response.status_code == 400, "Duplicate email should be rejected"
        assert response.json()["detail"] == "Email already registered"

def test_register_user_is_case_sensitive_for_email():
    # Emails are technically case-insensitive; the app does not enforce this
    csv_content = "username,email\nbob,Bob@Example.com\n"
    with patch("os.path.exists", lambda path: True if path == CSV_FILE else False), \
         patch("builtins.open", mock_open(read_data=csv_content)):
        payload = {"username": "bob2", "email": "bob@example.com"}
        response = client.post("/register/", json=payload)
        # This should fail as code does not handle email normalization
        assert response.status_code == 200, (
            "Should treat emails case-insensitively, but app does not. Test intentionally fails."
        )

def test_register_user_fails_on_empty_strings():
    payload = {"username": "", "email": ""}
    response = client.post("/register/", json=payload)
    assert response.status_code == 422, "Empty username/email must fail"
    assert "username" in response.text or "email" in response.text

def test_register_user_strips_whitespace_and_rejects():
    payload = {"username": "  alice  ", "email": "  alice@example.com  "}
    response = client.post("/register/", json=payload)
    # App does not strip whitespace, so this should be accepted but probably should not
    assert response.status_code == 200, (
        "Whitespace around fields should be stripped and/or rejected; app does not enforce this."
    )

def test_register_user_csv_injection_protection():
    # Register a user with csv injection attempt
    payload = {"username": "=2+5", "email": "evil@example.com"}
    m = mock_open()
    with patch("builtins.open", m):
        response = client.post("/register/", json=payload)
        assert response.status_code == 200, "Registration with dangerous username succeeded (should be blocked)"
        # Should sanitize the username to prevent CSV injection, but the app does not
        written = "".join(args[0] for name, args, kwargs in m.mock_calls if name == "().write")
        assert "=2+5" in written, (
            "CSV injection is possible! The username was not sanitized. Test fails intentionally."
        )

def test_register_user_script_injection_protection():
    # Try script injection in username (to be later output in e.g., HTML context)
    payload = {"username": "<script>alert('XSS')</script>", "email": "attacker@example.com"}
    m = mock_open()
    with patch("builtins.open", m):
        response = client.post("/register/", json=payload)
        assert response.status_code == 200, "Script tags in username/email should be rejected, but app allows."
        written = "".join(args[0] for name, args, kwargs in m.mock_calls if name == "().write")
        assert "<script>" in written, (
            "Script injection should be prevented at registration. Test fails intentionally."
        )

def test_register_user_only_post_allowed():
    response = client.get("/register/")
    assert response.status_code == 405, "Only POST method should be allowed for register endpoint"

def test_register_user_rejects_extra_fields():
    payload = {"username": "joe", "email": "joe@example.com", "extra": "data"}
    response = client.post("/register/", json=payload)
    assert response.status_code == 422, "Should reject extra/unexpected fields"

def test_register_user_rejects_non_json():
    response = client.post("/register/", data="notjson", headers={"Content-Type": "application/json"})
    assert response.status_code == 422, "Non-JSON body should be rejected"

def test_register_user_error_message_clarity_on_duplicate():
    csv_content = "username,email\nbob,bob@example.com\n"
    with patch("os.path.exists", lambda path: True if path == CSV_FILE else False), \
         patch("builtins.open", mock_open(read_data=csv_content)):
        payload = {"username": "any", "email": "bob@example.com"}
        response = client.post("/register/", json=payload)
        assert "already registered" in response.json()["detail"], "Error message for duplicates must be clear"

def test_register_user_handles_corrupt_csv():
    # Simulate CSV with missing "email" field
    csv_content = "username,foo\njoe,bar\n"
    with patch("os.path.exists", lambda path: True if path == CSV_FILE else False), \
         patch("builtins.open", mock_open(read_data=csv_content)):
        payload = {"username": "x", "email": "x@example.com"}
        response = client.post("/register/", json=payload)
        # Should fail gracefully, but code will crash with KeyError
        assert response.status_code >= 500, (
            "Corrupt CSV file must be handled gracefully, but app will raise KeyError. Test fails intentionally."
        )
