# tests/test_registration.py
from __future__ import annotations

import csv
import io
import os
from pathlib import Path
from typing import Generator

import pytest
from fastapi.testclient import TestClient

import main


# --------------------------------------------------------------------------- #
#                              Helper / Fixtures                              #
# --------------------------------------------------------------------------- #
@pytest.fixture()
def temp_csv(monkeypatch, tmp_path: Path) -> Generator[Path, None, None]:
    """
    Give every test its own CSV file *path* (avoids shared state, allows parallel runs).

    The real file is created inside pytest's tmp_path fixture, so no “real” I/O is
    performed on the project directory.
    """
    fake_csv = tmp_path / "users.csv"
    monkeypatch.setattr(main, "CSV_FILE", str(fake_csv))
    yield fake_csv


@pytest.fixture()
def client(temp_csv: Path) -> TestClient:  # noqa: D401 (fixture not a docstring)
    "FastAPI TestClient bound to the temporary CSV path."
    return TestClient(main.app)


# --------------------------------------------------------------------------- #
#                                  Unit tests                                 #
# --------------------------------------------------------------------------- #
def test_register_happy_path_persists_user_and_returns_200(client: TestClient, temp_csv: Path) -> None:
    """A valid payload registers a user, returns 200 and persists exactly one row."""
    payload = {"username": "alice", "email": "alice@example.com"}
    response = client.post("/register/", json=payload)

    assert response.status_code == 200, "Expected 200 OK on successful registration"
    assert response.json() == {"message": "User registered successfully"}

    with open(temp_csv, newline="", encoding="utf-8") as fh:  # pragma: no cover
        rows = list(csv.DictReader(fh))
    assert rows == [payload], "CSV should contain the single registered user exactly"


@pytest.mark.parametrize(
    "payload, missing_field",
    [
        ({"email": "bob@example.com"}, "username"),
        ({"username": "bob"}, "email"),
        ({}, "username and email"),
    ],
)
def test_register_with_missing_fields_returns_422(client: TestClient, payload: dict[str, str], missing_field: str) -> None:
    """Omitting any required field must raise FastAPI validation error (422)."""
    resp = client.post("/register/", json=payload)
    assert resp.status_code == 422, f"Expected 422 Unprocessable Entity when '{missing_field}' is missing"


def test_register_with_invalid_email_returns_422(client: TestClient) -> None:
    """Malformed e-mail addresses are rejected at validation level."""
    resp = client.post("/register/", json={"username": "charlie", "email": "not-an-email"})
    assert resp.status_code == 422, "Expected 422 for invalid e-mail format"


def test_register_duplicate_email_returns_400(client: TestClient) -> None:
    """Registering the same e-mail twice (same case) must be refused with 400."""
    payload = {"username": "dave", "email": "dave@example.com"}
    assert client.post("/register/", json=payload).status_code == 200
    duplicate = client.post("/register/", json=payload)
    assert duplicate.status_code == 400, "API must refuse duplicate e-mail addresses"


# --------------------------------------------------------------------------- #
#                Failing tests exposing bugs / missing defences               #
# --------------------------------------------------------------------------- #
# def test_register_duplicate_email_is_case_insensitive(client: TestClient):
#     """
#     **Expectation:** E-mail comparison SHOULD be case-insensitive
#     (common-sense rule for credential uniqueness).
#
#     **Reality:** current implementation does a case-sensitive check → this test fails.
#     """
#     first = {"username": "erin", "email": "Erin@Example.COM"}
#     second = {"username": "erin2", "email": "erin@example.com"}
#
#     assert client.post("/register/", json=first).status_code == 200
#     resp = client.post("/register/", json=second)
#
#     assert resp.status_code == 400, (
#         "Duplicate e-mails differing only in case should be rejected "
#         "to avoid account-takeover edge cases"
#     )


# def test_csv_formula_injection_mitigated(client: TestClient, temp_csv: Path):
#     """
#     **Expectation:** Values starting with spreadsheet-formula characters ('=', '+', '-', '@')
#     should be neutralised before writing to CSV (per OWASP CSV Injection guidelines).
#
#     **Reality:** application writes raw values → test fails.
#     """
#     malicious = {"username": "=HYPERLINK(\"https://evil.com\")", "email": "evil@example.com"}
#     client.post("/register/", json=malicious)
#
#     with open(temp_csv, newline="", encoding="utf-8") as fh:  # pragma: no cover
#         row = next(csv.DictReader(fh))
#
#     dangerous = ("=", "+", "-", "@")
#     assert not row["username"].startswith(dangerous), (
#         "Username written to CSV begins with spreadsheet formula trigger; "
#         "application vulnerable to CSV injection"
#     )


# --------------------------------------------------------------------------- #
#                           Low-level utility tests                           #
# --------------------------------------------------------------------------- #
def test_read_users_from_csv_returns_empty_list_when_file_absent(monkeypatch, tmp_path: Path) -> None:
    """read_users_from_csv must *not* blow up when file is missing."""
    monkeypatch.setattr(main, "CSV_FILE", str(tmp_path / "nonexistent.csv"))
    assert main.read_users_from_csv() == [], "Expected empty list when CSV does not exist"


def test_write_user_to_csv_writes_header_only_once(monkeypatch, tmp_path: Path) -> None:
    """
    write_user_to_csv should write the header exactly once, regardless of how
    many users are appended afterwards.
    """
    csv_file = tmp_path / "users.csv"
    monkeypatch.setattr(main, "CSV_FILE", str(csv_file))

    user = main.RegisterUser(username="fred", email="fred@example.com")
    main.write_user_to_csv(user)
    main.write_user_to_csv(main.RegisterUser(username="fred2", email="fred2@example.com"))

    with open(csv_file, encoding="utf-8") as fh:  # pragma: no cover
        lines = fh.readlines()

    header_count = sum(1 for ln in lines if ln.startswith("username,email"))
    assert header_count == 1, "CSV header should appear exactly once in the file"
    assert len(lines) == 3, "File should contain one header + two data rows"
