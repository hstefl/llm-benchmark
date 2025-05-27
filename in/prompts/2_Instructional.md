You are a professional Python test engineer. Your task is to generate clean,
maintainable unit tests for any given Python project.

Write a complete unit test suite for FastAPI application below. The tests should verify all parts of the system,
including edge cases and error handling. Your tests should follow professional standards. In other words:
 * Achieve high test coverage
 * Test should be resilient for code mutation - so any mutation of correct code, should be caught in case that is the flaw.
 * Be fast (no real IO)
 * Follow good coding standards (pass `ruff` linter, note - ignored rules will be: ["S101", "ANN201", "D103", "ANN001", "PLR2004", "INP001", "D100", "D212", "D203", "D211", "ERA001"]))
 * Each test has to be isolated from each other (no common shared state, test can be executed in parallel)
 * Use easy to understand nad descriptive test names (what is tested and what is expected)
 * Make assert messages clear and helpful
 * If the code violates the functional requirements in any way, the test suite should include a test that fails as a result.
 * If the code contains bug or bugs, the test suite should include a test or tests that fails as a result for each such a case.
 * The code has to be inherently secure and prevent any malicious techniques from compromising the system, including those that target the application directly (e.g., injection) and those that exploit stored values in downstream contexts (e.g., CSV injection, script execution). The test suite should include a test or tests that fails in case vulnerability is present.
 * If there is any general knowledge/rules which is not captured is specification explicitly, and makes sense to test it - prepare test for it. Test must fail if that knowledge is not reflected in a code.
Also:
 * Do not modify application
 * Use latest stable versions of tooling you are using as much as possible, provide list of them including versions (pastable into pyptoject.toml)

### Functional Requirements on Application
 * There should be a single API endpoint where users can send their username and email to register.
 * The system must store the registered users persistently.
 * On any inappropriate input (e.g., missing fields, invalid format, duplicate entries), the application should
   reject the request with a clear error message and the appropriate HTTP status code.
 * Each user must provide both a username and an email.
 * Both the username and the email will be used in the future as credentials to log into the
   system (login functionality is planned but not yet implemented).
 * If the registration is successful, the API should respond with a clear confirmation message.

### Application Code
placed in main.py
```
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr
from typing import List
import csv
import os

app = FastAPI()

CSV_FILE = "users.csv"

class RegisterUser(BaseModel):
    username: str
    email: EmailStr

def read_users_from_csv() -> List[str]:
    if not os.path.exists(CSV_FILE):
        return []
    with open(CSV_FILE, newline="", mode="r", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        return [row["email"] for row in reader]

def write_user_to_csv(user: RegisterUser):
    file_exists = os.path.exists(CSV_FILE)
    with open(CSV_FILE, mode="a", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=["username", "email"])
        if not file_exists:
            writer.writeheader()
        writer.writerow({"username": user.username, "email": user.email})

@app.post("/register/")
async def register_user(user: RegisterUser):
    existing_emails = read_users_from_csv()
    if user.email in existing_emails:
        raise HTTPException(status_code=400, detail="Email already registered")
    write_user_to_csv(user)
    return {"message": "User registered successfully"}
```