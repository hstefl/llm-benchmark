Please generate a full unit test suite for the FastAPI project below. Quality of tests will be measured by following metrics. 
Make sure that the provided test has highest possible score in each metric:
 * Test coverage (measured with coverage)
 * Logic mutations (measured with mutmut)
 * Efficient test execution time (analyzed mock usage by human/LLM)
 * Complies with common standards (pass 'ruff' analyzer without issues, ignored rules will be: ["S101", "ANN201", "D103", "ANN001", "PLR2004", "INP001", "D100", "D212", "D203", "D211", "ERA001"])
 * Tests isolation and possibility to run them in parallel (validated by human / LLM)
 * Readability and descriptiveness test names (validated by human / LLM)
 * Assert messages are clear and helpful  (validated by human / LLM)
 * Number and quality of tests for each violation of the functional requirements. If code violate requirement, test must fail. (validated by human / LLM) 
 * Number and quality of tests for each case of already existing bug in code. If code has a bug, test must fail. (validated by human / LLM)
 * Number and quality of tests aligned with - the code is inherently secure and prevents any malicious techniques from compromising the system. If code has a vulnerability, test must fail. (validated by human / LLM)
 * Number and quality of tests which are grounded in general knowledge or implicit rules not explicitly detailed in the specification—design. If code has a bug, test must fail.  (validated by human / LLM)
Also:
 * Do not modify input application
 * Use latest stable versions of tooling (for example httpx 0.28.1)

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