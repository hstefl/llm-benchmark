Write a complete unit test suite for the following application bellow:

### Functional Requirements on application
 * There should be a single API endpoint where users can send their username and email to register.
 * The system must store the registered users persistently.
 * On any inappropriate input (e.g., missing fields, invalid format, duplicate entries), the application should
   reject the request with a clear error message and the appropriate HTTP status code.
 * Each user must provide both a username and an email.
 * Both the username and the email will be used in the future as credentials to log into the
   system (login functionality is planned but not yet implemented).
 * If the registration is successful, the API should respond with a clear confirmation message.

### Application Code
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