import csv
import os

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr

app = FastAPI()

CSV_FILE = "users.csv"

class RegisterUser(BaseModel):
    username: str
    email: EmailStr

def read_users_from_csv() -> list[str]:
    if not os.path.exists(CSV_FILE):
        return []
    with open(CSV_FILE, newline="", encoding="utf-8") as file:
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
