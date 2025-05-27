# LLM Unit Test Generation Benchmark

## Goal

Evaluate how well large language models (LLMs) can generate **high-quality unit tests** for Python projects.  
The initial domain focuses on a FastAPI-based user registration API.

## Benchmark Structure
Each benchmark run evaluates an LLM’s ability to generate test code based on:
 * A business-style specification (non-technical) - see prompts in `in/prompts`
 * The actual Python source code under test - see `in/app/main.py`
 * A defined prompting strategy (zero-shot, instructional, metric aware, etc.) - see prompts in `in/prompts`
 * Test outputs are then measured across multiple technical and behavioral metrics.

## Scoring Criteria

| Category                | Metric                  | Symbol | Range | Tool/Method            | Description                                                            | Weight |
| ----------------------- | ----------------------- | ------ | ----- |------------------------|------------------------------------------------------------------------| ------ |
| Code Coverage           | Coverage (%)            | `C`    | 0–100 | `coverage.py`          | Measures how much of the app's code is exercised by tests              | 18%    |
| Mutation Score       | Mutation (%)            | `M`    | 0–100 | `mutmut`               | Detects whether tests catch logic changes                              | 18%    |
| Runtime Efficiency    | Runtime Efficiency      | `R`    | 0–1   | Timing + I/O detection | Were mocks used appropriatelly to isolate I/O operations?              | 10%    |
| Style Compliance     | Style/Typing Compliance | `S`    | 0–1   | `ruff`                 | Checks formatting, linting, and type correctness                       | 10%    |
| Test Name Quality    | Descriptive Test Names  | `D`    | 0–1   | manually               | Assesses whether test names are clear and meaningful                   | 12%    |
| Assert Message Clarity | Assert Clarity          | `A`    | 0–1   | manually               | Determines if assertion messages are informative and human-friendly    | 7%     |
| Bug Detection Score  | Bugs Found              | `B`    | 0–1   | manually | Fraction of pre-defined spec bugs caught by tests                      | 15%    |
| Functional Validity  | Functional Validity     | `F`    | 0–1   | LLM / manually           | Overall sanity of the test suite; if 0, suite is excluded from scoring | 10%    |

# How to

# New run
Create new directory structure in `out/`. You can use script `prepare_output_dirs.sh` passing argument of name run. Conventions is 
Data when run started in format YYYY-MM-DD, eg. `prepare_output_dirs.sh 2025-08-25`.

## Prompting and result collecting
Choose one prompt from `in/prompts`, the files are named by prompty type (zero-shot, ...) and use it against target model.
Store result into `out/RUN_NAME/models-outputs/PROMPT_TYPE/MODEL_NAME/test_generated.py`.
Also store link (if exists) to web ui where prompt was used into `out/RUN_NAME/models-outputs/PROMPT_TYPE/MODEL_NAME/link`.

## Output refining
### Fix imports
In case that imports are wrong, they are fixed manually before benchmarking.

### Code coverage (`C`)
pycharm run configuration
```bash
cd $PROJECT_ROOT
.venv/bin/coverage run -m pytest $TEST_FILEPATH
.venv/bin/coverage report
```

## Mutation score (`M`)
Tests which fails will be disabled for mutation testing (no matter whether are valid or not)
This is not optional, better approach would be execute testing over fully fixed application.
This will be done in next iterations.

```bash
./run_mutmut.sh
```

## Runtime efficiency (`R`)
Check manually, or with help of prompts bellow (which is not much helpful, yet) whether generated code uses mock properly.

## Style Compliance (`S`)
```bash
cd $PROJECT_ROOT
.venv/bin/ruff check $TEST_FILEPATH
```

## Test Name Quality (`D`)
Validate manually.

## Assert Message Clarity (`A`)
Validate manually.

## Bug Scenarios to Detect (`B`)

| ID  | Bug Description                                                    |
|-----|--------------------------------------------------------------------|
| B1  | Case-insensitive email duplication (`Test@x.com` vs `test@x.com`)  |
| B2  | Username not trimmed (`" alice "` vs `"alice"`)                    |
| B3  | Email with leading/trailing whitespace                             |
| B4  | Extremely long usernames accepted                                  |
| B5  | Duplicate usernames allowed (different emails)                     |
| B6  | Unicode variants treated as different (`é` vs `é`)                |
| B7  | CSV injection risk (`=1+1`, `@SUM(...)`) in username or email      |
| B8  | Username case sensitivity not handled (`Alice` vs `alice`)         |
| B9  | Model `RegisterUser` valides whether input is string or email - no |
| B10 | Extra field sent into /register, no rejection                      |
...


## Functional Validity (`F`) Scoring

| `F` Score | Criteria                                                                 |
|-----------|--------------------------------------------------------------------------|
| 1.0       | All tests are valid, runnable, and reflect the functional spec           |
| 0.5       | Some tests are vague, redundant, or contradict the spirit of the spec    |
| 0.0       | Tests are broken, assert nonsense, contradict spec, or do nothing        |

> ❗ **Test suites with `F = 0` are excluded from all further evaluation.**  
> That means they are not scored for coverage, mutation, runtime, or bugs.


### Eliminate invalid test
You can check them manually or use following prompt. Please note the prompt is not 100% bullet proof, s
for example it has problem to identify correct usage of mocks frequently.

-----------------------------------------------------------------------------------
Check whether all listed tests are aligned with specification, and logically valid. Provide simple table where
Is clearly visible result, do not generate any additional text. Also add information whether mocks are used properly 
(there are no i/o interactions (so for example no file is created and used during testing) or 3rd party system 
interactions) and all test are isolated as well (they are able to run in random order and they do not 
share global state).

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
 
### Test to validate
 PASTE YOUR TEST HERE

-----------------------------------------------------------------------------------


