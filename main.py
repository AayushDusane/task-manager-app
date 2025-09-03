from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import datetime, timedelta
from typing import Annotated
from fastapi.middleware.cors import CORSMiddleware

# These are for password hashing and JWT token management
from passlib.context import CryptContext
from jose import JWTError, jwt

# Import the Pydantic schemas and our simulated database
from schemas import UserCreate, UserLogin, Token, Task, TaskCreate
from database import user_db, task_db

# Initialize FastAPI
app = FastAPI()

origins = [
    "http://localhost:3000", # The origin of your React app
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Security Configuration ---
# To secure your API, replace this secret key with a strong, random string
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT token management
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

# --- New function to get the current user ---
def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = user_db.get(email)
    if user is None:
        raise credentials_exception
    return user

# --- API Endpoints ---
@app.get("/")
def read_root():
    return {"message": "Hello, World!"}

@app.post("/register", response_model=Token)
def register_user(user: UserCreate):
    if user.email in user_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered."
        )
    hashed_password = get_password_hash(user.password)
    user_db[user.email] = {"email": user.email, "hashed_password": hashed_password}
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/login", response_model=Token)
def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    user_data = user_db.get(form_data.username)
    if not user_data or not verify_password(form_data.password, user_data["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user_data["email"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# --- New Task Endpoints ---
@app.post("/tasks/", response_model=Task)
def create_task(task: TaskCreate, current_user: Annotated[dict, Depends(get_current_user)]):
    task_data = task.model_dump()
    new_task_id = len(task_db) + 1
    new_task = {
        "id": new_task_id,
        **task_data,
        "owner_email": current_user["email"],
    }
    task_db.append(new_task)
    return new_task

@app.get("/tasks/", response_model=list[Task])
def read_tasks(current_user: Annotated[dict, Depends(get_current_user)]):
    # Filter tasks to only show the ones owned by the current user
    return [task for task in task_db if task["owner_email"] == current_user["email"]]

@app.put("/tasks/{task_id}", response_model=Task)
def update_task(task_id: int, task: TaskCreate, current_user: Annotated[dict, Depends(get_current_user)]):
    task_to_update = next((t for t in task_db if t["id"] == task_id and t["owner_email"] == current_user["email"]), None)
    if not task_to_update:
        raise HTTPException(status_code=404, detail="Task not found or you don't have permission.")
    
    task_to_update.update(task.model_dump())
    return task_to_update

@app.delete("/tasks/{task_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_task(task_id: int, current_user: Annotated[dict, Depends(get_current_user)]):
    global task_db
    initial_count = len(task_db)
    task_db = [t for t in task_db if not (t["id"] == task_id and t["owner_email"] == current_user["email"])]
    if len(task_db) == initial_count:
        raise HTTPException(status_code=404, detail="Task not found or you don't have permission.")
    return