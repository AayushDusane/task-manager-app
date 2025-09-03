from pydantic import BaseModel, Field

# Schema for a new user registration
class UserCreate(BaseModel):
    email: str
    password: str

# Schema for a user login
class UserLogin(BaseModel):
    email: str
    password: str

# Schema for the JWT token response
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class TaskBase(BaseModel):
    title: str
    description: str | None = None
    completed: bool = False

class TaskCreate(TaskBase):
    pass

class Task(TaskBase):
    id: int
    owner_email: str

    class Config:
        from_attributes = True