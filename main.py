from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from passlib.context import CryptContext
from datetime import datetime, timedelta

app = FastAPI()

SECRET_KEY = "BigPapi69"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl="token",
    scopes={
        "admin": "Admin access",
        "student": "Student access"
    }
)

# Fake database
fake_users = {
    "admin": {
        "username": "admin",
        "hashed_password": pwd_context.hash("adminpass"),
        "scopes": ["admin"],
    },
    
    "nic": {
        "username": "nic",
        "hashed_password": pwd_context.hash("password123"),
        "scopes": ["student"],
    }
}


def verify_password(plain_pw, hashed_pw):
    return pwd_context.verify(plain_pw, hashed_pw)

def authenticate_user(username: str, password: str):
    user = fake_users.get(username)
    if not user:
        return None
    if not verify_password(password, user["hashed_password"]):
        return None
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=400,
            detail="Incorrect username or password"
            )
    
    token_data = {
        "user": user["username"],
        "type": "access",
        "scopes": user["scopes"],
    }

    access_token = create_access_token(
        token_data,
        timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    return {"access_token": access_token, "token_type": "bearer"}

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        username = payload.get("user")
        scope = payload.get("scopes")

        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        user = fake_users.get(username)

        if user is None:
          raise HTTPException(status_code=401, detail="Invalid token")
        
        return payload
    
    except JWTError:
        raise HTTPException(status_code=403, detail="Invalid token")


@app.get("/protected")
async def protected_route(current_user = Depends(get_current_user)):
        return {
            "message": "Success",
            "user": current_user.get("user"),
            "type": current_user.get("type"),
            "scopes": current_user.get("scopes")
        }

@app.get("/admin")
async def admin_route(current_user = Depends(get_current_user)):
    if "admin" not in current_user["scopes"]:
        raise HTTPException(status_code=403, detail="Admin only access")
    return {
    "message": "Welcome admin",
    "user": current_user["user"]
}