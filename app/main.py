from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from app import schemas, auth, models

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@app.post("/register", response_model=schemas.Token)
def register(user: schemas.UserCreate):
    if user.username in models.fake_users_db:
        raise HTTPException(status_code=400, detail="Usuario ya existe")
    
    hashed_pw = auth.hash_password(user.password)
    models.fake_users_db[user.username] = {
        "username": user.username,
        "email": user.email,
        "hashed_password": hashed_pw
    }

    token = auth.create_access_token(data={"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}

@app.post("/token", response_model=schemas.Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = models.fake_users_db.get(form_data.username)
    if not user or not auth.verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")

    token = auth.create_access_token(data={"sub": user['username']})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/protected")
def protected_route(token: str = Depends(oauth2_scheme)):
    try:
        payload = auth.jwt.decode(token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
        username = payload.get("sub")
        if username is None or username not in models.fake_users_db:
            raise HTTPException(status_code=401, detail="Token inválido")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")

    return {"message": f"Bienvenido {username}, esta es una ruta protegida"}



