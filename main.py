from fastapi import FastAPI, HTTPException
from typing import List
from pydantic import BaseModel
from passlib.context import CryptContext
import jwt
from datetime import datetime, timedelta, timezone

SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"

fake_db = {"users": {}}

app = FastAPI()

# Configuración para el cifrado de contraseñas
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class Payload(BaseModel):
    numbers: List[int]

class BinarySearchPayload(BaseModel):
    numbers: List[int]
    target: int

# En main.py necesito crear un endpoint para la creación de un usuario.
#Modifica la línea 49 para que el usuario se almacene en fake_db, dentro del objeto 'users', con su contraseña cifrada.
#no modifiques el resto del código, sólo lo necesario
#formatea lo seleccionado para copiar como curl en postman

class User(BaseModel):
    username: str
    password: str

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.post("/register")
def register_user(user: User):
    """
    Registra un nuevo usuario.

    Args:
        user (User): Los datos del usuario a registrar.

    Returns:
        dict: Un mensaje indicando el éxito del registro.

    Raises:
        HTTPException: Si el usuario ya existe.
    """
    if user.username in fake_db['users']:
        raise HTTPException(status_code=400, detail="El usuario ya existe")

    # Cifrar la contraseña antes de almacenarla
    hashed_password = pwd_context.hash(user.password)

    # Almacenar el usuario con la contraseña cifrada
    fake_db['users'][user.username] = hashed_password

    return {"message": "User registered successfully"}

@app.post("/login")
def login_user(user: User):
    """
    Inicia sesión un usuario y genera un token.

    Args:
        user (User): Los datos del usuario para iniciar sesión.

    Returns:
        dict: Un mensaje indicando el éxito del inicio de sesión y el token generado.

    Raises:
        HTTPException: Si el usuario no existe o la contraseña es incorrecta.
    """
    if user.username not in fake_db['users']:
        raise HTTPException(status_code=400, detail="El usuario no existe")

    # Verificar la contraseña
    hashed_password = fake_db['users'][user.username]
    if not pwd_context.verify(user.password, hashed_password):
        raise HTTPException(status_code=400, detail="Contraseña incorrecta")

    # Generar el token
    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )

    return {"message": "Login successful", "access_token": access_token, "token_type": "bearer"}