from fastapi import FastAPI, HTTPException, Depends, status
from typing import List
from pydantic import BaseModel
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer
import jwt
from datetime import datetime, timedelta, timezone

SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"

fake_db = {"users": {}}

app = FastAPI()

# Configuración para el cifrado de contraseñas
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class Payload(BaseModel):
    numbers: List[int]

class BinarySearchPayload(BaseModel):
    numbers: List[int]
    target: int

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

def verify_token(token: str):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
    return username

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

def bubble_sort(numbers: List[int]) -> List[int]:
    n = len(numbers)
    for i in range(n):
        for j in range(0, n-i-1):
            if numbers[j] > numbers[j+1]:
                numbers[j], numbers[j+1] = numbers[j+1], numbers[j]
    return numbers

@app.post("/bubble-sort")
def sort_numbers(payload: Payload, token: str = Depends(oauth2_scheme)):
    """
    Ordena una lista de números usando el algoritmo de ordenamiento de burbuja.

    Args:
        payload (Payload): La lista de números a ordenar.
        token (str): El token de autenticación.

    Returns:
        dict: La lista ordenada de números.

    Raises:
        HTTPException: Si el token de autenticación es inválido o no fue proporcionado.

    Ejemplo de uso:
    curl -X POST "http://localhost:8000/bubble-sort" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer <token>" \
    -d '{"numbers": [5, 3, 8, 6, 1, 9]}'

    Respuesta:
    {
        "numbers": [1, 3, 5, 6, 8, 9]
    }
    """
    username = verify_token(token)
    sorted_numbers = bubble_sort(payload.numbers)
    return {"numbers": sorted_numbers}

