from fastapi import FastAPI, HTTPException, Depends, status
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


"""
Registra un nuevo usuario.

Args:
    user (User): Los datos del usuario a registrar.

Returns:
    dict: Un mensaje indicando el éxito del registro.

Raises:
    HTTPException: Si el usuario ya existe.
"""
@app.post("/register")
def register_user(user: User):
    if user.username in fake_db['users']:
        raise HTTPException(status_code=400, detail="El usuario ya existe")

    # Cifrar la contraseña antes de almacenarla
    hashed_password = pwd_context.hash(user.password)

    # Almacenar el usuario con la contraseña cifrada
    fake_db['users'][user.username] = hashed_password

    return {"message": "User registered successfully"}

"""
Inicia sesión un usuario y genera un token.

Args:
    user (User): Los datos del usuario para iniciar sesión.

Returns:
    dict: Un mensaje indicando el éxito del inicio de sesión y el token generado.

Raises:
    HTTPException: Si el usuario no existe o la contraseña es incorrecta.
"""
@app.post("/login")
def login_user(user: User):
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

"""
Sorts a list of numbers using the bubble sort algorithm.

Args:
    payload (Payload): The list of numbers to sort.
    token (str): The authentication token.

Returns:
    dict: The sorted list of numbers.

Raises:
    HTTPException: If the authentication token is invalid or not provided.

Example usage:
curl -X POST "http://localhost:8000/bubble-sort?token=<token>" \
-H "Content-Type: application/json" \
-d '{"numbers": [5, 3, 8, 6, 1, 9]}'

Response:
{
    "numbers": [1, 3, 5, 6, 8, 9]
}
"""
@app.post("/bubble-sort")
def sort_numbers(payload: Payload, token: str):
    username = verify_token(token)
    sorted_numbers = bubble_sort(payload.numbers)
    return {"numbers": sorted_numbers}

"""
Filters a list of numbers to only include the even numbers.

Args:
    payload (Payload): The list of numbers to filter.
    token (str): The authentication token.

Returns:
    dict: The list of even numbers.

Raises:
    HTTPException: If the authentication token is invalid or not provided.

Example usage:
curl -X POST "http://localhost:8000/filter-even?token=<token>" \
-H "Content-Type: application/json" \
-d '{"numbers": [5, 3, 8, 6, 1, 9]}'

Response:
{
    "even_numbers": [8, 6]
}
"""
@app.post("/filter-even")
def filter_even_numbers(payload: Payload, token: str):
    username = verify_token(token)
    even_numbers = [num for num in payload.numbers if num % 2 == 0]
    return {"even_numbers": even_numbers}

"""
Calculates the sum of all numbers in the input list.

Args:
    payload (Payload): The list of numbers to sum.
    token (str): The authentication token.

Returns:
    dict: The sum of all numbers.

Raises:
    HTTPException: If the authentication token is invalid or not provided.

Example usage:
curl -X POST "http://localhost:8000/sum-elements?token=<token>" \
-H "Content-Type: application/json" \
-d '{"numbers": [5, 3, 8, 6, 1, 9]}'

Response:
{
    "sum": 32
}
"""
@app.post("/sum-elements")
def sum_numbers(payload: Payload, token: str):
    username = verify_token(token)
    total_sum = sum(payload.numbers)
    return {"sum": total_sum}

"""
Finds the maximum value in the input list of numbers.

Args:
    payload (Payload): The list of numbers to search.
    token (str): The authentication token.

Returns:
    dict: The maximum value found.

Raises:
    HTTPException: If the authentication token is invalid or not provided.

Example usage:
curl -X POST "http://localhost:8000/max-value?token=<token>" \
-H "Content-Type: application/json" \
-d '{"numbers": [5, 3, 8, 6, 1, 9]}'

Response:
{
    "max": 9
}
"""
@app.post("/max-value")
def find_max_value(payload: Payload, token: str):
    username = verify_token(token)
    max_value = max(payload.numbers)
    return {"max": max_value}

"""
Performs binary search on a sorted list of numbers.

Args:
    payload (BinarySearchPayload): The sorted list of numbers and target value.
    token (str): The authentication token.

Returns:
    dict: Whether the target was found and its index.

Raises:
    HTTPException: If the authentication token is invalid or not provided.

Example usage:
curl -X POST "http://localhost:8000/binary-search?token=<token>" \
-H "Content-Type: application/json" \
-d '{"numbers": [1, 2, 3, 4, 5], "target": 3}'

Response:
{
    "found": true,
    "index": 2
}
"""
@app.post("/binary-search")
def binary_search(payload: BinarySearchPayload, token: str):
    username = verify_token(token)
    
    left = 0
    right = len(payload.numbers) - 1
    
    while left <= right:
        mid = (left + right) // 2
        if payload.numbers[mid] == payload.target:
            return {"found": True, "index": mid}
        elif payload.numbers[mid] < payload.target:
            left = mid + 1
        else:
            right = mid - 1
            
    return {"found": False, "index": -1}
