from datetime import datetime, timedelta, timezone
from typing import Annotated, Union

import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext
from pydantic import BaseModel
from models import User

# Константы для JWT (JSON Web Token)
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"  # Секретный ключ для подписи токенов
ALGORITHM = "HS256"  # Алгоритм шифрования для JWT
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # Время жизни токена в минутах

# Модель для возврата токена
class Token(BaseModel):
    access_token: str  # Токен доступа
    token_type: str  # Тип токена (обычно "bearer")

# Модель для данных, хранящихся в токене
class TokenData(BaseModel):
    username: str | None = None  # Имя пользователя, хранящееся в токене

# Модель для данных пользователя
class UserD(BaseModel):
    username: str  # Имя пользователя (обязательное поле)
    email: str | None = None  # Электронная почта пользователя (необязательное поле)
    full_name: str | None = None  # Полное имя пользователя (необязательное поле)
    password: str |None = None# Пароль пользователя 
    disabled: bool | None = None  # Флаг, указывающий, отключен ли пользователь (необязательное поле)
# Модель для пользователя в базе данных (наследуется от UserD)
class UserInDB(UserD):
    hashed_password: str  # Хешированный пароль пользователя

# Контекст для хеширования паролей
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Схема OAuth2 для аутентификации через токен
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Создание экземпляра FastAPI
app = FastAPI()

# Функция для проверки пароля
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)  # Сравнение введенного пароля с хешированным

# Функция для хеширования пароля
def get_password_hash(password):
    return pwd_context.hash(password)  # Возвращает хешированный пароль

# Функция для получения пользователя из базы данных по имени
def get_user(username: str):
    user = User.get_or_none(username=username)  # Поиск пользователя в базе данных
    if user:
        return UserInDB(
            username=user.username,
            email=user.email,
            full_name=user.full_name,
            disabled=user.disabled,
            hashed_password=user.hashed_password,
        )  # Возвращает данные пользователя, если он найден

# Функция для аутентификации пользователя
def authenticate_user(username: str, password: str) -> Union[UserInDB, bool]:
    user = get_user(username)  # Получаем пользователя по имени
    if not user:
        return False  # Если пользователь не найден, возвращаем False
    if not verify_password(password, user.hashed_password):
        return False  # Если пароль неверный, возвращаем False
    return user  # Возвращаем пользователя, если аутентификация успешна

# Функция для создания токена доступа
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()  # Копируем данные для кодирования
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta  # Устанавливаем срок действия токена
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)  # По умолчанию токен действует 15 минут
    to_encode.update({"exp": expire})  # Добавляем срок действия в данные
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)  # Кодируем данные в JWT
    return encoded_jwt  # Возвращаем закодированный токен

# Функция для получения текущего пользователя по токену
async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )  # Исключение, если токен недействителен
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])  # Декодируем токен
        username: str = payload.get("sub")  # Получаем имя пользователя из токена
        if username is None:
            raise credentials_exception  # Если имя пользователя отсутствует, выбрасываем исключение
        token_data = TokenData(username=username)  # Создаем объект TokenData
    except jwt.ExpiredSignatureError:
        raise credentials_exception  # Если срок действия токена истек, выбрасываем исключение
    except jwt.InvalidTokenError:
        raise credentials_exception  # Если токен недействителен, выбрасываем исключение

    user = get_user(username=token_data.username)  # Получаем пользователя по имени из токена
    if user is None:
        raise credentials_exception  # Если пользователь не найден, выбрасываем исключение
    return user  # Возвращаем пользователя

# Функция для получения текущего активного пользователя
async def get_current_active_user(
    current_user: Annotated[UserD, Depends(get_current_user)],
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")  # Если пользователь отключен, выбрасываем исключение
    return current_user  # Возвращаем текущего активного пользователя

# Эндпоинт для получения токена доступа
@app.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    user = authenticate_user(form_data.username, form_data.password)  # Аутентифицируем пользователя
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )  # Если аутентификация не удалась, выбрасываем исключение
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)  # Устанавливаем срок действия токена
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )  # Создаем токен доступа
    return {"access_token": access_token, "token_type": "bearer"}  # Возвращаем токен

# Эндпоинт для получения данных текущего пользователя
@app.get("/users/me/", response_model=UserD)
async def read_users_me(
    current_user: Annotated[UserD, Depends(get_current_active_user)],
):
    return current_user  # Возвращаем данные текущего пользователя

# Эндпоинт для регистрации нового пользователя
@app.post("/register/")
async def register(user: UserD):
    # Проверяем, существует ли пользователь с таким именем
    existing_user = User.get_or_none(username=user.username)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered",
        )  # Если пользователь уже существует, выбрасываем исключение

    # Хешируем пароль перед сохранением
    hashed_password = get_password_hash(user.password)

    # Создаем нового пользователя
    new_user = User.create(
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        hashed_password=hashed_password,
        disabled=False  # По умолчанию пользователь активен
    )
    return {"message": "User registered successfully", "username": new_user.username}  # Возвращаем сообщение об успешной регистрации