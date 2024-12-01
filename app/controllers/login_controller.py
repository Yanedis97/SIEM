from datetime import datetime, timedelta
from fastapi import APIRouter, HTTPException, Depends, Query, status
from pydantic import BaseModel
from typing import List
from sqlalchemy.orm import Session
from app.services.login_service import create_user, authenticate_user, get_all_users_service
from database.db_connection import get_db
from sqlalchemy.exc import IntegrityError
import math
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from fastapi import Depends, HTTPException

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Configuración para JWT
SECRET_KEY = "admin123"  # Cambia esto por una clave segura
ALGORITHM = "HS256"  # Algoritmo usado para firmar el token
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # Expiración en minutos

class GetUsersResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str
    created_at: str

class PaginatedUsersResponse(BaseModel):
    detail: str
    data: List[GetUsersResponse]
    pagination: dict

# Pydantic model para la solicitud de creación de usuario
class CreateUserRequest(BaseModel):
    username: str
    email: str
    password: str
    role: str = "viewer" 
    user_id: int

# Pydantic model para la respuesta de creación de usuario
class CreateUserResponse(BaseModel):
    detail: str
    data: dict

# Pydantic model para la solicitud de login
class LoginRequest(BaseModel):
    email: str
    password: str

# Pydantic model para la respuesta de login (token JWT u otra forma de respuesta)
class LoginResponse(BaseModel):
    detail: str
    data: dict


def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = verify_token(token)
    if payload is None:
        raise HTTPException(
            status_code=401,
            detail="Token inválido o expirado.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return payload

def verify_token(token: str):
    """
    Verifica y decodifica un token JWT.
    Args:
        token (str): Token JWT.
    Returns:
        dict: Datos decodificados del token.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="El token ha expirado.")
    except jwt.JWTClaimsError:
        raise HTTPException(status_code=401, detail="Reclamos inválidos en el token.")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido.")
    
def create_access_token(data: dict):
    """
    Genera un token de acceso con datos específicos.
    Args:
        data (dict): Datos a incluir en el token.
    Returns:
        str: Token JWT.
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# API para crear un nuevo usuario
@router.post("/create_user", response_model=CreateUserResponse, status_code=status.HTTP_201_CREATED)
def create_new_user(request: CreateUserRequest, db: Session = Depends(get_db), current_user: dict = Depends(get_current_user)):
    try:
        # Crear el nuevo usuario
        new_user = create_user(
            db=db, 
            username=request.username, 
            email=request.email, 
            password=request.password, 
            role=request.role,
            user_id=request.user_id
        )

        if not new_user:
            raise HTTPException(status_code=400, detail="No tiene permisos para realizar esta acción.")
        else:
            # Devolver la respuesta con los datos del nuevo usuario
            return {
                "detail": "Usuario creado exitosamente",
                "data": {
                    "id": new_user.id,
                    "username": new_user.username,
                    "email": new_user.email,
                    "role": new_user.role
                }
            }
            
    except IntegrityError:
        raise HTTPException(status_code=400, detail="El nombre de usuario o el correo electrónico ya existen.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al crear el usuario: {str(e)}")


# API para autenticación de usuario (login)
@router.post("/login", response_model=LoginResponse)
def login(request: LoginRequest, db: Session = Depends(get_db)):
    user = authenticate_user(db=db, email=request.email, password=request.password)
    
    if not user:
        raise HTTPException(status_code=401, detail="Credenciales inválidas.")
    
    access_token = create_access_token(data={"sub": user.email})
    
    # Devolver los datos del usuario (puedes incluir un token si usas JWT)
    return {
        "detail": "Inicio de sesion exitoso",
        "data": {
            "access_token": access_token,
            "token_type": "bearer",
            "user": {
                "id": user.id,
                "username": user.username,
                "role": user.role
            }
        }
    }

# Endpoint para obtener todos los usuarios
@router.get("/all")
def get_all_users(
    page: int = Query(1, ge=1),
    size: int = Query(10, ge=10), 
    db: Session = Depends(get_db),
    current_user: dict = Depends(get_current_user)
    ):
    try:
        users, total_users = get_all_users_service(db=db, page=page, size=size)
        if len(users) == 0:
            raise HTTPException(status_code=404, detail="No se encontraron datos.")
        
        users_data = [
            GetUsersResponse(
                id=user.id,
                username=user.username,
                email=user.email,
                role=user.role,
                created_at=user.created_at.isoformat()
            ) for user in users
        ]

        total_pages = math.ceil(total_users / size)
        
        return {
            "detail": "Usuarios obtenidos exitosamente",
            "data": users_data,
            "pagination": {
                "page": page,
                "size": size,
                "total_users": total_users,
                "total_pages": total_pages
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener usuarios: {str(e)}")