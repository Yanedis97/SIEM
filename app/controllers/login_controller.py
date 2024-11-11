from fastapi import APIRouter, HTTPException, Depends, Query, status
from pydantic import BaseModel
from typing import List, Optional
from sqlalchemy.orm import Session
from app.services.login_service import create_user, authenticate_user, get_all_users
from database.db_connection import get_db
from sqlalchemy.exc import IntegrityError
import math

router = APIRouter()


class GetUsersRequest(BaseModel):
    page: int = Query(1, ge=1)
    size: int = Query(10, ge=10)

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
    role: str = "Viewer"  # Rol por defecto es 'Viewer'
    user_id: int

# Pydantic model para la respuesta de creación de usuario
class CreateUserResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str

# Pydantic model para la solicitud de login
class LoginRequest(BaseModel):
    email: str
    password: str

# Pydantic model para la respuesta de login (token JWT u otra forma de respuesta)
class LoginResponse(BaseModel):
    id: int
    username: str
    role: str

# API para crear un nuevo usuario
@router.post("/create_user", response_model=CreateUserResponse, status_code=status.HTTP_201_CREATED)
def create_new_user(request: CreateUserRequest, db: Session = Depends(get_db)):
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
    
    # Devolver los datos del usuario (puedes incluir un token si usas JWT)
    return {
        "detail": "Inicio de sesion exitoso",
        "data": {
            "id": user.id,
            "username": user.username,
            "role": user.role
        }
    }

# Endpoint para obtener todos los usuarios
@router.get("/all")
def get_all_users(request: GetUsersRequest, db: Session = Depends(get_db)):
    try:
        users, total_users = get_all_users(db=db, page=request.page, size=request.size)
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

        total_pages = math.ceil(total_users / request.size)
        
        return {
            "detail": "Usuarios obtenidos exitosamente",
            "data": users_data,
            "pagination": {
                "page": request.page,
                "size": request.size,
                "total_users": total_users,
                "total_pages": total_pages
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener usuarios: {str(e)}")