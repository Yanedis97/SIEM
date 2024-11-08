from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.services.login_service import create_user, authenticate_user
from database.db_connection import get_db  # Asegúrate de tener una función para obtener la sesión de la BD
from sqlalchemy.exc import IntegrityError

router = APIRouter()

# Pydantic model para la solicitud de creación de usuario
class CreateUserRequest(BaseModel):
    username: str
    email: str
    password: str
    role: str = "Viewer"  # Rol por defecto es 'Viewer'

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
@router.post("/create_user", response_model=CreateUserResponse)
def create_new_user(request: CreateUserRequest, db: Session = Depends(get_db)):
    try:
        # Crear el nuevo usuario
        new_user = create_user(
            db=db, 
            username=request.username, 
            email=request.email, 
            password=request.password, 
            role=request.role
        )
        
        # Devolver la respuesta con los datos del nuevo usuario
        return {
            "id": new_user.id,
            "username": new_user.username,
            "email": new_user.email,
            "role": new_user.role
        }
    
    except IntegrityError:
        raise HTTPException(status_code=400, detail="Username or email already exists.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error creating user: {str(e)}")


# API para autenticación de usuario (login)
@router.post("/login", response_model=LoginResponse)
def login(request: LoginRequest, db: Session = Depends(get_db)):
    user = authenticate_user(db=db, email=request.email, password=request.password)
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Devolver los datos del usuario (puedes incluir un token si usas JWT)
    return {
        "id": user.id,
        "username": user.username,
        "role": user.role
    }
