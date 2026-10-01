from sqlalchemy.orm import Session
from app.models.users import Users
import bcrypt

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def create_user(db: Session, username: str, email: str, password: str, role: str, user_id: int):
    # Crear un nuevo usuario
    new_user = Users(username=username, email=email, password_hash=hash_password(password), role=role)
        
    # Agregar el nuevo usuario a la base de datos
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
        
    return new_user


def authenticate_user(db: Session, email: str, password: str):
    # Buscar el usuario en la base de datos
    user = db.query(Users).filter(Users.email == email).first()
    
    if user is None:
        return False
    
    # Verificar la contraseña
    if bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
        return user
    else:
        return False
    
# Obtener todos los usuarios
def get_all_users_service(db: Session, page: int = 1, size: int = 10):
    try:
        start_from = (page - 1) * size
        users = db.query(Users).order_by(Users.id.desc()).offset(start_from).limit(size).all()
        total_users = db.query(Users).count()

        return users, total_users
    except Exception as e:
        raise e