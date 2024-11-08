# auth.py
from sqlalchemy.orm import Session
from models.users import Users
import bcrypt

def create_user(db: Session, username: str, email: str, password: str, role: str):
    # Hashear la contraseña
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    # Crear un nuevo usuario
    new_user = Users(username=username, email=email, password_hash=hashed_password.decode('utf-8'), role=role)
    
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