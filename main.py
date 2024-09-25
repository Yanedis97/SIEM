# main.py
from sqlalchemy.orm import Session
from database import SessionLocal
from auth import create_user, authenticate_user

def main():
    # Crear una sesión para interactuar con la base de datos
    db: Session = SessionLocal()

    # Ejemplo de registro de un nuevo usuario
    username = "testuser"
    password = "password123"
    user = create_user(db, username, password)
    print(f"Usuario creado: {user.username}")

    # Ejemplo de autenticación de usuario
    auth_user = authenticate_user(db, username, password)
    if auth_user:
        print(f"Usuario autenticado: {auth_user.username}")
    else:
        print("Fallo en la autenticación")

if __name__ == "__main__":
    main()
