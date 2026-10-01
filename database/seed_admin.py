import os, sys
from database.db_connection import SessionLocal, init_db
from app.models.users import Users
from app.services.login_service import hash_password

def seed_admin():
    email = os.getenv("ADMIN_EMAIL")
    username = os.getenv("ADMIN_USERNAME", "admin")
    password = os.getenv("ADMIN_PASSWORD")
    if not email or not password:
        print("Faltan ADMIN_EMAIL y/o ADMIN_PASSWORD en el entorno. No se creó ningún usuario.")
        sys.exit(1)
    db = SessionLocal()
    try:
        if db.query(Users).filter(Users.role == "admin").first():
            print("Ya existe un admin. No se creó ninguno nuevo.")
            return
        admin = Users(username=username, email=email, password_hash=hash_password(password), role="admin")
        db.add(admin); db.commit(); db.refresh(admin)
        print(f"Admin creado: {admin.email} (id={admin.id})")
    finally:
        db.close()

if __name__ == "__main__":
    init_db()
    seed_admin()