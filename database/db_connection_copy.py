from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

Base = declarative_base()

# Configuración de la base de datos
DATABASE_URL = "mysql+pymysql://root@localhost/my_siem"  # Ajusta con tus credenciales y nombre de la base de datos

engine = create_engine(DATABASE_URL, echo=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Crea todas las tablas en la base de datos
Base.metadata.create_all(bind=engine)