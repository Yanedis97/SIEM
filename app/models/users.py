from sqlalchemy import Column, Integer, String, TIMESTAMP
from database.db_connection import Base
from datetime import datetime


class Users(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(100), nullable=False)
    email = Column(String(100), nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(50), nullable=False, default='user')
    created_at = Column(TIMESTAMP, nullable=False, default=datetime.utcnow)