from sqlalchemy import Column, Integer, String, TIMESTAMP
from sqlalchemy.orm import relationship
from database.db_connection import Base
from datetime import datetime

class Devices(Base):
    __tablename__ = 'devices'

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_name = Column(String(100), nullable=False)
    ip_address = Column(String(45), nullable=True)
    device_type = Column(String(50), nullable=True)
    created_at = Column(TIMESTAMP, nullable=False, default=datetime.utcnow)

    logs = relationship("Log", back_populates="device")