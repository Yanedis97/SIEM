from sqlalchemy import Column, Integer, String, Text, DATETIME, TIMESTAMP, ForeignKey
from sqlalchemy.orm import relationship
from database.db_connection import Base
from datetime import datetime

class Logs(Base):
    __tablename__ = 'logs'

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(Integer, ForeignKey('devices.id'), nullable=False)
    log_date = Column(DATETIME, nullable=False)
    log_level = Column(String(50), nullable=True)
    message = Column(Text, nullable=False)
    json_data = Column(Text, nullable=True)  # longtext in MySQL maps to LongText in SQLAlchemy
    created_at = Column(TIMESTAMP, nullable=False, default=datetime.utcnow)

    device = relationship("Devices", back_populates="logs")
    alerts = relationship("Alerts", back_populates="log")