from sqlalchemy import Column, Integer, String, TIMESTAMP, ForeignKey
#from sqlalchemy.orm import relationship
from datetime import datetime
from database.db_connection import Base


class Alerts(Base):
    __tablename__ = 'alerts'

    id = Column(Integer, primary_key=True, autoincrement=True)
    log_id = Column(Integer, ForeignKey('logs.id'), nullable=False)
    alert_type = Column(String(100), nullable=False)
    severity = Column(String(50), nullable=True)
    created_at = Column(TIMESTAMP, nullable=False, default=datetime.utcnow)

    #log = relationship("Log", back_populates="alerts")