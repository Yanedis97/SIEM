from sqlalchemy import Column, Integer, String, TIMESTAMP
#from sqlalchemy.orm import relationship
from datetime import datetime
from database.db_connection import Base


class Alerts(Base):
    __tablename__ = 'alerts'

    id = Column(Integer, primary_key=True, autoincrement=True)
    second_id = Column (String, nullable=False)
    log_ids = Column(String, nullable=False, default='[]') 
    alert_type = Column(Integer, nullable=False)
    message = Column(String(500), nullable=True)
    source_ip = Column(String(50), nullable=True)
    dest_ip = Column(String(50), nullable=True)
    severity = Column(Integer, nullable=True)
    context = Column(String(), nullable=True)
    alert_category = Column(Integer, nullable=True)
    status = Column(Integer, nullable=True)
    created_at = Column(TIMESTAMP, nullable=False, default=datetime.utcnow)