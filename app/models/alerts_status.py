from sqlalchemy import Column, Integer, String
from database.db_connection import Base


class AlertsStatus(Base):
    __tablename__ = 'alert_status'

    id = Column(Integer, primary_key=True, autoincrement=True)
    code = Column (String, nullable=False)
    name = Column(String, nullable=False) 