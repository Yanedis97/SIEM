from sqlalchemy import Column, Integer, String, Text, TIMESTAMP, func
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class AlertsCategory(Base):
    __tablename__ = 'alerts_categories'

    id = Column(Integer, primary_key=True, autoincrement=True)
    code = Column(String, nullable=False, unique=True)
    name = Column(String, nullable=False)
    severity = Column(Integer, nullable=True)
    description = Column(Text, nullable=True)
    status = Column(Integer, default=1)  # 1 for active, 0 for inactive
    created_at = Column(TIMESTAMP, default=func.current_timestamp())
