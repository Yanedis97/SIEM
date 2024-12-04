from sqlalchemy import Column, Integer, String, Text
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class Recommendation(Base):
    __tablename__ = 'recommendations'

    id = Column(Integer, primary_key=True, autoincrement=True)
    category_id = Column(Integer, nullable=False)
    recommendation = Column(Text, nullable=False)
    created_at = Column(String(50))
