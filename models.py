from sqlalchemy import Column, Integer, String
from db import Base

class student(Base);
    __tablename__ = "students"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), index=True)
    age = Column(Integer)
    
