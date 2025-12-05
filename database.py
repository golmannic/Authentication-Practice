from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = "mysql+pymysql://fastapi:password@localhost/fastapi_db"

engine = create_engine(
    DATABSE_URL,
    pool_pre_ping=True 
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bing=engine)

Base = declarative_base()