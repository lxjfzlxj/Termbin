from sqlalchemy import Column, String, Integer, Text, Enum, create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
import enum

Base = declarative_base()

class AuthorStatus(enum.Enum):
    author_only = 0
    someone_only = 1
    all = 2

class Clipboard(Base):
    __tablename__ = 'clipboards'
    date = Column(String(45), nullable = False)
    digest = Column(String(45), nullable = False)
    short = Column(String(45), nullable = False)
    size = Column(Integer, nullable = False)
    url = Column(String(45), nullable = False)
    uuid = Column(String(45), primary_key = True, nullable = False)
    content = Column(Text)
    author = Column(String(45))
    status = Column(Enum(AuthorStatus), nullable = False)
    someone = Column(String(45))
    
engine = create_engine('mysql+pymysql://rigel:root@localhost:3306/termbin')
DBsession = sessionmaker(bind = engine)

def get_session():
    return DBsession()