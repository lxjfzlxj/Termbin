from sqlalchemy import Column, String, Integer, Text, Enum, create_engine, BigInteger
from sqlalchemy.orm import sessionmaker, declarative_base
import enum

Base = declarative_base()

class Visibility(enum.Enum):
    author_only = 0
    someone_only = 1
    all = 2

class SelfDestruction(enum.Enum):
    undestroyed = 0
    destroyed = 1

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
    visibility = Column(Enum(Visibility), nullable = False, default = Visibility.all)
    someone = Column(String(45))
    self_destruction = Column(Enum(SelfDestruction))
    expiration_time = Column(BigInteger)
    alias = Column(String(45))
    
class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, nullable = False, autoincrement = True, primary_key = True)
    username = Column(String(45), nullable = False, unique = True)
    password = Column(String(45), nullable = False)
    
engine = create_engine('mysql+pymysql://rigel:root@localhost:3306/termbin')
DBsession = sessionmaker(bind = engine)

def get_session():
    return DBsession()