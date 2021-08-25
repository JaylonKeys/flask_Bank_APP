from sqlalchemy import create_engine
from sqlalchemy import Column,Integer,String
import sqlalchemy
from flask import Flask, json
from sqlalchemy.orm import declarative_base, sessionmaker, scoped_session, relationship
from sqlalchemy.ext.declarative import declarative_base
from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash
from _Project import app, login_manager
from sqlalchemy import create_engine, ForeignKey




app = Flask(__name__)



engine = create_engine ('sqlite:///fuck.db', connect_args={'check_same_thread': False})

s_session = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=False,
                                         bind=engine))



Base = declarative_base()
Base.query = s_session.query_property()



class Post(Base):
    __tablename__ = 'post'
    id = Column(Integer, primary_key=True)
    balance = Column(Integer)
    interest = Column(Integer)
    age = Column(Integer)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship("User", back_populates="post")


    def __repr__(self):
        return "<Post(balance='%s', interest='%s', age='%s')>" % (
            self.balance, self.interest, self.age
        )





class User(Base, UserMixin):
     __tablename__ = 'user'
     id = Column(Integer, primary_key=True)
     username = Column(String)
     password = Column(String)
     cookie = Column(String)
     post = relationship('Post', back_populates='user', lazy=True)

     def __repr__(self):


        return "<User(username='%s', password='%s')>" % (
                             self.username, self.password,)

     def set_password(self, password):
         """Create hashed password."""
         self.password = generate_password_hash(
             password,
             method='sha256'
         )



     def check_password(self, password):
         return check_password_hash(self.password_hash, password)



     def toJson(self):
         return json.dumps(self, default=lambda o: o.__dict__)



