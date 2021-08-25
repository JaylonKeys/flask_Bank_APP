from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
import json



app = Flask(__name__)

app.config['SECRET_KEY'] = 'jaksjdkjf'

#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///aaa.db'



login_manager = LoginManager()
login_manager.login_view = 'login'

login_manager.init_app(app)

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))



from _Project.db import User, Post
from _Project import db






from _Project import routes








