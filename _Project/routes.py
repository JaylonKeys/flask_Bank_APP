from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for, json, jsonify
)
from flask_login import login_required, logout_user, current_user, login_user, UserMixin
from _Project.db import User, Post
from _Project.db import Base, engine, s_session
from _Project import app, login_manager
from sqlalchemy import select
from .forms import LoginForm, SignupForm
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from sqlalchemy.orm import sessionmaker, relationship
import re
import jwt
from flask import session as s
from datetime import timedelta

app.permanent_session_lifetime = timedelta(days=365)


@app.route('/register', methods=('GET', 'POST'))
def register():
    if current_user.is_authenticated:
        return redirect(url_for('ho'))

    if request.method == 'POST':

        Base.metadata.create_all(engine)
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user:
            flash('username already exists', category='error')


        elif len(username) < 4:
            flash('Email must be greater than 3 characters. ', category='error')
        elif len(password) < 3:
            flash('Password must be at least 3 characters.', category='error')
        else:

            # user = User(username=json.dumps(User.username.toJson()), password=json.dumps(User.password.toJson(generate_password_hash(password, method='sha256'))))
            user = User(username=username, password=generate_password_hash(password, method='sha256'))

            s_session.add(user)
            s_session.commit()
            flash('Great! we created your account. You can now login', category='success')
            return redirect(url_for('login'))

    return render_template('auth/register.html', user=current_user)


@app.route('/login', methods=('GET', 'POST'))
def login():
    if current_user.is_authenticated:
        return redirect(url_for('ho'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user:
            if check_password_hash(user.password, password):
                # flash('You are Logged In!!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('ho'))
            else:
                flash('The password is incorrect, try again.', category='error')
        else:
            flash('Username does not exist', category='error')
    return render_template('auth/login.html', user=current_user, )


@app.route('/home', methods=('GET', 'POST'))
@login_required
def home():
    cookie = ''
    Session = sessionmaker(bind=engine)
    Session.configure(bind=engine)
    session = Session()
    # q = Post.query.get(current_user.id)
    # the = posts.balance
    q = s_session.query(Post).filter(Post.user_id == current_user.id).first()
    a = session.query(User).get(current_user.id)
    # if q == None :
    #   return redirect(url_for('ho'))

    if q == None:
        return redirect(url_for('hom'))
    else:
        balance = q.balance

    s.get('cookie')
    if a.cookie == 'true':
        cookie = 'yo'

    return render_template('base5.html', user=current_user, bool=bool, balance=balance, cookie=cookie)


@app.route('/', methods=('GET', 'POST'))
@login_required
def ho():
    Session = sessionmaker(bind=engine)
    Session.configure(bind=engine)

    cook = s_session.query(User.cookie).filter(User.id == current_user.id).first()
    cookie = cook.cookie

    if cookie:
        q = s_session.query(Post).filter(Post.user_id == current_user.id).first()
        balance = q.balance
        return render_template('base5.html', user=current_user, bool=bool, cookie=cookie, cook=cook, balance=balance)
    else:
        return render_template('base6.html', user=current_user, bool=bool, cookie=cookie, cook=cook)


@app.route('/hom', methods=('GET', 'POST'))
def hom():
    return render_template('base6.html', user=current_user, bool=bool, )


@app.route('/money', methods=('GET', 'POST'))
@login_required
def money():
    # Post.user = current_user.id

    Session = sessionmaker(bind=engine)
    Session.configure(bind=engine)
    q = s_session.query(Post).filter(Post.user_id == current_user.id).first()
    # q = Post.query.get(Post.user_id)
    balance = q.balance

    bal = request.form.get('OP')
    name = 0
    money = 0
    new = 0

    if request.method == 'POST':
        try:
            money = float(request.form.get('add'))
            if money <= 0:
                flash('Positive numbers only please', category='error')

            if bal == 'add':

                Session = sessionmaker(bind=engine)
                Session.configure(bind=engine)
                session = Session()
                # q = s_session.query(Post).filter(Post.user == current_user).first()
                s_session.query(Post).filter(Post.user_id == current_user.id).first()
                money2 = q.balance
                q.balance = q.balance + money

                s_session.commit()

                if q.balance > money2:
                    flash('Your transaction has been completed', category='success')
                    return redirect(url_for('home'))
                else:
                    flash('Error in transaction. Try again', category='error')



            elif bal == 'ad':
                flash('Please select to add or withdraw money', category='error')



            else:
                Session = sessionmaker(bind=engine)
                Session.configure(bind=engine)
                # q = s_session.query(Post).filter(Post.user == current_user).first()
                s_session.query(Post).filter(Post.user_id == current_user.id).first()
                money3 = q.balance
                q.balance = q.balance - money
                s_session.commit()

                if q.balance < money3:
                    flash('Your transaction has been completed', category='success')
                    return redirect(url_for('home'))
                else:
                    flash('Error in transaction. Try again', category='error')






        except ValueError:
            flash('Numbers 0-9 only please. No letters or special characters', category='error')

    return render_template('money.html', user=current_user, bool=bool, bal=bal, name=name, money=money, new=new,
                           balance=balance)


@app.route('/view', methods=('GET', 'POST'))
@login_required
def view():
    cookie = ''

    post = 'post'
    s.get('cookie')
    if 'cookie' in s:
        cookie = 'Bless'

    # posts = Post.query.get(current_user.id)
    posts = s_session.query(Post).filter(Post.user_id == current_user.id).first()

    # query = posts.balance
    query = 'treu'
    if query:
        bool = True
    else:
        bool = False

    # if query:
    #   bool = True

    num = posts.balance * posts.interest
    balance = posts.balance
    U_interest = posts.interest

    numbers = [1, 2, 3, 4, 5, 6]

    numbers[0] = posts.balance
    numbers[1] = num * 5 + posts.balance
    numbers[2] = num * 10 + posts.balance
    numbers[3] = num * 15 + posts.balance
    numbers[4] = num * 20 + posts.balance
    numbers[5] = num * 25 + posts.balance

    data = json.dumps(numbers)

    Ages = [1, 2, 3, 4, 5, 6]

    Ages[0] = posts.age
    Ages[1] = posts.age + 5
    Ages[2] = posts.age + 10
    Ages[3] = posts.age + 15
    Ages[4] = posts.age + 20
    Ages[5] = posts.age + 25

    labels = json.dumps(Ages)

    return render_template('base4.html', user=current_user, bool=bool, labels=labels, data=data, U_interest=U_interest,
                           balance=balance, post=post, query=query, cookie=cookie)


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))


@app.route('/index', methods=('GET', 'POST'))
@login_required
def index():
    balance = 1.0
    interest = 1.0
    age = 1.0

    if request.method == 'POST':
        try:
            balance = float(request.form['balance'])
            interest = float(request.form['interest'])
            age = float(request.form['age'])
            error = None
            if not balance:
                error = 'Balance is required.'
            elif not interest:
                error = 'Interest is required.'
            elif not age:
                error = "Please enter your age"
            else:
                Session = sessionmaker(bind=engine)
                Session.configure(bind=engine)
                session = Session()
                # Base.metadata.create_all(engine)
                balance = float(request.form['balance'])
                interest = float(request.form['interest'])
                age = float(request.form['age'])

                a = Post(balance=balance, interest=interest, age=age, user_id=current_user.id)
                # u.post.append(a)
                # session.add(u)
                s_session.add(a)
                s_session.commit()

                app.secret_key = 'hey'
                s.permanent = True
                s['cookie'] = 0
                cookie = 'true'
                # u = User(username=current_user.username,
                #             password=session.query(User.password).filter(User.username == current_user.username),
                #             cookie=cookie)
                # s_session.add(u)
                # s_session.commit()
                # a = s_session.query(User).get(current_user.id)
                a = s_session.query(User).filter(User.username == current_user.username).first()

                a.cookie = 'true'
                s_session.commit()

                return redirect(url_for('ho'))



        except ValueError:
            flash('Numbers 0-9 only please. No letters or special characters', category='error')

    return render_template('bank/index2.html', user=current_user)


@login_manager.unauthorized_handler
def unauthorized():
    """Redirect unauthorized users to Login page."""
    flash('You must be logged in to view that page.')
    return redirect(url_for('login'))


@app.route('/account', methods=('GET', 'POST'))
@login_required
def account():
    hope = s_session.query(Post.balance).filter(Post.user_id == current_user.id).first()

    jet = hope.balance

    return render_template('bank/rough.html', hope=hope, jet=jet)


@app.route('/chart', methods=('GET', 'POST'))
@login_required
def chart():
    SB = float(request.form['balance'])
    Int = float(request.form['interest'])
    Age = float(request.form['age'])
    # posts = Post.query.all()
    # u = User()
    Session = sessionmaker(bind=engine)
    Session.configure(bind=engine)
    session = Session()
    a = Post(balance=SB, interest=Int, age=Age, user_id=current_user.id)
    session.add(a)
    session.commit()
    # posts = Post.query.all()
    posts = Post.query.get(current_user.id)

    num = posts.balance * posts.interest

    numbers = [1, 2, 3, 4, 5, 6]

    numbers[0] = posts.balance
    numbers[1] = num * 5 + posts.balance
    numbers[2] = num * 10 + posts.balance
    numbers[3] = num * 15 + posts.balance
    numbers[4] = num * 20 + posts.balance
    numbers[5] = num * 25 + posts.balance

    data = json.dumps(numbers)

    Ages = [1, 2, 3, 4, 5, 6]

    Ages[0] = posts.age
    Ages[1] = posts.age + 5
    Ages[2] = posts.age + 10
    Ages[3] = posts.age + 15
    Ages[4] = posts.age + 20
    Ages[5] = posts.age + 25

    labels = json.dumps(Ages)

    return render_template('bank/chart.html', data=data, labels=labels, user=current_user, posts=posts,
                           sally=posts.balance)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    s.pop('cookie', None)
    return redirect(url_for('login'))
