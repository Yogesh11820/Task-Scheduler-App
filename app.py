from flask import Flask, render_template, request, redirect, url_for, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user,current_user
from sqlobject import *
import os
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Email, EqualTo
from flask_wtf import FlaskForm


app = Flask(__name__)
app.config['SECRET_KEY'] = 'qwerasdfzxcv'  
csrf = CSRFProtect(app)


class User(SQLObject):
    email = StringCol(alternateID=True, unique=True)
    password = StringCol()

db_filename = os.path.abspath('credentials.sqlite')
connection_string = 'sqlite:' + db_filename
connection = connectionForURI(connection_string)
sqlhub.processConnection = connection

User.createTable(ifNotExists=True)


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['username']
        password = request.form['password']
        error = 'Invalid email or password'

        try:
            user = User.byEmail(email)
        except SQLObjectNotFound:
            return render_template('login.html', error=error,form=request.form)
        
        if user.password == password:
            return render_template('dashboard.html')
        
        return render_template('login.html', error=error,form=request.form)

    return render_template('login.html',form=request.form)

class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        email = form.username.data
        password = form.password.data
        confirm_password = form.confirm_password.data

        if User.selectBy(email=email).count() > 0:
            error = 'User already registered. Please choose a different email.'
            return render_template('signup.html', form=form, error=error)

        if password != confirm_password:
            error = 'The provided password and confirm password do not match. Please ensure both fields have the same value.'
            return render_template('signup.html', form=form, error=error)

        User(email=email, password=password)
        return redirect(url_for('login'))

    return render_template('signup.html', form=form)




@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))


@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    return render_template('dashboard.html')

if __name__ == '__main__':
    app.run(debug=True)

