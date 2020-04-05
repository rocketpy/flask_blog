from flask import Flask
from flask_admin import Admin
from flask_wtf import FlaskForm
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from wtforms import StringField, PasswordField, BooleanField
from flask_admin.contrib.sqla import ModelView
from flask_login import login_user, logout_user
from wtforms.validators import InputRequired, Length
from flask import render_template, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_user import UserMixin, login_required, current_user
from datetime import datetime


app = Flask(__name__)
admin = Admin(app)
app.config['SECRET_KEY'] = 'SECRET_KEY'
app.config['WTF_CSRF_SECRET_KEY'] = "CSRF_SECRET_KEY"
app.config['CSRF_ENABLED'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
db = SQLAlchemy(app)
db.init_app(app)


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20))
    surname = db.Column(db.String(20))
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(50))
    posts = db.relationship('BlogPost', backref='author')


class BlogPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50))
    subtitle = db.Column(db.String(50))
    post_author = db.Column(db.String(20))
    date_posted = db.Column(db.DateTime)
    content = db.Column(db.Text)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'))


class SignUp(FlaskForm):
    name = StringField('name', validators=[InputRequired(message='An name is required !'),
                                           Length(min=2, max=20)])
    surname = StringField('surname', validators=[InputRequired(message='An surname is required !'),
                                                 Length(min=2, max=20)])
    email = StringField('email', validators=[InputRequired(message='An email is required !'),
                                             Length(min=5, max=50)])
    password = PasswordField('password', validators=[InputRequired(message='A password is required !'),
                                                     Length(min=5, max=50, message='Not greater a 50')])


class LoginForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(message='An email is required !'),
                                             Length(min=5, max=50)])
    password = PasswordField('password', validators=[InputRequired(message='A password is required !'),
                                                     Length(min=5, max=50, message='Not greater a 50')])
    remember = BooleanField('remember me')


class AddPostForm(FlaskForm):
    title = StringField('title', validators=[InputRequired(message='An name is required !'),
                                           Length(min=2, max=50, message='It is a wrong length')])
    subtitle = StringField('subtitle', validators=[InputRequired(message='An email is required !'),
                                             Length(min=5, max=50, message='It is a wrong length')])
    author = StringField('subtitle', validators=[InputRequired(message='An email is required !'),
                                             Length(min=5, max=20, message='It is a wrong length')])
    content = StringField('content', validators=[InputRequired(message='Text field is required !'),
                                                 Length(min=5, max=10000, message='It is a wrong length')])


@app.route('/')
def index():
    # posts = BlogPost.query.order_by(BlogPost.date_posted.desc()).all()
    return render_template('index.html')  # posts=posts


@app.route('/about')
@login_required
def profile():
    return render_template('about.html', name=current_user.name)


@app.errorhandler(404)
def page_not_found(error):
    return render_template('404_error.html', title='404'), 404


@app.route('/post/<int:post_id>')
@login_required
def post(post_id):
    # posts = UserPost.query.all()
    post = BlogPost.query.filter_by(id=post_id).one()
    return render_template('post.html', post=post)


"""
@app.route('/add')
@login_required
def add():
    return render_template('add.html')
"""


@app.route('/signup', methods=['POST', 'GET'])
def signup_post():
    form = SignUp()
    name = request.form.get('name')  # request.form['name']
    surname = request.form.get('surname')
    email = request.form.get('email')
    password = request.form.get('password')

    user = User.query.filter_by(email=email).first()

    if user:
        # flash('Email address already exists')
        return render_template('login.html', form=form)

    if form.validate_on_submit():
        new_user = User(name=name, surname=surname, email=email, sex=sex, birthday=birthday,
                        password=generate_password_hash(password, method='sha256'))

        db.session.add(new_user)  # adding a new user to db
        db.session.commit()
        # flash('New user created , login please !')
        return redirect(url_for('login_bootstrap', form=form))

    return render_template('signup.html', form=form)


@app.route('/login', methods=['POST', 'GET'])
def login_post():
    form = LoginForm()
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(email=email).first()

    if not user or not check_password_hash(user.password, password):
        # flash('Please check your login details and try again !')
        return render_template('login_bootstrap.html', form=form)

    if form.validate_on_submit():
        login_user(user, remember=remember)
        # flash('Logged in successfully.')
        return redirect(url_for('index'))

    return render_template('login_bootstrap.html', form=form)


@app.route('/add', methods=['POST'])
@login_required
def add_post():
    title = request.form['title']
    subtitle = request.form['subtitle']
    author = request.form['author']
    content = request.form['content']

    new_post = BlogPost(title=title, subtitle=subtitle, author=author, content=content, date_posted=datetime.now())

    db.session.add(new_post)
    db.session.commit()

    return redirect(url_for('index'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return render_template('index.html')


login_manager = LoginManager()
login_manager.login_view = 'login.html'
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


admin.add_view(ModelView(User, db.session))
admin.add_view(ModelView(BlogPost, db.session))


if __name__ == '__main__':
    app.run(debug=True)
