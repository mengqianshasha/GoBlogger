from functools import wraps

from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor, CKEditorField
from datetime import date
import fontawesome as fa

from flask_wtf import FlaskForm
from sqlalchemy import ForeignKey
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, ValidationError, Length

from forms import CreatePostForm
from flask_gravatar import Gravatar

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

# Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
app.secret_key = '4544b5f9058600e377ecbdfedba2c1d5e9e2d61e98ecfc340aee6a6f3776be96'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

# Rgister Form
class RegisterForm(FlaskForm):
    email = StringField(label='Email', validators=[DataRequired()])
    password = PasswordField(label='Password', validators=[DataRequired(), Length(min=6)])
    name = StringField(label='Name', validators=[DataRequired()])
    submit = SubmitField(label='SIGN ME UP!')

# Login Form
class LoginForm(FlaskForm):
    email = StringField(label='Email', validators=[DataRequired()])
    password = PasswordField(label='Password', validators=[DataRequired()])
    submit = SubmitField(label='LOG ME IN!')

# Comment Form
class CommentForm(FlaskForm):
    comment_text = CKEditorField(label='Comment', validators=[DataRequired()])
    submit = SubmitField(label='Submit Comment')

##CONNECT TO DB
# app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:admin@172.26.144.1:5432/postgres'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

##CONFIGURE TABLES
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    name = db.Column(db.String(40), nullable=False)

    # One-to-Many: user --- posts, comments
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="user")

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    # One to Many: User --- BlogPost
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = relationship("User", back_populates="posts")

    # One to Many: BlogPost --- Comment
    comments = relationship("Comment", back_populates="post")

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)

    # One to Many: User --- Comment
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = relationship("User", back_populates="comments")

    # One to Many: BlogPost --- Comment
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    post = relationship("BlogPost", back_populates="comments")



db.create_all()

# decorator
def admin_only(f):
    @wraps(f)
    def wrap_func(*args, **kwargs):
        if not current_user.is_authenticated or current_user.id != 1:
            return abort(403)
        else:
            return f(*args, **kwargs)
    return wrap_func

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html",
                           all_posts=posts,
                           logged_in=current_user.is_authenticated,
                           is_admin=current_user.is_authenticated and current_user.id==1
                           )


@app.route('/register', methods=['GET', 'POST'])
def register():
    # already logged in
    if current_user.is_authenticated:
        return redirect(url_for('get_all_posts'))

    form = RegisterForm()
    if form.validate_on_submit():
        # case1: user already exists
        user = get_user_by_email(form.email.data)
        if user:
            flash("You've already signed up with that email. Please log in instead.")
            return redirect(url_for('login'))

        # case2: register new user
        password = form.password.data
        password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        new_user = User(
            email=form.email.data,
            password=password,
            name=form.name.data
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('get_all_posts'))

    return render_template("register.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('get_all_posts'))

    form = LoginForm()
    if form.validate_on_submit():
        user = get_user_by_email(form.email.data)
        if not user:
            flash('The email address does not match any record.')
            return redirect(url_for('login'))
        if not check_password_hash(user.password, form.password.data):
            flash('The password does not match the record.')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('get_all_posts'))
    return render_template("login.html", form=form, logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comment_form = CommentForm()

    if comment_form.validate_on_submit():
        new_comment = Comment(
            text=comment_form.comment_text.data,
            post_id=post_id,
            user_id=current_user.id
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for("show_post", post_id=post_id))

    return render_template("post.html",
                           post=requested_post,
                           logged_in=current_user.is_authenticated,
                           is_admin=current_user.is_authenticated and current_user.id==1,
                           form=comment_form,
                           comments=get_comments_by_post_id(post_id))


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


@app.route("/new-post", methods=['GET', 'POST'])
@admin_only
def add_new_post():
    form = CreatePostForm()

    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


@admin_only
@app.route("/edit-post/<int:post_id>")
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, logged_in=current_user.is_authenticated)

@app.route("/submit-comment/<int:post_id>")
def submit_comment(post_id):
    pass

@admin_only
@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))



def get_user_by_email(user_email):
    return User.query.filter_by(email=user_email).first()

def get_user_by_id(user_id):
    return User.query.get(user_id)

def get_comments_by_post_id(post_id):
    comments = Comment.query.filter_by(post_id=post_id)[::-1]

    for i in range(len(comments)):
        comment = comments[i]
        user = get_user_by_id(comment.user_id)
        comments[i] = [user, comment]
    return comments


if __name__ == "__main__":
    app.run(port=5000)
