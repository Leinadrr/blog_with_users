from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
import secrets
from functools import wraps
import nh3
import os


app = Flask(__name__)
random_key = secrets.token_bytes()
app.config['SECRET_KEY'] = random_key
ckeditor = CKEditor(app)
Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite:///blog.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy()
db.init_app(app)


# CONFIGURE TABLES

class User(db.Model, UserMixin):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, unique=True)
    password = db.Column(db.String)
    name = db.Column(db.String(200))
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    author = relationship("User", back_populates="posts")
    comments = relationship("Comment", back_populates="own_posts")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    author = relationship("User", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    own_posts = relationship("BlogPost", back_populates="comments")

# with app.app_context():
#     db.create_all()


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated and current_user.id == 1:
            return f(*args, **kwargs)
        return abort(403)

    return decorated_function


@login_manager.user_loader
def load_user(user_id):
    # Lógica para cargar el usuario desde la base de datos o almacenamiento
    user = User.query.get(int(user_id))
    return user


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    if current_user.is_authenticated:
        print(f"El usuario está activo: {current_user.is_authenticated} - {current_user.name}")
    else:
        pass
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    user_data = form.data
    del(user_data["csrf_token"], user_data["submit"])
    if form.validate_on_submit():
        if form.data["email"] in db.session.scalars(db.select(User.email)).all():
            flash("The email you typed is already in the system. Please, consider login then")
            return redirect(url_for("login"))

        hash_and_salted_password = generate_password_hash(user_data["password"], method="scrypt", salt_length=16)
        user_data["password"] = hash_and_salted_password
        instance = User(**user_data)
        db.session.add(instance)
        db.session.commit()
        login_user(instance)
        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    email = form.data["email"]
    password = form.data["password"]
    if form.validate_on_submit():
        user = db.session.execute(db.select(User).filter_by(email=email)).scalar()
        if user:
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for("get_all_posts"))
            else:
                flash("Sorry, you enter and wrong password. Try again")
        else:
            flash("Sorry, you enter and wrong email. Try again")
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    form = CommentForm()
    requested_comment = db.session.execute(db.select(Comment).filter_by(own_posts=requested_post)).scalars().all()
    if form.validate_on_submit():
        if current_user.is_authenticated:
            instance = Comment(
                body=nh3.clean(form.body.data),
                author=current_user,
                own_posts=requested_post,
                )
            db.session.add(instance)
            db.session.commit()
            return redirect(url_for("show_post", post_id=requested_post.id))
        else:
            flash("Sorry, login if you want to leave a comment")
            return redirect(url_for("login"))
    return render_template("post.html", post=requested_post, form=form, comment=requested_comment)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
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
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
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
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/delete_comment/<int:comment_id>")
@admin_only
def del_comments(comment_id):
    comment_to_delete = db.session.execute(db.select(Comment).filter_by(id=comment_id)).scalar_one()
    post_id = comment_to_delete.own_posts.id
    db.session.delete(comment_to_delete)
    db.session.commit()
    return redirect(url_for("show_post", post_id=post_id))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
