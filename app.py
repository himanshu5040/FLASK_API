import os

from flask import Flask, flash, redirect, render_template, session, url_for
from flask_sqlalchemy import SQLAlchemy
from register import LoginForm, RegisterForm, UserUpdateForm
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "secret_key")

db_url = os.environ.get("DATABASE_URL")

if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

if not db_url:
    raise RuntimeError("DATABASE_URL is not set.")

app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


def get_admin_email():
    return os.environ.get("ADMIN_EMAIL", "").strip().lower()


def is_admin_user():
    session_email = session.get("email", "").strip().lower()
    admin_email = get_admin_email()
    return bool(admin_email and session_email == admin_email)


def require_login(message):
    if not session.get("username"):
        flash(message, "error")
        return redirect(url_for("login"))
    return None


def require_admin():
    login_redirect = require_login("Please sign in to continue.")
    if login_redirect:
        return login_redirect

    if not get_admin_email():
        flash("ADMIN_EMAIL is not configured on the server.", "error")
        return redirect(url_for("dashboard"))

    if not is_admin_user():
        flash("Only the admin can access that page.", "error")
        return redirect(url_for("dashboard"))

    return None


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)


with app.app_context():
    db.create_all()


@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(user.password_hash, password):
            flash("Incorrect email or password. Please try again.", "error")
        else:
            session["username"] = user.username
            session["email"] = email
            flash(f"Welcome back, {user.username}!", "success")
            return redirect(url_for("dashboard"))

    return render_template("login.html", form=form)


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data

        existing_user = User.query.filter_by(email=email).first()

        if existing_user:
            flash("An account with this email already exists.", "error")
            return render_template("register.html", form=form)

        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
        )
        db.session.add(user)
        db.session.commit()

        flash(f"Registration successful for {username}", "success")
        return redirect(url_for("login"))

    return render_template("register.html", form=form)


@app.route("/dashboard")
def dashboard():
    login_redirect = require_login("Please sign in to open the dashboard.")
    if login_redirect:
        return login_redirect

    return render_template(
        "dashboard.html",
        username=session.get("username"),
        is_admin=is_admin_user(),
    )


@app.route("/users")
def users():
    admin_redirect = require_admin()
    if admin_redirect:
        return admin_redirect

    registered_users = User.query.order_by(User.id.desc()).all()
    return render_template(
        "users.html",
        username=session.get("username"),
        users=registered_users,
        total_users=len(registered_users),
    )


@app.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
def edit_user(user_id):
    admin_redirect = require_admin()
    if admin_redirect:
        return admin_redirect

    user = db.get_or_404(User, user_id)
    form = UserUpdateForm(obj=user)

    if form.validate_on_submit():
        new_email = form.email.data.strip().lower()
        existing_user = User.query.filter(
            User.email == new_email,
            User.id != user.id,
        ).first()

        if existing_user:
            flash("Another account already uses this email address.", "error")
            return render_template("edit_user.html", form=form, user=user)

        current_email = user.email.strip().lower()
        session_email = session.get("email", "").strip().lower()

        if current_email == session_email and new_email != current_email:
            flash("Update ADMIN_EMAIL before changing the admin account email.", "error")
            return render_template("edit_user.html", form=form, user=user)

        user.username = form.username.data.strip()
        user.email = new_email

        if form.password.data:
            user.password_hash = generate_password_hash(form.password.data)

        db.session.commit()
        flash(f"{user.username}'s account was updated successfully.", "success")
        return redirect(url_for("users"))

    return render_template("edit_user.html", form=form, user=user)


@app.route("/users/<int:user_id>/delete", methods=["POST"])
def delete_user(user_id):
    admin_redirect = require_admin()
    if admin_redirect:
        return admin_redirect

    user = db.get_or_404(User, user_id)

    if user.email.strip().lower() == session.get("email", "").strip().lower():
        flash("You cannot delete the admin account that is currently signed in.", "error")
        return redirect(url_for("users"))

    db.session.delete(user)
    db.session.commit()
    flash(f"{user.username}'s account was deleted successfully.", "success")
    return redirect(url_for("users"))


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
