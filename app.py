from flask import Flask, flash, redirect, render_template, session, url_for
from register import LoginForm, RegisterForm

app = Flask(__name__)
app.config["SECRET_KEY"] = "secret_key"
users = {}


@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        user = users.get(email)

        if not user or user["password"] != password:
            flash("Incorrect email or password. Please try again.", "error")
        else:
            session["username"] = user["username"]
            session["email"] = email
            flash(f"Welcome back, {user['username']}!", "success")
            return redirect(url_for("dashboard"))

    return render_template("login.html", form=form)


@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data

        if email in users:
            flash("An account with this email already exists.", "error")
            return render_template("register.html", form=form)

        users[email] = {
            "username": username,
            "password": password,
        }

        flash(f"Registration successful for {username}", "success")
        return redirect(url_for("login"))

    return render_template("register.html", form=form)


@app.route("/dashboard")
def dashboard():
    username = session.get("username")

    if not username:
        flash("Please sign in to open the dashboard.", "error")
        return redirect(url_for("login"))

    return render_template("dashboard.html", username=username)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
