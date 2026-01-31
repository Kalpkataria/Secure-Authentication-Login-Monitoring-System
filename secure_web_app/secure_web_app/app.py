from flask import Flask, render_template, request, redirect, session, flash
import sqlite3
import bcrypt

app = Flask(__name__)
app.secret_key = "super_secret_key_change_this"

def get_db():
    return sqlite3.connect("users.db")


with get_db() as conn:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users(
            username TEXT PRIMARY KEY,
            password BLOB NOT NULL
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS login_logs(
            username TEXT,
            status TEXT,
            ip TEXT,
            time DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)


@app.route("/", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

        try:
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO users VALUES (?, ?)",
                    (username, hashed)
                )
            flash("Registration successful! Please login.", "success")
            return redirect("/login")

        except sqlite3.IntegrityError:
            flash("Username already exists!", "error")

    return render_template("register.html")



@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        ip = request.remote_addr

        with get_db() as conn:
            user = conn.execute(
                "SELECT password FROM users WHERE username = ?",
                (username,)
            ).fetchone()

    
        if not user:
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO login_logs(username, status, ip) VALUES (?, 'FAILED', ?)",
                    (username, ip)
                )
            flash("Invalid username or password", "error")
            return render_template("login.html")

    
        if not bcrypt.checkpw(password.encode(), user[0]):
            with get_db() as conn:
                conn.execute(
                    "INSERT INTO login_logs(username, status, ip) VALUES (?, 'FAILED', ?)",
                    (username, ip)
                )
            flash("Invalid username or password", "error")
            return render_template("login.html")

       
        session.clear()
        session["user"] = username
        session.modified = True

        with get_db() as conn:
            conn.execute(
                "INSERT INTO login_logs(username, status, ip) VALUES (?, 'SUCCESS', ?)",
                (username, ip)
            )

        flash("Login successful!", "success")
        return redirect("/dashboard")

    return render_template("login.html")



@app.route("/dashboard")
def dashboard():

    print("SESSION IN DASHBOARD:", session)
    if "user" not in session:
        return redirect("/login")
    
    with get_db() as conn:
        logs=conn.execute(
            """
            SELECT username,status, ip ,time
            FROM login_logs
            WHERE username = ?
            ORDER BY time DESC
            LIMIT 10
            """,
            (session["user"],)
        ).fetchall()

        total_attempts = conn.execute(
            "SELECT COUNT(*) FROM login_logs WHERE username = ?",
            (session["user"],)
        ).fetchone()[0]

        failed_attempts = conn.execute(
            "SELECT COUNT(*) FROM login_logs WHERE username = ? AND status='FAILED'",
            (session["user"],)
        ).fetchone()[0]

        last_ip_row = conn.execute(
            """
            SELECT ip FROM login_logs
            WHERE username = ? AND status='SUCCESS'
            ORDER BY time DESC
            LIMIT 1
            """,
            (session["user"],)
        ).fetchone()

        last_ip = last_ip_row[0] if last_ip_row else "N/A"



    return render_template("dashboard.html", user=session["user"], logs=logs,total=total_attempts,failed=failed_attempts,last_ip=last_ip)


@app.route("/export")
def export_logs():
    if "user" not in session:
        return redirect("/login")

    import csv
    from io import StringIO

    output = StringIO()
    writer = csv.writer(output)

    with get_db() as conn:
        logs = conn.execute(
            """
            SELECT status, ip, time
            FROM login_logs
            WHERE username = ?
            ORDER BY time DESC
            """,
            (session["user"],)
        ).fetchall()

    writer.writerow(["Status", "IP Address", "Time"])
    writer.writerows(logs)

    return output.getvalue(), 200, {
        "Content-Type": "text/csv",
        "Content-Disposition": "attachment; filename=login_logs.csv"
    }


@app.route("/logout")
def logout():
    session.pop("user", None)
    flash("Logged out successfully.", "success")
    return redirect("/login")

if __name__ == "__main__":
    app.run(debug=False)
