#!/usr/bin/env python3
"""
Vulnerable Web Application for Scraping Challenge

Simple Flask app with login, session handling, and employee directory.
"""

from flask import Flask, render_template_string, request, session, redirect, url_for
import secrets
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Credentials
USERS = {"admin": "password123"}

# Employee data (paginated)
EMPLOYEES = [
    {
        "id": i,
        "name": f"Employee {i}",
        "email": f"emp{i}@company.com",
        "department": "Engineering" if i % 2 == 0 else "Sales",
    }
    for i in range(1, 101)
]

# Add flag to specific employee
EMPLOYEES[49]["notes"] = "FLAG{Web_Scraping_Masters_The_DOM}"


@app.route("/")
def index():
    if "username" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login_page"))


@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        request.form.get("csrf_token")

        if username in USERS and USERS[username] == password:
            session["username"] = username
            return redirect(url_for("dashboard"))

        return "Invalid credentials", 401

    csrf_token = secrets.token_hex(16)
    session["csrf_token"] = csrf_token

    return render_template_string(
        """
        <html>
        <body>
            <h1>Company Intranet Login</h1>
            <form method="post">
                <input type="hidden" name="csrf_token" value="{{ csrf }}">
                Username: <input name="username"><br>
                Password: <input type="password" name="password"><br>
                <button type="submit">Login</button>
            </form>
        </body>
        </html>
    """,
        csrf=csrf_token,
    )


@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login_page"))

    return render_template_string(
        """
        <html>
        <body>
            <h1>Dashboard</h1>
            <p>Welcome, {{ username }}!</p>
            <a href="/employees">Employee Directory</a>
        </body>
        </html>
    """,
        username=session["username"],
    )


@app.route("/employees")
def employees():
    if "username" not in session:
        return redirect(url_for("login_page"))

    page = int(request.args.get("page", 1))
    per_page = 10
    start = (page - 1) * per_page
    end = start + per_page

    page_employees = EMPLOYEES[start:end]

    rows = "".join(
        [
            f'<tr><td>{e["id"]}</td><td><a href="/employee/{e["id"]}">{e["name"]}</a></td><td>{e["email"]}</td><td>{e["department"]}</td></tr>'
            for e in page_employees
        ]
    )

    return render_template_string(
        """
        <html>
        <body>
            <h1>Employee Directory</h1>
            <table id="employee-table" border="1">
                <tr><th>ID</th><th>Name</th><th>Email</th><th>Department</th></tr>
                {{ rows|safe }}
            </table>
            <p>
                {% if page > 1 %}<a href="?page={{ page - 1 }}">Previous</a>{% endif %}
                Page {{ page }}
                {% if has_next %}<a href="?page={{ page + 1 }}">Next</a>{% endif %}
            </p>
        </body>
        </html>
    """,
        rows=rows,
        page=page,
        has_next=end < len(EMPLOYEES),
    )


@app.route("/employee/<int:emp_id>")
def employee_detail(emp_id):
    if "username" not in session:
        return redirect(url_for("login_page"))

    emp = next((e for e in EMPLOYEES if e["id"] == emp_id), None)
    if not emp:
        return "Not found", 404

    return render_template_string(
        """
        <html>
        <body>
            <h1>{{ emp.name }}</h1>
            <p>Email: {{ emp.email }}</p>
            <p>Department: {{ emp.department }}</p>
            {% if emp.get('notes') %}
            <p>Notes: {{ emp.notes }}</p>
            {% endif %}
        </body>
        </html>
    """,
        emp=emp,
    )


if __name__ == "__main__":
    print(f"FLAG: {EMPLOYEES[49]['notes']}")
    app.run(host="0.0.0.0", port=8080, debug=True)
