import sys
try:
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
except Exception:
    pass

from flask import Flask, render_template, request, session, redirect, url_for, jsonify, g
from werkzeug.security import check_password_hash, generate_password_hash
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail, Message
import sqlite3
from datetime import datetime, timedelta
import json
import os
import secrets

app = Flask(__name__)

# ── Secret Key (REQUIRED — app refuses to start without it in production) ──
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-insecure-key-change-in-production")
if app.secret_key == "dev-only-insecure-key-change-in-production":
    print("[WARNING] Using insecure dev secret key. Set SECRET_KEY env variable in production!")

# ── Absolute DB path ──
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(BASE_DIR, "database.db")

# ── PostgreSQL Support ──
DATABASE_URL = os.environ.get("DATABASE_URL", "")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
USE_POSTGRES = bool(DATABASE_URL)
print("✓ Database:", "PostgreSQL" if USE_POSTGRES else "SQLite (local)")

# ================= CSRF PROTECTION =================
csrf = CSRFProtect(app)

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return render_template("error.html",
        error_title="Security Error",
        error_message="Your session expired or the form was tampered with. Please try again."), 400


# ================= RATE LIMITING =================
limiter = Limiter(
    get_remote_address,         # key_func must be FIRST positional arg in flask-limiter 3.x
    app=app,
    default_limits=[],          # No global limit — apply per-route
    storage_uri="memory://"     # In-memory storage (use Redis in production)
)


# ================= FLASK-MAIL CONFIG =================
# Set these environment variables before running:
#   MAIL_SERVER     e.g. smtp.gmail.com
#   MAIL_PORT       e.g. 587
#   MAIL_USERNAME   e.g. yourapp@gmail.com
#   MAIL_PASSWORD   e.g. your_app_password  (use Gmail App Password)
#   MAIL_DEFAULT_SENDER  e.g. M3 Portfolio <yourapp@gmail.com>

app.config["MAIL_SERVER"]          = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
app.config["MAIL_PORT"]            = int(os.environ.get("MAIL_PORT", 587))
app.config["MAIL_USE_TLS"]         = True
app.config["MAIL_USE_SSL"]         = False
app.config["MAIL_USERNAME"]        = os.environ.get("MAIL_USERNAME", "")
app.config["MAIL_PASSWORD"]        = os.environ.get("MAIL_PASSWORD", "")
app.config["MAIL_DEFAULT_SENDER"]  = os.environ.get("MAIL_DEFAULT_SENDER", "M3 Portfolio <no-reply@m3portfolio.com>")

mail = Mail(app)


# ================= SESSION CONFIG =================
app.config["SESSION_COOKIE_HTTPONLY"] = True   # JS cannot read cookie
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # CSRF protection layer 2
# Force HTTPS scheme for url_for() on Render/production
app.config["PREFERRED_URL_SCHEME"] = "https" if os.environ.get("FLASK_ENV") == "production" else "http"
app.config["SESSION_COOKIE_SECURE"]   = os.environ.get("FLASK_ENV", "development") == "production"  # HTTPS only in prod
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=2)  # Auto logout after 2 hrs


# ================= USER PREFERENCES LOADER =================
@app.before_request
def load_user_preferences():
    if "user_id" in session and "currency_format" not in session:
        try:
            conn = get_db_connection()
            user = conn.execute(
                "SELECT currency_format, theme, autosave FROM users WHERE id = ?",
                (session["user_id"],)
            ).fetchone()
            conn.close()
            if user:
                session["currency_format"] = user["currency_format"] or "indian"
                session["theme"]           = user["theme"] or "light"
                session["autosave"]        = bool(user["autosave"])
        except Exception:
            pass


# ================= TEMPLATE FILTERS =================
@app.template_filter('abs')
def abs_filter(value):
    try:
        return abs(float(value))
    except Exception:
        return value


@app.template_filter('indian_currency')
def indian_currency_filter(amount):
    try:
        value = int(float(amount))
    except Exception:
        return str(amount)

    fmt = session.get('currency_format', 'indian')
    if fmt == 'western':
        return '{:,}'.format(value)
    else:
        s = str(value)
        if len(s) <= 3:
            return s
        last3 = s[-3:]
        remaining = s[:-3]
        result = last3
        while remaining:
            if len(remaining) <= 2:
                result = remaining + ',' + result
                break
            result = remaining[-2:] + ',' + result
            remaining = remaining[:-2]
        return result


# ================= DATABASE INITIALIZATION =================
def fix_query(q):
    """Convert SQLite ? placeholders to PostgreSQL %s"""
    if USE_POSTGRES:
        q = q.replace("?", "%s")
        q = q.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
    return q


class _PGCursor:
    """Wraps psycopg2 cursor result to support both [0] and ['col'] access"""
    def __init__(self, cur):
        self._cur = cur

    def fetchone(self):
        row = self._cur.fetchone()
        if row is None:
            return None
        return _PGRow(row)

    def fetchall(self):
        rows = self._cur.fetchall()
        return [_PGRow(r) for r in rows]

    def __iter__(self):
        for row in self._cur:
            yield _PGRow(row)

    @property
    def description(self):
        return self._cur.description


class _PGRow:
    """Wraps a psycopg2 RealDictRow to support both row[0] and row['col']"""
    def __init__(self, row):
        self._row = row
        self._keys = list(row.keys()) if hasattr(row, 'keys') else []

    def __getitem__(self, key):
        if isinstance(key, int):
            # Use .values() for positional access — RealDictRow keys are strings
            # (e.g. "count", "avg"), so self._row[self._keys[key]] fails with KeyError: 0
            return list(self._row.values())[key]
        return self._row[key]

    def __contains__(self, key):
        return key in self._row

    def keys(self):
        return self._keys

    def get(self, key, default=None):
        return self._row.get(key, default)

    def __repr__(self):
        return repr(dict(self._row))


class _ConnWrapper:
    """Wraps psycopg2 connection to support conn.execute() like SQLite"""
    def __init__(self, conn):
        self._conn = conn
        self._cur = None

    def execute(self, query, params=()):
        self._cur = self._conn.cursor()
        self._cur.execute(fix_query(query), params)
        return _PGCursor(self._cur)

    def fetchone(self):
        if self._cur:
            row = self._cur.fetchone()
            return _PGRow(row) if row else None
        return None

    def fetchall(self):
        if self._cur:
            return [_PGRow(r) for r in self._cur.fetchall()]
        return []

    def commit(self):
        self._conn.commit()

    def close(self):
        self._conn.close()

    def __getattr__(self, name):
        return getattr(self._conn, name)



def fetch_count(conn, query, params=()):
    """Helper for COUNT queries - works with both SQLite and PostgreSQL"""
    row = conn.execute(fix_query(query), params).fetchone()
    if row is None:
        return 0
    # Try integer index first, then 'count' key
    try:
        return row[0] or 0
    except (KeyError, IndexError):
        return 0


def get_db_connection():
    """Returns PostgreSQL in production, SQLite locally"""
    if USE_POSTGRES:
        import psycopg2, psycopg2.extras
        conn = psycopg2.connect(DATABASE_URL, cursor_factory=psycopg2.extras.RealDictCursor)
        return _ConnWrapper(conn)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    if USE_POSTGRES:
        import psycopg2
        conn = psycopg2.connect(DATABASE_URL)
        conn.autocommit = True  # Each statement is its own transaction
    else:
        conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # ── Users table ──
    cursor.execute(fix_query("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """))

    # ── Clients table (NEW) ──
    cursor.execute(fix_query("""
    CREATE TABLE IF NOT EXISTS clients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        advisor_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        email TEXT,
        phone TEXT,
        age INTEGER,
        risk_profile TEXT DEFAULT 'moderate',
        notes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (advisor_id) REFERENCES users(id)
    )
    """))

    # ── Portfolio analyses table ──
    cursor.execute(fix_query("""
    CREATE TABLE IF NOT EXISTS portfolio_analyses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        client_name TEXT NOT NULL,
        current_total REAL NOT NULL,
        current_return REAL NOT NULL,
        revised_total REAL NOT NULL,
        revised_return REAL NOT NULL,
        overall_rating TEXT,
        fv_5yr_current REAL,
        fv_5yr_revised REAL,
        fv_10yr_current REAL,
        fv_10yr_revised REAL,
        fv_20yr_current REAL,
        fv_20yr_revised REAL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """))

    # Safe migrations — add new columns if they don't exist
    safe_alters = [
        "ALTER TABLE portfolio_analyses ADD COLUMN r1_equity_pct REAL DEFAULT 0",
        "ALTER TABLE portfolio_analyses ADD COLUMN r1_debt_pct REAL DEFAULT 0",
        "ALTER TABLE portfolio_analyses ADD COLUMN r1_real_pct REAL DEFAULT 0",
        "ALTER TABLE portfolio_analyses ADD COLUMN r1_alternate_pct REAL DEFAULT 0",
        "ALTER TABLE portfolio_analyses ADD COLUMN r1_liq_score REAL DEFAULT 0",
        "ALTER TABLE portfolio_analyses ADD COLUMN r2_equity_pct REAL DEFAULT 0",
        "ALTER TABLE portfolio_analyses ADD COLUMN r2_debt_pct REAL DEFAULT 0",
        "ALTER TABLE portfolio_analyses ADD COLUMN r2_real_pct REAL DEFAULT 0",
        "ALTER TABLE portfolio_analyses ADD COLUMN r2_alternate_pct REAL DEFAULT 0",
        "ALTER TABLE portfolio_analyses ADD COLUMN r2_liq_score REAL DEFAULT 0",
        "ALTER TABLE portfolio_analyses ADD COLUMN client_id INTEGER REFERENCES clients(id)",
        "ALTER TABLE users ADD COLUMN currency_format TEXT DEFAULT 'indian'",
        "ALTER TABLE users ADD COLUMN theme TEXT DEFAULT 'light'",
        "ALTER TABLE users ADD COLUMN autosave INTEGER DEFAULT 0",
        "ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0",
        "ALTER TABLE users ADD COLUMN is_blocked INTEGER DEFAULT 0",
        "ALTER TABLE portfolio_analyses ADD COLUMN raw_data TEXT",
    ]
    for sql in safe_alters:
        try:
            cursor.execute(fix_query(sql))
            if not USE_POSTGRES:
                conn.commit()
        except Exception:
            pass  # Column already exists — ignore

    # ── Password reset tokens table ──
    cursor.execute(fix_query("""
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token TEXT UNIQUE NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        used INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """))

    # ── SIP Plans table ──
    cursor.execute(fix_query("""
    CREATE TABLE IF NOT EXISTS sip_plans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        amount REAL NOT NULL,
        start_date TEXT NOT NULL,
        duration_months INTEGER NOT NULL,
        fund_name TEXT,
        notes TEXT,
        is_active INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    """))

    # ── SIP Payments table ──
    cursor.execute(fix_query("""
    CREATE TABLE IF NOT EXISTS sip_payments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        plan_id INTEGER NOT NULL,
        month TEXT NOT NULL,
        status TEXT DEFAULT 'pending',
        paid_amount REAL,
        paid_date TEXT,
        notes TEXT,
        FOREIGN KEY (plan_id) REFERENCES sip_plans(id)
    )
    """))

    if not USE_POSTGRES:
        conn.commit()
    conn.close()
    print("✓ Database initialized successfully")


init_db()


# ================= HELPER FUNCTIONS =================
def send_reset_email(user_email, user_name, reset_url):
    """Send password reset email. Returns (success: bool, error: str)"""
    # If mail is not configured, fall back to showing the link on screen
    if not app.config["MAIL_USERNAME"]:
        return False, "mail_not_configured"
    try:
        msg = Message(
            subject="Reset Your M3 Portfolio Password",
            recipients=[user_email]
        )
        msg.html = render_template(
            "email_reset_password.html",
            user_name=user_name,
            reset_url=reset_url
        )
        mail.send(msg)
        return True, None
    except Exception as e:
        print(f"Mail error: {e}")
        return False, str(e)


# ================= ROUTES =================

@app.route("/")
def home():
    return render_template("index.html")


# ── LOGIN (Rate limited: 5 attempts per minute per IP) ──
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute; 20 per hour")
def login():
    if request.method == "POST":
        email    = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        conn = get_db_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE LOWER(email) = LOWER(?)", (email,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            if user["is_blocked"]:
                return render_template("login.html", error="Your account has been suspended. Please contact support.")
            session.permanent = True
            session["user_id"]   = user["id"]
            session["user_name"] = user["name"]
            session["is_admin"]  = bool(user["is_admin"])
            return redirect(url_for("dashboard"))
        else:
            return render_template("login.html", error="Invalid email or password. Please try again.")

    return render_template("login.html")


@app.errorhandler(429)
def rate_limit_exceeded(e):
    return render_template("login.html",
        error="Too many login attempts. Please wait a minute and try again."), 429


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name     = (request.form.get("name") or "").strip()
        email    = (request.form.get("email") or "").strip().lower()
        password = (request.form.get("password") or "").strip()

        if not name or not email or not password:
            return render_template("register.html", error="All fields are required.")
        if len(password) < 6:
            return render_template("register.html",
                error="Password must be at least 6 characters.", name=name, email=email)

        try:
            conn = get_db_connection()
            conn.execute(
                "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
                (name, email, generate_password_hash(password))
            )
            conn.commit()
            conn.close()
            return redirect(url_for("login"))
        except Exception as e:
            # sqlite3 raises IntegrityError; psycopg2 raises UniqueViolation.
            # Both contain "unique" or "duplicate" in their string representation.
            err_lower = str(e).lower()
            if "unique" in err_lower or "duplicate" in err_lower:
                return render_template("register.html",
                    error="Email already exists. Try logging in.", name=name)
            raise  # re-raise unexpected errors so they show up in logs

    return render_template("register.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ================= FORGOT / RESET PASSWORD (with Real Email) =================

@app.route("/forgot", methods=["GET", "POST"])
@limiter.limit("3 per hour")
def forgot_password():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip()
        if not email:
            return render_template("forgot.html", error="Please enter your email address.")

        conn = get_db_connection()
        user = conn.execute("SELECT id, name FROM users WHERE LOWER(email) = LOWER(?)", (email,)).fetchone()

        # Always show same message — don't reveal whether email exists
        if not user:
            conn.close()
            return render_template("forgot.html",
                success="If that email is registered, a password reset link has been sent.")

        # Expire old tokens
        conn.execute(
            "UPDATE password_reset_tokens SET used = 1 WHERE user_id = ? AND used = 0",
            (user["id"],)
        )

        # Generate secure token (30 minutes expiry)
        token      = secrets.token_urlsafe(32)
        expires_at = datetime.utcnow() + timedelta(minutes=30)
        conn.execute(
            "INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)",
            (user["id"], token, expires_at.strftime("%Y-%m-%d %H:%M:%S"))
        )
        conn.commit()
        conn.close()

        # Force HTTPS on Render/production — url_for may default to HTTP
        reset_url = url_for("reset_password", token=token, _external=True)
        if request.headers.get("X-Forwarded-Proto") == "https" or \
           os.environ.get("FLASK_ENV") == "production":
            reset_url = reset_url.replace("http://", "https://", 1)

        # Try to send real email
        sent, error = send_reset_email(email, user["name"], reset_url)

        if sent:
            # Email sent successfully
            return render_template("forgot.html",
                success=f"Password reset link sent to {email}. Check your inbox (and spam folder).")
        else:
            # Mail not configured OR failed — ALWAYS show the reset link so user can proceed
            if error == "mail_not_configured":
                msg = f"Email service not configured. Use the link below to reset your password:"
            else:
                print(f"Mail send failed: {error}")
                msg = f"Email could not be sent ({error[:80]}). Use the link below to reset your password:"
            return render_template("forgot.html",
                success=msg,
                reset_link=reset_url,
                user_name=user["name"])

    return render_template("forgot.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    conn = get_db_connection()
    now  = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    row  = conn.execute(
        """SELECT t.id, t.user_id, u.email
           FROM password_reset_tokens t
           JOIN users u ON u.id = t.user_id
           WHERE t.token = ? AND t.used = 0 AND t.expires_at >= ?""",
        (token, now)
    ).fetchone()
    conn.close()

    if not row:
        return render_template("reset_password.html",
            error="This reset link is invalid or has expired. Please request a new one.",
            token=None)

    if request.method == "POST":
        new_password     = (request.form.get("new_password") or "").strip()
        confirm_password = (request.form.get("confirm_password") or "").strip()

        if not new_password or len(new_password) < 6:
            return render_template("reset_password.html",
                error="Password must be at least 6 characters.", token=token)
        if new_password != confirm_password:
            return render_template("reset_password.html",
                error="Passwords do not match.", token=token)

        conn = get_db_connection()
        conn.execute("UPDATE users SET password = ? WHERE id = ?",
                     (generate_password_hash(new_password), row["user_id"]))
        conn.execute("UPDATE password_reset_tokens SET used = 1 WHERE token = ?", (token,))
        conn.commit()
        conn.close()

        return render_template("reset_password.html",
            success="Password reset successfully! You can now log in.",
            token=None)

    return render_template("reset_password.html", token=token, email=row["email"])


# ================= DASHBOARD =================

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()
    uid  = session["user_id"]

    # Stats for dashboard cards
    total_analyses = conn.execute(
        "SELECT COUNT(*) FROM portfolio_analyses WHERE user_id = ?", (uid,)
    ).fetchone()[0]

    total_clients = conn.execute(
        "SELECT COUNT(*) FROM clients WHERE advisor_id = ?", (uid,)
    ).fetchone()[0]

    avg_revised_return = conn.execute(
        "SELECT AVG(revised_return) FROM portfolio_analyses WHERE user_id = ?", (uid,)
    ).fetchone()[0] or 0
    avg_return = avg_revised_return  # alias kept for template compatibility

    recent_analyses = conn.execute(
        """SELECT pa.id, pa.client_name, pa.revised_return, pa.overall_rating, pa.created_at
           FROM portfolio_analyses pa
           WHERE pa.user_id = ?
           ORDER BY pa.created_at DESC LIMIT 5""",
        (uid,)
    ).fetchall()

    conn.close()

    return render_template("dashboard.html",
        user_name=session.get("user_name"),
        total_analyses=total_analyses,
        total_clients=total_clients,
        avg_return=round(avg_return, 1),
        recent_analyses=recent_analyses
    )


# ================= CLIENT MANAGEMENT (NEW) =================

@app.route("/clients")
def clients():
    if "user_id" not in session:
        return redirect(url_for("login"))

    search = request.args.get("search", "").strip()
    risk   = request.args.get("risk", "").strip()

    query  = "SELECT * FROM clients WHERE advisor_id = ?"
    params = [session["user_id"]]

    if search:
        query  += " AND name LIKE ?"
        params.append(f"%{search}%")
    if risk:
        query  += " AND risk_profile = ?"
        params.append(risk)

    query += " ORDER BY created_at DESC"

    conn    = get_db_connection()
    clients_list = conn.execute(query, params).fetchall()

    # Get analysis count per client
    client_analysis_counts = {}
    for c in clients_list:
        count = conn.execute(
            "SELECT COUNT(*) FROM portfolio_analyses WHERE client_id = ?", (c["id"],)
        ).fetchone()[0]
        client_analysis_counts[c["id"]] = count

    conn.close()

    return render_template("clients.html",
        clients=clients_list,
        search=search,
        risk=risk,
        client_analysis_counts=client_analysis_counts
    )


@app.route("/clients/add", methods=["GET", "POST"])
def add_client():
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        name         = (request.form.get("name") or "").strip()
        email        = (request.form.get("email") or "").strip()
        phone        = (request.form.get("phone") or "").strip()
        age_raw      = request.form.get("age", "").strip()
        risk_profile = request.form.get("risk_profile", "moderate")
        notes        = (request.form.get("notes") or "").strip()

        if not name:
            return render_template("add_edit_client.html",
                mode="add", error="Client name is required.",
                form=request.form)

        try:
            age = int(age_raw) if age_raw else None
            if age and (age < 1 or age > 120):
                raise ValueError
        except ValueError:
            return render_template("add_edit_client.html",
                mode="add", error="Please enter a valid age.",
                form=request.form)

        conn = get_db_connection()
        conn.execute(
            """INSERT INTO clients (advisor_id, name, email, phone, age, risk_profile, notes)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (session["user_id"], name, email, phone, age, risk_profile, notes)
        )
        conn.commit()
        conn.close()

        return redirect(url_for("clients"))

    return render_template("add_edit_client.html", mode="add", form={})


@app.route("/clients/<int:client_id>")
def view_client(client_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn   = get_db_connection()
    client = conn.execute(
        "SELECT * FROM clients WHERE id = ? AND advisor_id = ?",
        (client_id, session["user_id"])
    ).fetchone()

    if not client:
        conn.close()
        return redirect(url_for("clients"))

    # All analyses linked to this client
    analyses = conn.execute(
        """SELECT * FROM portfolio_analyses
           WHERE client_id = ? AND user_id = ?
           ORDER BY created_at DESC""",
        (client_id, session["user_id"])
    ).fetchall()

    conn.close()

    return render_template("client_detail.html",
        client=client,
        analyses=analyses
    )


@app.route("/clients/<int:client_id>/edit", methods=["GET", "POST"])
def edit_client(client_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn   = get_db_connection()
    client = conn.execute(
        "SELECT * FROM clients WHERE id = ? AND advisor_id = ?",
        (client_id, session["user_id"])
    ).fetchone()
    conn.close()

    if not client:
        return redirect(url_for("clients"))

    if request.method == "POST":
        name         = (request.form.get("name") or "").strip()
        email        = (request.form.get("email") or "").strip()
        phone        = (request.form.get("phone") or "").strip()
        age_raw      = request.form.get("age", "").strip()
        risk_profile = request.form.get("risk_profile", "moderate")
        notes        = (request.form.get("notes") or "").strip()

        if not name:
            return render_template("add_edit_client.html",
                mode="edit", client=client, error="Client name is required.", form=request.form)

        try:
            age = int(age_raw) if age_raw else None
            if age and (age < 1 or age > 120):
                raise ValueError
        except ValueError:
            return render_template("add_edit_client.html",
                mode="edit", client=client, error="Please enter a valid age.", form=request.form)

        conn = get_db_connection()
        conn.execute(
            """UPDATE clients
               SET name = ?, email = ?, phone = ?, age = ?, risk_profile = ?, notes = ?
               WHERE id = ? AND advisor_id = ?""",
            (name, email, phone, age, risk_profile, notes, client_id, session["user_id"])
        )
        conn.commit()
        conn.close()

        return redirect(url_for("view_client", client_id=client_id))

    return render_template("add_edit_client.html", mode="edit", client=client, form=client)


@app.route("/clients/delete/<int:client_id>", methods=["POST"])
def delete_client(client_id):
    if "user_id" not in session:
        return jsonify({"success": False, "message": "Not logged in"})

    conn = get_db_connection()
    client = conn.execute(
        "SELECT id FROM clients WHERE id = ? AND advisor_id = ?",
        (client_id, session["user_id"])
    ).fetchone()

    if not client:
        conn.close()
        return jsonify({"success": False, "message": "Client not found"})

    # Unlink analyses (don't delete them — just remove the client_id link)
    conn.execute(
        "UPDATE portfolio_analyses SET client_id = NULL WHERE client_id = ?",
        (client_id,)
    )
    conn.execute("DELETE FROM clients WHERE id = ?", (client_id,))
    conn.commit()
    conn.close()

    return jsonify({"success": True, "message": "Client deleted successfully"})


# ================= PORTFOLIO =================

@app.route("/portfolio")
def portfolio():
    if "user_id" not in session:
        return redirect(url_for("login"))

    # Pass clients list so advisor can link analysis to a client
    conn    = get_db_connection()
    clients_list = conn.execute(
        "SELECT id, name FROM clients WHERE advisor_id = ? ORDER BY name",
        (session["user_id"],)
    ).fetchall()
    conn.close()

    return render_template("portfolio.html", clients=clients_list)


@app.route("/result", methods=["POST"])
def result():
    if "user_id" not in session:
        return redirect(url_for("login"))

    def safe_float(val, default=0.0):
        try:
            if val in (None, ""):
                return default
            return float(str(val).replace(',', ''))
        except (ValueError, TypeError):
            return None

    name       = request.form.get("name", "Client")
    client_id  = request.form.get("client_id") or None
    if client_id:
        try:
            client_id = int(client_id)
        except (ValueError, TypeError):
            client_id = None

    current_total  = safe_float(request.form.get("current_total"))
    current_return = safe_float(request.form.get("current_return"))
    revised_total  = safe_float(request.form.get("revised_total"))
    revised_return = safe_float(request.form.get("revised_return"))

    if None in (current_total, current_return, revised_total, revised_return):
        conn = get_db_connection()
        clients_list = conn.execute(
            "SELECT id, name FROM clients WHERE advisor_id = ? ORDER BY name",
            (session["user_id"],)
        ).fetchall()
        conn.close()
        return render_template("portfolio.html",
            error="Please enter valid numbers in all amount and return fields.",
            clients=clients_list)

    current_return /= 100
    revised_return /= 100

    instruments_meta = [
        ("fd",         "debt",       "high"),
        ("gold",       "alternate",  "medium"),
        ("elss",       "equity",     "low"),
        ("pms",        "equity",     "low"),
        ("aif",        "equity",     "low"),
        ("sif",        "equity",     "low"),
        ("govt",       "debt",       "medium"),
        ("insurance",  "debt",       "low"),
        ("ppf",        "debt",       "low"),
        ("epf",        "debt",       "low"),
        ("realestate", "realassets", "low"),
        ("mf",         "equity",     "high"),
        ("equity",     "equity",     "high"),
    ]

    LIQ_MAP = {"high": "high", "med": "medium", "medium": "medium", "low": "low"}
    CAT_MAP = {"equity": "equity", "debt": "debt", "real": "realassets",
               "realassets": "realassets", "alternate": "alternate", "alt": "alternate"}

    def get_amounts(prefix):
        amounts = {}
        for inst_id, cat, liq in instruments_meta:
            raw = request.form.get(f"{prefix}_{inst_id}_amt")
            try:
                val = float(raw.replace(',', '')) if raw not in (None, "") else 0.0
            except (ValueError, TypeError):
                val = 0.0
            amounts[inst_id] = {"amount": val, "category": cat, "liquidity": liq, "label": ""}

        custom_amts  = request.form.getlist(f"{prefix}_custom_amt[]")
        custom_xirrs = request.form.getlist(f"{prefix}_custom_xirr[]")
        custom_cats  = request.form.getlist(f"{prefix}_custom_cat[]")
        custom_liqs  = request.form.getlist(f"{prefix}_custom_liq[]")
        custom_names = request.form.getlist(f"{prefix}_custom_name[]")

        for i, amt_raw in enumerate(custom_amts):
            try:
                amt = float(str(amt_raw).replace(',', ''))
            except (ValueError, TypeError):
                amt = 0.0
            if amt <= 0:
                continue
            try:
                xirr = float(custom_xirrs[i]) if i < len(custom_xirrs) else 0.0
            except (ValueError, TypeError):
                xirr = 0.0
            raw_cat = custom_cats[i]  if i < len(custom_cats)  else "debt"
            raw_liq = custom_liqs[i]  if i < len(custom_liqs)  else "low"
            cname   = custom_names[i] if i < len(custom_names) else f"Custom {i+1}"
            cat  = CAT_MAP.get(raw_cat, "debt")
            liq  = LIQ_MAP.get(raw_liq, "low")
            cid  = f"custom_{prefix}_{i}"
            amounts[cid] = {"amount": amt, "category": cat, "liquidity": liq,
                            "label": cname, "xirr": xirr, "is_custom": True}
        return amounts

    r1_amounts = get_amounts("r1")
    r2_amounts = get_amounts("r2")

    def calc_allocation(amounts, total):
        equity = debt = realassets = alternate = 0
        liq_high = liq_medium = liq_low = 0
        breakdown = {"equity": [], "debt": [], "realassets": [], "alternate": []}
        labels_map = {
            "fd": "FD", "gold": "Gold", "govt": "Govt Bonds",
            "elss": "ELSS", "pms": "PMS", "aif": "AIF", "sif": "SIF",
            "insurance": "Insurance", "ppf": "PPF", "epf": "EPF",
            "realestate": "Real Estate", "mf": "Mutual Funds", "equity": "Equity"
        }
        for inst_id, data in amounts.items():
            amt   = data["amount"]
            cat   = data["category"]
            liq   = data["liquidity"]
            pct   = (amt / total * 100) if total > 0 else 0
            label = data.get("label") or labels_map.get(inst_id, inst_id.title())
            if cat == "equity":       equity     += amt
            elif cat == "debt":       debt       += amt
            elif cat == "realassets": realassets += amt
            elif cat == "alternate":  alternate  += amt
            if liq == "high":         liq_high   += amt
            elif liq == "medium":     liq_medium += amt
            elif liq == "low":        liq_low    += amt
            if amt > 0:
                breakdown[cat].append({"name": label, "amount": amt, "pct": round(pct, 1)})
        liq_score = round(((liq_high + liq_medium * 0.5) / total * 100) if total > 0 else 0, 1)
        return {
            "equity":          round(equity),
            "debt":            round(debt),
            "realassets":      round(realassets),
            "alternate":       round(alternate),
            "equity_pct":      round(equity     / total * 100, 1) if total > 0 else 0,
            "debt_pct":        round(debt        / total * 100, 1) if total > 0 else 0,
            "realassets_pct":  round(realassets  / total * 100, 1) if total > 0 else 0,
            "alternate_pct":   round(alternate   / total * 100, 1) if total > 0 else 0,
            "liq_high":        round(liq_high),
            "liq_medium":      round(liq_medium),
            "liq_low":         round(liq_low),
            "liq_score":       liq_score,
            "breakdown":       breakdown,
        }

    r1_alloc   = calc_allocation(r1_amounts, current_total)
    r2_alloc   = calc_allocation(r2_amounts, revised_total)
    liq_change = round(r2_alloc["liq_score"] - r1_alloc["liq_score"], 1)

    def get_rating(pct):
        if pct >= 12:  return "Excellent"
        elif pct >= 9: return "Good"
        elif pct >= 6: return "Moderate"
        else:          return "Poor"

    current_rating = get_rating(current_return * 100)
    revised_rating = get_rating(revised_return * 100)
    overall_rating = revised_rating

    years_list  = [5, 10, 15, 20, 25]
    future_data = []
    for y in years_list:
        c_fv     = round(current_total * ((1 + current_return) ** y), 2)
        r_fv     = round(revised_total * ((1 + revised_return) ** y), 2)
        diff     = round(r_fv - c_fv, 2)
        pct_gain = round((diff / c_fv * 100) if c_fv > 0 else 0, 2)
        future_data.append({"year": y, "current": c_fv, "revised": r_fv,
                            "difference": diff, "percentage_gain": pct_gain})

    chart_labels  = ["Now"] + [f"{y} Years" for y in years_list]
    chart_current = [round(current_total, 2)] + [d["current"] for d in future_data]
    chart_revised = [round(revised_total, 2)] + [d["revised"] for d in future_data]

    try:
        conn = get_db_connection()
        fv       = {d["year"]: d for d in future_data}
        raw_data = json.dumps(dict(request.form))
        edit_id  = request.form.get("edit_id")

        vals_update = (
            client_id, name,
            current_total, current_return * 100,
            revised_total, revised_return * 100, overall_rating,
            fv.get(5,{}).get("current",0),  fv.get(5,{}).get("revised",0),
            fv.get(10,{}).get("current",0), fv.get(10,{}).get("revised",0),
            fv.get(20,{}).get("current",0), fv.get(20,{}).get("revised",0),
            r1_alloc.get("equity_pct",0), r1_alloc.get("debt_pct",0),
            r1_alloc.get("realassets_pct",0), r1_alloc.get("alternate_pct",0), r1_alloc.get("liq_score",0),
            r2_alloc.get("equity_pct",0), r2_alloc.get("debt_pct",0),
            r2_alloc.get("realassets_pct",0), r2_alloc.get("alternate_pct",0), r2_alloc.get("liq_score",0),
            raw_data
        )

        if edit_id:
            conn.execute(
                """UPDATE portfolio_analyses SET
                   client_id=?, client_name=?, current_total=?, current_return=?,
                   revised_total=?, revised_return=?, overall_rating=?,
                   fv_5yr_current=?, fv_5yr_revised=?,
                   fv_10yr_current=?, fv_10yr_revised=?,
                   fv_20yr_current=?, fv_20yr_revised=?,
                   r1_equity_pct=?, r1_debt_pct=?, r1_real_pct=?, r1_alternate_pct=?, r1_liq_score=?,
                   r2_equity_pct=?, r2_debt_pct=?, r2_real_pct=?, r2_alternate_pct=?, r2_liq_score=?,
                   raw_data=?
                   WHERE id=? AND user_id=?""",
                vals_update + (int(edit_id), session["user_id"])
            )
        else:
            conn.execute(
                """INSERT INTO portfolio_analyses
                   (user_id, client_id, client_name, current_total, current_return,
                    revised_total, revised_return, overall_rating,
                    fv_5yr_current, fv_5yr_revised,
                    fv_10yr_current, fv_10yr_revised,
                    fv_20yr_current, fv_20yr_revised,
                    r1_equity_pct, r1_debt_pct, r1_real_pct, r1_alternate_pct, r1_liq_score,
                    r2_equity_pct, r2_debt_pct, r2_real_pct, r2_alternate_pct, r2_liq_score,
                    raw_data)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (session["user_id"],) + vals_update
            )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Warning: Could not save analysis: {e}")

    # Build instrument comparison list for result page
    labels_map = {
        "fd": "Fixed Deposit", "gold": "Gold", "govt": "Govt Bonds",
        "elss": "ELSS", "pms": "PMS", "aif": "AIF", "sif": "SIF",
        "insurance": "Insurance", "ppf": "PPF", "epf": "EPF",
        "realestate": "Real Estate", "mf": "Mutual Funds", "equity": "Direct Equity"
    }
    instrument_comparison = []
    all_keys = set(list(r1_amounts.keys()) + list(r2_amounts.keys()))
    for k in all_keys:
        r1d = r1_amounts.get(k, {"amount": 0, "category": "debt", "liquidity": "low"})
        r2d = r2_amounts.get(k, {"amount": 0, "category": "debt", "liquidity": "low"})
        r1a = r1d.get("amount", 0)
        r2a = r2d.get("amount", 0)
        if r1a == 0 and r2a == 0:
            continue
        label = r1d.get("label") or r2d.get("label") or labels_map.get(k, k.title())
        r1_xirr = float(request.form.get(f"r1_{k}_xirr", 0) or 0)
        r2_xirr = float(request.form.get(f"r2_{k}_xirr", 0) or 0)
        instrument_comparison.append({
            "name": label,
            "category": r1d.get("category", r2d.get("category", "debt")),
            "r1_amount": round(r1a),
            "r2_amount": round(r2a),
            "r1_xirr": round(r1_xirr, 2),
            "r2_xirr": round(r2_xirr, 2),
            "change": round(r2a - r1a),
        })
    instrument_comparison.sort(key=lambda x: -max(x["r1_amount"], x["r2_amount"]))

    return render_template(
        "result.html",
        name=name,
        current_total=current_total,
        current_return=current_return * 100,
        revised_total=revised_total,
        revised_return=revised_return * 100,
        overall_rating=overall_rating,
        current_rating=current_rating,
        revised_rating=revised_rating,
        r1_alloc=r1_alloc,
        r2_alloc=r2_alloc,
        liq_change=liq_change,
        future_data=future_data,
        instrument_comparison=instrument_comparison,
        chart_labels=json.dumps(chart_labels),
        chart_current=json.dumps(chart_current),
        chart_revised=json.dumps(chart_revised),
    )


# ================= REPORTS =================

@app.route("/reports")
def reports():
    if "user_id" not in session:
        return redirect(url_for("login"))

    search    = request.args.get("search", "").strip()
    date_from = request.args.get("date_from", "").strip()
    date_to   = request.args.get("date_to", "").strip()

    query  = "SELECT * FROM portfolio_analyses WHERE user_id = ?"
    params = [session["user_id"]]

    if search:
        query  += " AND client_name LIKE ?"
        params.append(f"%{search}%")
    if date_from:
        query  += " AND DATE(created_at) >= ?"
        params.append(date_from)
    if date_to:
        query  += " AND DATE(created_at) <= ?"
        params.append(date_to)

    query += " ORDER BY created_at DESC"

    conn        = get_db_connection()
    analyses    = conn.execute(query, params).fetchall()
    total_count = conn.execute(
        "SELECT COUNT(*) FROM portfolio_analyses WHERE user_id = ?",
        (session["user_id"],)
    ).fetchone()[0]
    conn.close()

    return render_template("reports.html", analyses=analyses,
        search=search, date_from=date_from, date_to=date_to, total_count=total_count)


@app.route("/reports/delete/<int:analysis_id>", methods=["POST"])
def delete_report(analysis_id):
    if "user_id" not in session:
        return jsonify({"success": False, "message": "Not logged in"})

    try:
        conn   = get_db_connection()
        report = conn.execute(
            "SELECT id FROM portfolio_analyses WHERE id = ? AND user_id = ?",
            (analysis_id, session["user_id"])
        ).fetchone()

        if not report:
            conn.close()
            return jsonify({"success": False, "message": "Report not found"})

        conn.execute("DELETE FROM portfolio_analyses WHERE id = ?", (analysis_id,))
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": "Report deleted successfully"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})


# ================= EDIT ANALYSIS =================

@app.route("/reports/edit/<int:analysis_id>")
def edit_analysis(analysis_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()
    analysis = conn.execute(
        "SELECT * FROM portfolio_analyses WHERE id = ? AND user_id = ?",
        (analysis_id, session["user_id"])
    ).fetchone()

    clients_list = conn.execute(
        "SELECT id, name FROM clients WHERE advisor_id = ? ORDER BY name",
        (session["user_id"],)
    ).fetchall()
    conn.close()

    if not analysis:
        return redirect(url_for("reports"))

    # Pass raw_data back so portfolio.html can pre-fill the form
    raw_data = analysis["raw_data"] if analysis["raw_data"] else "{}"

    return render_template("portfolio.html",
        clients=clients_list,
        edit_mode=True,
        edit_id=analysis_id,
        edit_data=raw_data
    )


# ================= MEETING MODE (PRESENT) =================

@app.route("/present/<int:analysis_id>")
def present_analysis(analysis_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()
    analysis = conn.execute(
        "SELECT * FROM portfolio_analyses WHERE id = ? AND user_id = ?",
        (analysis_id, session["user_id"])
    ).fetchone()
    advisor = conn.execute(
        "SELECT name FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    conn.close()

    if not analysis:
        return redirect(url_for("reports"))

    return render_template("meeting_mode.html",
        a=analysis,
        advisor_name=(advisor["name"] if advisor else session.get("user_name", ""))
    )


# ================= CALCULATORS =================

@app.route("/calculator/sip", methods=["GET", "POST"])
def sip_calculator():
    if "user_id" not in session:
        return redirect(url_for("login"))
    result = monthly_investment = expected_return = time_period = error = None
    if request.method == "POST":
        try:
            monthly_investment = float((request.form.get("monthly_investment") or "0").replace(",", ""))
            expected_return    = float(request.form.get("expected_return"))
            time_period        = int(request.form.get("time_period"))
        except (TypeError, ValueError):
            error = "Please fill in all fields with valid numbers."
            return render_template("sip_calculator.html", result=None,
                monthly_investment=None, expected_return=None, time_period=None, error=error)
        monthly_rate     = expected_return / 12 / 100
        months           = time_period * 12
        if monthly_rate > 0:
            expected_value = monthly_investment * (
                ((1 + monthly_rate) ** months - 1) / monthly_rate) * (1 + monthly_rate)
        else:
            expected_value = monthly_investment * months
        total_investment = monthly_investment * months
        result = {"total_investment": total_investment,
                  "total_returns": expected_value - total_investment,
                  "expected_value": expected_value}
    return render_template("sip_calculator.html", result=result,
        monthly_investment=monthly_investment, expected_return=expected_return,
        time_period=time_period, error=error)


@app.route("/calculator/stepup-sip", methods=["GET", "POST"])
def stepup_sip_calculator():
    if "user_id" not in session:
        return redirect(url_for("login"))
    result = initial_investment = annual_increment = expected_return = time_period = error = None
    if request.method == "POST":
        try:
            initial_investment = float((request.form.get("initial_investment") or "0").replace(",", ""))
            annual_increment   = float(request.form.get("annual_increment"))
            expected_return    = float(request.form.get("expected_return"))
            time_period        = int(request.form.get("time_period"))
        except (TypeError, ValueError):
            error = "Please fill in all fields with valid numbers."
            return render_template("stepup_sip_calculator.html", result=None,
                initial_investment=None, annual_increment=None,
                expected_return=None, time_period=None, error=error)
        monthly_rate     = expected_return / 12 / 100
        running_value    = 0
        total_investment = 0
        current_monthly  = initial_investment
        yearly_breakdown = []
        final_monthly_sip = initial_investment
        for year in range(1, time_period + 1):
            final_monthly_sip = current_monthly
            for month in range(12):
                running_value    = running_value * (1 + monthly_rate) + current_monthly
                total_investment += current_monthly
            yearly_breakdown.append({"year": year, "monthly_sip": round(current_monthly, 2),
                "total_invested": round(total_investment, 2), "expected_value": round(running_value, 2)})
            if year < time_period:
                current_monthly = current_monthly * (1 + annual_increment / 100)
        result = {"total_investment": total_investment,
                  "total_returns": running_value - total_investment,
                  "expected_value": running_value,
                  "final_monthly_sip": final_monthly_sip,
                  "yearly_breakdown": yearly_breakdown}
    return render_template("stepup_sip_calculator.html", result=result,
        initial_investment=initial_investment, annual_increment=annual_increment,
        expected_return=expected_return, time_period=time_period, error=error)


@app.route("/calculator/lumpsum", methods=["GET", "POST"])
def lumpsum_calculator():
    if "user_id" not in session:
        return redirect(url_for("login"))
    result = investment_amount = expected_return = time_period = error = None
    if request.method == "POST":
        try:
            investment_amount = float((request.form.get("investment_amount") or "0").replace(",", ""))
            expected_return   = float(request.form.get("expected_return"))
            time_period       = int(request.form.get("time_period"))
        except (TypeError, ValueError):
            error = "Please fill in all fields with valid numbers."
            return render_template("lumpsum_calculator.html", result=None,
                investment_amount=None, expected_return=None, time_period=None, error=error)
        annual_rate    = expected_return / 100
        expected_value = investment_amount * ((1 + annual_rate) ** time_period)
        result = {"investment_amount": investment_amount,
                  "total_returns": expected_value - investment_amount,
                  "expected_value": expected_value}
    return render_template("lumpsum_calculator.html", result=result,
        investment_amount=investment_amount, expected_return=expected_return,
        time_period=time_period, error=error)


@app.route("/calculator/swp", methods=["GET", "POST"])
def swp_calculator():
    if "user_id" not in session:
        return redirect(url_for("login"))
    result = initial_investment = monthly_withdrawal = expected_return = time_period = inflation_rate = error = None
    if request.method == "POST":
        try:
            initial_investment  = float((request.form.get("initial_investment") or "0").replace(",", ""))
            monthly_withdrawal  = float((request.form.get("monthly_withdrawal") or "0").replace(",", ""))
            expected_return     = float(request.form.get("expected_return"))
            time_period         = int(request.form.get("time_period"))
            inflation_rate      = float(request.form.get("inflation_rate") or 0)
        except (TypeError, ValueError):
            error = "Please fill in all fields with valid numbers."
            return render_template("swp_calculator.html", result=None,
                initial_investment=None, monthly_withdrawal=None,
                expected_return=None, time_period=None, inflation_rate=None, error=error)
        monthly_rate       = expected_return / 12 / 100
        months             = time_period * 12
        remaining_amount   = initial_investment
        total_withdrawn    = 0
        current_withdrawal = monthly_withdrawal
        corpus_depleted    = False
        for month in range(months):
            # Apply annual inflation at the START of each new year (month 12, 24, 36...)
            if month > 0 and month % 12 == 0 and inflation_rate > 0:
                current_withdrawal = current_withdrawal * (1 + inflation_rate / 100)
            remaining_amount = remaining_amount * (1 + monthly_rate)
            remaining_amount -= current_withdrawal
            total_withdrawn  += current_withdrawal
            if remaining_amount <= 0:
                remaining_amount = 0
                actual_months    = month + 1
                corpus_depleted  = True
                break
        else:
            actual_months = months
        result = {"initial_investment": initial_investment, "total_withdrawn": total_withdrawn,
                  "remaining_amount": max(0, remaining_amount),
                  "total_returns": remaining_amount + total_withdrawn - initial_investment,
                  "months_sustained": actual_months, "final_monthly_withdrawal": current_withdrawal,
                  "corpus_depleted": corpus_depleted}
    return render_template("swp_calculator.html", result=result,
        initial_investment=initial_investment, monthly_withdrawal=monthly_withdrawal,
        expected_return=expected_return, time_period=time_period,
        inflation_rate=inflation_rate, error=error)


@app.route("/calculator/retirement", methods=["GET", "POST"])
def retirement_calculator():
    if "user_id" not in session:
        return redirect(url_for("login"))
    result = current_age = retirement_age = life_expectancy = monthly_expense = None
    expected_return = inflation_rate = post_retirement_return = post_retirement_inflation = error = None

    def _render(err=None):
        return render_template("retirement_calculator.html",
            result=result, current_age=current_age, retirement_age=retirement_age,
            life_expectancy=life_expectancy, monthly_expense=monthly_expense,
            expected_return=expected_return, inflation_rate=inflation_rate,
            post_retirement_return=post_retirement_return,
            post_retirement_inflation=post_retirement_inflation, error=err)

    if request.method == "POST":
        try:
            current_age              = int(request.form.get("current_age"))
            retirement_age           = int(request.form.get("retirement_age"))
            life_expectancy          = int(request.form.get("life_expectancy"))
            monthly_expense          = float((request.form.get("monthly_expense") or "0").replace(",", ""))
            expected_return          = float(request.form.get("expected_return"))
            inflation_rate           = float(request.form.get("inflation_rate") or 6)
            post_retirement_return   = float(request.form.get("post_retirement_return") or 7)
            post_retirement_inflation = float(request.form.get("post_retirement_inflation") or 5)
        except (TypeError, ValueError):
            return _render("Please fill in all fields with valid numbers.")
        if retirement_age <= current_age:
            return _render("Retirement age must be greater than your current age.")
        if life_expectancy <= retirement_age:
            return _render("Life expectancy must be greater than retirement age.")

        years_to_retirement     = retirement_age - current_age
        years_in_retirement     = life_expectancy - retirement_age
        future_monthly_expense  = monthly_expense * ((1 + inflation_rate / 100) ** years_to_retirement)
        post_real_return        = ((1 + post_retirement_return / 100) / (1 + post_retirement_inflation / 100)) - 1
        monthly_post_real_return = post_real_return / 12

        if monthly_post_real_return > 0:
            retirement_corpus = future_monthly_expense * (
                (1 - (1 + monthly_post_real_return) ** (-years_in_retirement * 12)) / monthly_post_real_return)
        else:
            retirement_corpus = future_monthly_expense * years_in_retirement * 12

        monthly_rate          = expected_return / 12 / 100
        months_to_retirement  = years_to_retirement * 12
        if monthly_rate > 0 and months_to_retirement > 0:
            sip_factor        = ((1 + monthly_rate) ** months_to_retirement - 1) / monthly_rate * (1 + monthly_rate)
            monthly_sip_needed = retirement_corpus / sip_factor if sip_factor else 0
        elif months_to_retirement > 0:
            monthly_sip_needed = retirement_corpus / months_to_retirement
        else:
            monthly_sip_needed = 0

        # Post-retirement breakdown uses real return (consistent with corpus sizing)
        post_retirement_breakdown = []
        corpus_remaining          = retirement_corpus
        current_withdrawal        = future_monthly_expense
        for yr in range(1, years_in_retirement + 1):
            for m in range(12):
                corpus_remaining  = corpus_remaining * (1 + monthly_post_real_return)
                corpus_remaining -= current_withdrawal
                if corpus_remaining <= 0:
                    corpus_remaining = 0
                    break
            post_retirement_breakdown.append({
                "year": yr,
                "age": retirement_age + yr,
                "monthly_withdrawal": round(current_withdrawal, 2),
                "corpus_remaining": round(max(0, corpus_remaining), 2)
            })
            # Withdrawal grows by inflation each year (already baked into real-return calc)
            current_withdrawal = current_withdrawal * (1 + post_retirement_inflation / 100)
            if corpus_remaining <= 0:
                break

        result = {"retirement_corpus": retirement_corpus, "monthly_sip_needed": monthly_sip_needed,
                  "future_monthly_expense": future_monthly_expense,
                  "years_to_retirement": years_to_retirement,
                  "years_in_retirement": years_in_retirement,
                  "post_retirement_breakdown": post_retirement_breakdown}
    return _render(error)


@app.route("/calculator/goal-sip", methods=["GET", "POST"])
def goal_sip_calculator():
    if "user_id" not in session:
        return redirect(url_for("login"))
    result = goal_amount = current_savings = time_period = expected_return = inflation_rate = goal_type = None
    if request.method == "POST":
        try:
            goal_type        = request.form.get("goal_type", "other")
            goal_amount      = float((request.form.get("goal_amount") or "0").replace(",", ""))
            current_savings  = float((request.form.get("current_savings") or "0").replace(",", ""))
            time_period      = int(request.form.get("time_period"))
            expected_return  = float(request.form.get("expected_return"))
            inflation_rate   = float(request.form.get("inflation_rate") or 6)
        except (TypeError, ValueError):
            return render_template("goal_sip_calculator.html", result=None,
                goal_amount=None, current_savings=None, time_period=None,
                expected_return=None, inflation_rate=None, goal_type=None,
                error="Please fill in all fields with valid numbers.")
        future_goal_amount           = goal_amount * ((1 + inflation_rate / 100) ** time_period)
        current_savings_future_value = current_savings * ((1 + expected_return / 100) ** time_period)
        amount_needed                = future_goal_amount - current_savings_future_value
        monthly_rate                 = expected_return / 12 / 100
        months                       = time_period * 12
        if amount_needed > 0 and monthly_rate > 0:
            required_sip = amount_needed / (
                (((1 + monthly_rate) ** months - 1) / monthly_rate) * (1 + monthly_rate))
        else:
            required_sip = 0
        annual_rate           = expected_return / 100
        lumpsum_needed_today  = (future_goal_amount - current_savings_future_value) / ((1 + annual_rate) ** time_period)
        if lumpsum_needed_today < 0:
            lumpsum_needed_today = 0
        # Achievable: SIP required < 30% of the inflation-adjusted monthly goal spend (realistic heuristic)
        reasonable_monthly = future_goal_amount / max(time_period * 12, 1)
        result = {"future_goal_amount": future_goal_amount, "required_sip": required_sip,
                  "total_investment": current_savings + (required_sip * months),
                  "achievable": required_sip <= (reasonable_monthly * 0.30) or required_sip <= 0,
                  "current_savings_future_value": current_savings_future_value,
                  "lumpsum_needed_today": lumpsum_needed_today}
    return render_template("goal_sip_calculator.html", result=result,
        goal_amount=goal_amount, current_savings=current_savings,
        time_period=time_period, expected_return=expected_return,
        inflation_rate=inflation_rate, goal_type=goal_type)


# ================= XIRR CALCULATOR =================

def _xirr(cashflows):
    """cashflows: list of (date, signed_amount). Returns annualized rate (decimal) or None."""
    if not cashflows or len(cashflows) < 2:
        return None
    cf = sorted(cashflows, key=lambda x: x[0])
    d0 = cf[0][0]
    if not (any(a < 0 for _, a in cf) and any(a > 0 for _, a in cf)):
        return None

    def npv(rate):
        if rate <= -1:
            return float("inf")
        s = 0.0
        for d, a in cf:
            t = (d - d0).days / 365.0
            s += a / ((1 + rate) ** t)
        return s

    def dnpv(rate):
        s = 0.0
        for d, a in cf:
            t = (d - d0).days / 365.0
            if t == 0:
                continue
            s -= t * a / ((1 + rate) ** (t + 1))
        return s

    # Newton-Raphson
    r = 0.1
    for _ in range(100):
        v = npv(r)
        if abs(v) < 1e-6:
            return r
        dv = dnpv(r)
        if dv == 0:
            break
        r_new = r - v / dv
        if r_new <= -0.9999:
            r_new = -0.9999
        if abs(r_new - r) < 1e-9:
            return r_new
        r = r_new

    # Bisection fallback
    lo, hi = -0.9999, 10.0
    try:
        v_lo = npv(lo)
    except Exception:
        return None
    for _ in range(200):
        mid = (lo + hi) / 2
        v_mid = npv(mid)
        if abs(v_mid) < 1e-4:
            return mid
        if v_lo * v_mid < 0:
            hi = mid
        else:
            lo = mid
            v_lo = v_mid
    return (lo + hi) / 2


@app.route("/calculator/xirr", methods=["GET", "POST"])
def xirr_calculator():
    if "user_id" not in session:
        return redirect(url_for("login"))

    result = error = None
    cashflows_in = []

    # ---- GET prefill (e.g. from AI Goal Planner) ----
    # Supported query params:
    #   ?monthly=10000&months=36&value=500000[&start=YYYY-MM-DD]
    # Builds a monthly SIP series + one final "current value" row.
    if request.method == "GET" and request.args:
        try:
            q_monthly = request.args.get("monthly", type=float)
            q_months  = request.args.get("months",  type=int)
            q_value   = request.args.get("value",   type=float)
            q_start   = request.args.get("start")
            if q_monthly and q_months and q_value and q_monthly > 0 and q_months > 0 and q_value > 0:
                if q_months > 240:
                    q_months = 240  # safety cap at 20 yrs
                try:
                    start_dt = datetime.strptime(q_start, "%Y-%m-%d").date() if q_start else None
                except ValueError:
                    start_dt = None
                if start_dt is None:
                    # Default: months back from today, rounded to 1st of month
                    today = datetime.today().date()
                    # Step back q_months months
                    y = today.year
                    m = today.month - q_months
                    while m <= 0:
                        m += 12
                        y -= 1
                    start_dt = datetime(y, m, 1).date()
                rows = []
                for i in range(q_months):
                    yy = start_dt.year + (start_dt.month - 1 + i) // 12
                    mm = (start_dt.month - 1 + i) % 12 + 1
                    d_i = datetime(yy, mm, min(start_dt.day, 28)).date()
                    rows.append({"date": d_i.isoformat(),
                                 "amount": str(int(q_monthly)),
                                 "type": "invest"})
                # Final current-value row = today
                today = datetime.today().date()
                rows.append({"date": today.isoformat(),
                             "amount": str(int(q_value)),
                             "type": "redeem"})
                cashflows_in = rows
        except Exception:
            pass  # silent — fall through to empty form

    if request.method == "POST":
        dates = request.form.getlist("cf_date[]")
        amts  = request.form.getlist("cf_amount[]")
        types = request.form.getlist("cf_type[]")

        parsed = []
        for d, a, t in zip(dates, amts, types):
            d_s     = (d or "").strip()
            a_raw   = (a or "").replace(",", "").strip()
            t_s     = (t or "invest").strip().lower()
            if not d_s or not a_raw:
                continue
            try:
                dt = datetime.strptime(d_s, "%Y-%m-%d").date()
                amt = float(a_raw)
            except ValueError:
                continue
            if amt <= 0:
                continue
            signed = -amt if t_s == "invest" else amt
            parsed.append({"date": dt, "amount": signed, "type": t_s, "abs": amt})

        # echo back for re-render
        cashflows_in = [
            {"date": (d or "").strip(),
             "amount": (a or "").replace(",", "").strip(),
             "type": (t or "invest").strip()}
            for d, a, t in zip(dates, amts, types)
        ]

        if len(parsed) < 2:
            error = "Please add at least 2 cashflows (1 investment + 1 redemption / current value)."
        else:
            invested = sum(p["abs"] for p in parsed if p["amount"] < 0)
            received = sum(p["abs"] for p in parsed if p["amount"] > 0)
            if invested <= 0 or received <= 0:
                error = "Needs at least one Investment and at least one Redemption / Current Value."
            else:
                rate = _xirr([(p["date"], p["amount"]) for p in parsed])
                if rate is None:
                    error = "Could not compute XIRR — please check dates and amounts."
                else:
                    ds    = [p["date"] for p in parsed]
                    days  = (max(ds) - min(ds)).days
                    years = days / 365.0 if days > 0 else 0
                    abs_return = ((received - invested) / invested) * 100 if invested > 0 else 0
                    sorted_rows = sorted(
                        [{"date": p["date"].isoformat(), "amount": p["abs"],
                          "type": p["type"], "signed": p["amount"]} for p in parsed],
                        key=lambda x: x["date"]
                    )
                    result = {
                        "xirr": rate * 100,
                        "total_invested": invested,
                        "total_received": received,
                        "net_gain": received - invested,
                        "abs_return": abs_return,
                        "years": years,
                        "days": days,
                        "cashflows": sorted_rows,
                    }

    return render_template("xirr_calculator.html",
                           result=result, error=error, cashflows_in=cashflows_in)


# ================= REGRET CALCULATOR =================

@app.route("/calculator/regret", methods=["GET", "POST"])
def regret_calculator():
    if "user_id" not in session:
        return redirect(url_for("login"))

    result = monthly_sip = exp_return = time_period = delay_months = error = None

    if request.method == "POST":
        try:
            monthly_sip  = float((request.form.get("monthly_sip") or "0").replace(",", ""))
            exp_return   = float(request.form.get("exp_return"))
            time_period  = int(request.form.get("time_period"))
            delay_months = int(request.form.get("delay_months"))
        except (TypeError, ValueError):
            error = "Please fill in all fields with valid numbers."
            return render_template("regret_calculator.html", result=None, error=error,
                monthly_sip=None, exp_return=None, time_period=None, delay_months=None)

        if monthly_sip <= 0:
            error = "Monthly SIP amount must be greater than zero."
            return render_template("regret_calculator.html", result=None, error=error,
                monthly_sip=monthly_sip, exp_return=exp_return,
                time_period=time_period, delay_months=delay_months)

        if delay_months >= time_period * 12:
            error = (f"Delay ({delay_months} months) must be less than "
                     f"the investment horizon ({time_period * 12} months).")
            return render_template("regret_calculator.html", result=None, error=error,
                monthly_sip=monthly_sip, exp_return=exp_return,
                time_period=time_period, delay_months=delay_months)

        def _sip_fv(pmt, annual_rate, years):
            """Standard SIP future value (annuity-due)."""
            n = int(round(years * 12))
            if n <= 0:
                return 0.0
            m = annual_rate / 12 / 100
            if m == 0:
                return pmt * n
            return pmt * (((1 + m) ** n - 1) / m) * (1 + m)

        on_time_corpus  = _sip_fv(monthly_sip, exp_return, time_period)
        effective_years = time_period - (delay_months / 12)
        delayed_corpus  = _sip_fv(monthly_sip, exp_return, effective_years) if effective_years > 0 else 0.0
        cost_of_delay   = on_time_corpus - delayed_corpus
        wealth_lost_pct = round((cost_of_delay / on_time_corpus) * 100, 1) if on_time_corpus > 0 else 0
        monthly_cost    = round(cost_of_delay / delay_months, 2) if delay_months > 0 else 0

        # What-if: starting 1yr / 2yr earlier (extra corpus gained)
        whatif_1yr = _sip_fv(monthly_sip, exp_return, time_period + 1)
        whatif_2yr = _sip_fv(monthly_sip, exp_return, time_period + 2)

        lost_pct   = min(100, max(0, round((cost_of_delay / on_time_corpus) * 100, 1) if on_time_corpus > 0 else 0))
        gained_pct = 100 - lost_pct

        insight_text = (
            f"By investing ₹{int(monthly_sip):,}/month for {time_period} years at "
            f"{exp_return}% p.a., a delay of {delay_months} months "
            f"({delay_months // 12} yr {delay_months % 12} mo) "
            f"costs you ₹{int(cost_of_delay):,} — "
            f"that's {wealth_lost_pct}% of your potential wealth. "
            f"Each month of delay drains approximately ₹{int(monthly_cost):,} from your future."
        )

        result = {
            "on_time_corpus":  round(on_time_corpus, 2),
            "delayed_corpus":  round(delayed_corpus, 2),
            "cost_of_delay":   round(cost_of_delay, 2),
            "wealth_lost_pct": wealth_lost_pct,
            "monthly_cost":    monthly_cost,
            "whatif_1yr":      round(whatif_1yr, 2),
            "whatif_2yr":      round(whatif_2yr, 2),
            "lost_pct":        lost_pct,
            "gained_pct":      gained_pct,
            "insight_text":    insight_text,
        }

    return render_template("regret_calculator.html", result=result, error=error,
        monthly_sip=monthly_sip, exp_return=exp_return,
        time_period=time_period, delay_months=delay_months)


# ================= SETTINGS =================

@app.route("/settings")
def settings():
    if "user_id" not in session:
        return redirect(url_for("login"))
    conn = get_db_connection()
    user = conn.execute(
        "SELECT name, email, currency_format, theme, autosave FROM users WHERE id = ?",
        (session["user_id"],)
    ).fetchone()
    conn.close()
    return render_template("settings.html",
        username=user["name"] if user else "",
        email=user["email"] if user else "",
        currency_format=user["currency_format"] if user and user["currency_format"] else "indian",
        theme=user["theme"] if user and user["theme"] else "light",
        autosave=bool(user["autosave"]) if user else False)


@app.route("/settings/profile", methods=["POST"])
def update_profile():
    if "user_id" not in session:
        return jsonify({"success": False, "message": "Not logged in"})
    username = request.form.get("username")
    email    = request.form.get("email")
    try:
        conn     = get_db_connection()
        existing = conn.execute(
            "SELECT id FROM users WHERE email = ? AND id != ?",
            (email, session["user_id"])
        ).fetchone()
        if existing:
            conn.close()
            return jsonify({"success": False, "message": "Email already registered"})
        conn.execute("UPDATE users SET name = ?, email = ? WHERE id = ?",
                     (username, email, session["user_id"]))
        conn.commit()
        conn.close()
        session["user_name"] = username
        return jsonify({"success": True, "message": "Profile updated successfully!"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Error: {str(e)}"})


@app.route("/settings/password", methods=["POST"])
def update_password():
    if "user_id" not in session:
        return jsonify({"success": False, "message": "Not logged in"})
    current_password = request.form.get("current_password")
    new_password     = request.form.get("new_password")
    try:
        conn = get_db_connection()
        user = conn.execute("SELECT password FROM users WHERE id = ?",
                            (session["user_id"],)).fetchone()
        if not user:
            conn.close()
            return jsonify({"success": False, "message": "User not found"})
        if not check_password_hash(user["password"], current_password):
            conn.close()
            return jsonify({"success": False, "message": "Current password is incorrect"})
        conn.execute("UPDATE users SET password = ? WHERE id = ?",
                     (generate_password_hash(new_password), session["user_id"]))
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": "Password updated successfully!"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Error: {str(e)}"})


@app.route("/settings/preferences", methods=["POST"])
def update_preferences():
    if "user_id" not in session:
        return jsonify({"success": False, "message": "Not logged in"})
    currency_format = request.form.get("currency_format", "indian")
    theme           = request.form.get("theme", "light")
    autosave        = 1 if request.form.get("autosave", "0") == "1" else 0
    try:
        conn = get_db_connection()
        conn.execute(
            "UPDATE users SET currency_format = ?, theme = ?, autosave = ? WHERE id = ?",
            (currency_format, theme, autosave, session["user_id"])
        )
        conn.commit()
        conn.close()
        session["currency_format"] = currency_format
        session["theme"]           = theme
        session["autosave"]        = bool(autosave)
        session.modified           = True
        return jsonify({"success": True, "message": "Preferences saved successfully!"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Error: {str(e)}"})


@app.route("/settings/clear-data", methods=["POST"])
def clear_data():
    if "user_id" not in session:
        return jsonify({"success": False, "message": "Not logged in"})
    try:
        conn = get_db_connection()
        conn.execute("DELETE FROM portfolio_analyses WHERE user_id = ?", (session["user_id"],))
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": "All portfolio data cleared successfully!"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Error: {str(e)}"})


@app.route("/settings/delete-account", methods=["POST"])
def delete_account():
    if "user_id" not in session:
        return jsonify({"success": False, "message": "Not logged in"})
    try:
        conn = get_db_connection()
        uid  = session["user_id"]
        conn.execute("DELETE FROM portfolio_analyses WHERE user_id = ?", (uid,))
        conn.execute("DELETE FROM password_reset_tokens WHERE user_id = ?", (uid,))  # ← Bug fix
        conn.execute("DELETE FROM clients WHERE advisor_id = ?", (uid,))
        conn.execute("DELETE FROM users WHERE id = ?", (uid,))
        conn.commit()
        conn.close()
        session.clear()
        return jsonify({"success": True, "message": "Account deleted successfully. Goodbye!"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Error: {str(e)}"})


# ================= ADMIN PANEL =================

def admin_required(f):
    """Decorator: only allow admin users"""
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        conn = get_db_connection()
        user = conn.execute("SELECT is_admin FROM users WHERE id = ?", (session["user_id"],)).fetchone()
        conn.close()
        if not user or not user["is_admin"]:
            return render_template("error.html",
                error_title="Access Denied",
                error_message="You don't have permission to access the admin panel.",
                back_url=url_for("dashboard")), 403
        return f(*args, **kwargs)
    return decorated


@app.route("/admin/setup")
def admin_setup():
    """One-time route to make the first registered user an admin"""
    conn = get_db_connection()
    # Check if any admin already exists
    existing_admin = conn.execute("SELECT id FROM users WHERE is_admin = 1").fetchone()
    if existing_admin:
        conn.close()
        return "<h2>✅ Admin already exists! This route is disabled.</h2>"
    # Make the first registered user (lowest ID) an admin
    first_user = conn.execute("SELECT id, name, email FROM users ORDER BY id LIMIT 1").fetchone()
    if not first_user:
        conn.close()
        return "<h2>❌ No users found. Please register first!</h2>"
    conn.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (first_user["id"],))
    conn.commit()
    conn.close()
    return f"<h2>✅ Success! {first_user['name']} ({first_user['email']}) is now Admin!</h2><p><a href='/admin'>Go to Admin Panel</a></p>"


@app.route("/admin")
@admin_required
def admin_dashboard():
    conn = get_db_connection()
    # Stats
    total_users     = conn.execute("SELECT COUNT(*) as c FROM users WHERE is_admin = 0").fetchone()["c"]
    total_analyses  = conn.execute("SELECT COUNT(*) as c FROM portfolio_analyses").fetchone()["c"]
    total_clients   = conn.execute("SELECT COUNT(*) as c FROM clients").fetchone()["c"]
    blocked_users   = conn.execute("SELECT COUNT(*) as c FROM users WHERE is_blocked = 1").fetchone()["c"]
    # Recent users
    users = conn.execute("""
        SELECT id, name, email, created_at, is_blocked, is_admin,
               (SELECT COUNT(*) FROM portfolio_analyses WHERE user_id = users.id) as analysis_count
        FROM users ORDER BY created_at DESC LIMIT 50
    """).fetchall()
    # Recent analyses
    recent_analyses = conn.execute("""
        SELECT pa.id, pa.client_name, pa.current_total, pa.revised_total,
               pa.overall_rating, pa.created_at, u.name as advisor_name
        FROM portfolio_analyses pa
        JOIN users u ON pa.user_id = u.id
        ORDER BY pa.created_at DESC LIMIT 20
    """).fetchall()
    conn.close()
    return render_template("admin_dashboard.html",
        total_users=total_users,
        total_analyses=total_analyses,
        total_clients=total_clients,
        blocked_users=blocked_users,
        users=users,
        recent_analyses=recent_analyses
    )


@app.route("/admin/block/<int:user_id>", methods=["POST"])
@admin_required
def admin_block_user(user_id):
    conn = get_db_connection()
    user = conn.execute("SELECT is_blocked, is_admin FROM users WHERE id = ?", (user_id,)).fetchone()
    if user and not user["is_admin"]:
        new_status = 0 if user["is_blocked"] else 1
        conn.execute("UPDATE users SET is_blocked = ? WHERE id = ?", (new_status, user_id))
        conn.commit()
    conn.close()
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/delete-user/<int:user_id>", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    conn = get_db_connection()
    user = conn.execute("SELECT is_admin FROM users WHERE id = ?", (user_id,)).fetchone()
    if user and not user["is_admin"]:
        conn.execute("DELETE FROM portfolio_analyses WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM password_reset_tokens WHERE user_id = ?", (user_id,))
        conn.execute("DELETE FROM clients WHERE advisor_id = ?", (user_id,))
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
    conn.close()
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/delete-analysis/<int:analysis_id>", methods=["POST"])
@admin_required
def admin_delete_analysis(analysis_id):
    conn = get_db_connection()
    conn.execute("DELETE FROM portfolio_analyses WHERE id = ?", (analysis_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/make-admin/<int:user_id>", methods=["POST"])
@admin_required
def admin_make_admin(user_id):
    conn = get_db_connection()
    conn.execute("UPDATE users SET is_admin = 1 WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("admin_dashboard"))


# ================= RUN =================

# ================= AI GOAL PLANNER =================

GOAL_PLANNER_SYSTEM_PROMPT = """You are an expert Indian financial advisor AI inside M3 Portfolio — a tool used by Mutual Fund Distributors.

CRITICAL RULES — READ FIRST:
1. Return ONLY raw HTML. No markdown. No asterisks (**). No plain text paragraphs before the HTML.
2. Start your response DIRECTLY with a <div> tag. Nothing before it.
3. Never write "Intent Detection", "Auto-Fill", "Step 1", "Step 2" etc. in the response.
4. All numbers in Indian format — lakhs, crores. Use ₹ symbol.
5. Always calculate real numbers — never say "X" or placeholder values.

CALCULATION RULES:
- SIP Future Value = P × [((1 + r/12)^(n×12) - 1) / (r/12)] × (1 + r/12)  where r = annual rate, n = years
- Lumpsum Future Value = P × (1 + r)^n
- Monthly SIP needed = Target / [((1 + r/12)^(n×12) - 1) / (r/12) × (1 + r/12)]
- Inflation adjusted target = Target × (1 + inflation)^years
- Default return rate = 12% p.a. if not given
- Default inflation = 6% p.a. if not given

ALWAYS OUTPUT IN THIS EXACT HTML FORMAT — nothing else:

<div class="ai-section">
<div class="section-title">🎯 Goal Summary</div>
<ul>
<li><strong>Goal:</strong> [what user wants]</li>
<li><strong>Target Amount:</strong> ₹[amount in lakhs/crores]</li>
<li><strong>Time Horizon:</strong> [X] years</li>
<li><strong>Inflation-adjusted Target:</strong> ₹[calculated amount]</li>
</ul>
</div>

<div class="stats-row">
<div class="stat-pill"><span class="sval">₹[calculated]</span><span class="slbl">Monthly SIP Needed</span></div>
<div class="stat-pill"><span class="sval">₹[calculated]</span><span class="slbl">Total Invested</span></div>
<div class="stat-pill"><span class="sval">₹[calculated]</span><span class="slbl">Future Value</span></div>
<div class="stat-pill"><span class="sval">₹[calculated]</span><span class="slbl">Wealth Gained</span></div>
</div>

<div class="ai-section green">
<div class="section-title">✅ Recommended Plan</div>
<ul>
<li><strong>Expected Return:</strong> [X]% p.a.</li>
<li><strong>Inflation Assumed:</strong> [X]% p.a.</li>
<li><strong>Fund Category:</strong> [e.g. Flexi Cap / Large Cap / Hybrid]</li>
<li><strong>Start With:</strong> ₹[amount] SIP per month</li>
</ul>
</div>

<div class="ai-section amber">
<div class="section-title">⚠️ Key Risks & Watch-outs</div>
<ul>
[3 specific, practical risk points for this goal]
</ul>
</div>

<div class="ai-section purple">
<div class="section-title">💡 Smart Tips</div>
<ul>
[3 actionable tips — tax saving, step-up SIP, ELSS etc. relevant to this goal]
</ul>
</div>"""


@app.route("/ai/goal-planner")
def ai_goal_planner():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("ai_goal_planner.html")


@app.route("/ai/goal-planner", methods=["POST"])
def ai_goal_planner_api():
    if "user_id" not in session:
        return jsonify({"error": "Not logged in"}), 401

    data = request.get_json()
    if not data or not data.get("goal"):
        return jsonify({"error": "Please enter a financial goal."}), 400

    goal = data["goal"].strip()
    if len(goal) > 500:
        return jsonify({"error": "Goal description too long. Please keep it under 500 characters."}), 400

    GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
    if not GROQ_API_KEY:
        return jsonify({"error": "GROQ_API_KEY not set. Add it in Render Environment Variables."}), 500

    try:
        import json as json_lib
        import http.client
        import ssl

        payload = json_lib.dumps({
            "model": "llama-3.3-70b-versatile",
            "messages": [
                {"role": "system", "content": GOAL_PLANNER_SYSTEM_PROMPT},
                {"role": "user", "content": goal}
            ],
            "max_tokens": 1500,
            "temperature": 0.7
        })

        context = ssl.create_default_context()
        conn = http.client.HTTPSConnection("api.groq.com", context=context, timeout=60)
        conn.request(
            "POST",
            "/openai/v1/chat/completions",
            body=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "User-Agent": "python-httpx/0.24.0"
            }
        )
        resp = conn.getresponse()
        body = resp.read().decode("utf-8")
        conn.close()

        if resp.status != 200:
            print(f"Groq error {resp.status}: {body}")
            return jsonify({"error": f"AI API error {resp.status}: {body[:300]}"}), 500

        result = json_lib.loads(body)
        ai_text = result["choices"][0]["message"]["content"]
        return jsonify({"result": ai_text})

    except Exception as e:
        print(f"AI Goal Planner error: {type(e).__name__}: {e}")
        return jsonify({"error": f"Error: {type(e).__name__}: {str(e)[:200]}"}), 500


# ================= AI WEALTH ASSISTANT =================

def get_market_data():
    """Fetch live market data — Nifty 50, Sensex, top FD rates, inflation"""
    import http.client, ssl, json as jlib
    market = {
        "nifty": None, "nifty_change": None,
        "sensex": None, "sensex_change": None,
        "fd_rate": "7.0-7.5", "inflation": "5.1",
        "repo_rate": "6.5"
    }
    try:
        ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection("query1.finance.yahoo.com", context=ctx, timeout=8)
        conn.request("GET", "/v8/finance/chart/%5ENSEI?interval=1d&range=1d",
                     headers={"User-Agent": "Mozilla/5.0"})
        resp = conn.getresponse()
        if resp.status == 200:
            data = jlib.loads(resp.read().decode())
            meta = data["chart"]["result"][0]["meta"]
            price = round(meta["regularMarketPrice"], 2)
            prev  = round(meta["previousClose"], 2)
            chg   = round(((price - prev) / prev) * 100, 2)
            market["nifty"] = f"{price:,.2f}"
            market["nifty_change"] = f"{chg:+.2f}%"
        conn.close()
    except Exception as e:
        print(f"Market data fetch error: {e}")
    return market


def build_wealth_assistant_prompt():
    """Build system prompt with live market data injected"""
    m = get_market_data()

    nifty_str = f"Nifty 50: {m['nifty']} ({m['nifty_change']})" if m["nifty"] else "Nifty 50: data unavailable"

    return f"""You are an expert AI Wealth Assistant built for professional Wealth Advisors and Mutual Fund Distributors (MFDs) in India. You assist advisors during client meetings and portfolio reviews.

━━━━━━━━━━━━━━━━━━━━━━━━
LIVE MARKET SNAPSHOT (Today)
━━━━━━━━━━━━━━━━━━━━━━━━
• {nifty_str}
• RBI Repo Rate: {m['repo_rate']}%
• Top Bank FD Rates: {m['fd_rate']}% p.a.
• Current CPI Inflation: ~{m['inflation']}%

━━━━━━━━━━━━━━━━━━━━━━━━
CLIENT PROFILE THIS FIRM SERVES
━━━━━━━━━━━━━━━━━━━━━━━━
• HNI clients (₹50L+ portfolio) and Mass Affluent (₹10L-₹50L)
• Primary instruments: Mutual Funds (Equity + Hybrid)
• Fund categories used: Large Cap, Flexi Cap, Mid & Small Cap, Hybrid/Balanced Advantage, ELSS, Debt/Liquid

━━━━━━━━━━━━━━━━━━━━━━━━
FIRM'S INVESTMENT PHILOSOPHY
━━━━━━━━━━━━━━━━━━━━━━━━
• Goal-based investing — every rupee should have a purpose
• Long-term wealth creation through equity MFs (5+ year horizon)
• Tax-efficient investing — prefer ELSS over PPF for 80C, LTCG harvesting
• Balanced growth and safety based on client risk profile
• FD and Traditional Insurance (LIC endowment/money-back): STRONGLY DISCOURAGE
  → Always recommend MF alternatives (Debt MF / Balanced Advantage / ELSS)
  → Show the client the opportunity cost with real numbers

━━━━━━━━━━━━━━━━━━━━━━━━
KNOWLEDGE BASE — STANDARD ASSUMPTIONS
━━━━━━━━━━━━━━━━━━━━━━━━
Returns (unless client specifies):
• Large Cap MF: 12% p.a.
• Flexi/Multi Cap MF: 13% p.a.
• Mid & Small Cap MF: 15% p.a.
• Hybrid/BAF: 10% p.a.
• Debt MF / Liquid: 7% p.a.
• FD (current top rate): {m['fd_rate']}% p.a.
• PPF: 7.1% p.a.
• EPF: 8.25% p.a.
• NPS (equity): 10% p.a.
• Gold (long term): 8% p.a.
• Real Estate: 7-8% p.a.
• Inflation assumption: 6% p.a.

━━━━━━━━━━━━━━━━━━━━━━━━
ASSET ALLOCATION GUIDELINES (by risk profile)
━━━━━━━━━━━━━━━━━━━━━━━━
• Conservative:  20% Equity | 60% Debt | 15% Hybrid | 5% Gold
• Moderate:      50% Equity | 30% Debt | 15% Hybrid | 5% Gold
• Aggressive:    70% Equity | 15% Debt | 10% Hybrid | 5% Gold
• Very Aggressive: 85% Equity | 5% Debt | 5% Hybrid | 5% Gold

━━━━━━━━━━━━━━━━━━━━━━━━
COMMON CLIENT OBJECTIONS — HOW TO HANDLE
━━━━━━━━━━━━━━━━━━━━━━━━
"FD is safe":
→ FD returns ({m['fd_rate']}%) are BELOW inflation ({m['inflation']}%) — real return is negative
→ Show: ₹10L in FD for 10 years = ~₹19L. Same in equity MF = ~₹31L
→ Suggest: Debt MF for safety + better post-tax returns

"Market is too volatile / I am scared":
→ SIP averages out volatility (Rupee Cost Averaging)
→ In last 20 years, Nifty 50 has never given negative returns on any 7-year SIP
→ Suggest: Start with Balanced Advantage Fund first, then shift to pure equity

"LIC policy gives guaranteed returns + insurance":
→ Separation principle: Keep insurance and investment separate
→ Term insurance (₹1Cr cover for ₹10-15K/year) + MF SIP is far superior
→ Show IRR of typical LIC endowment = 4-5% only

"I will invest when markets fall":
→ Time in market > Timing the market
→ Show data: Missing top 10 days in a year reduces returns by 50%

━━━━━━━━━━━━━━━━━━━━━━━━
TAX KNOWLEDGE BASE
━━━━━━━━━━━━━━━━━━━━━━━━
• LTCG on Equity MF: 12.5% above ₹1.25L gain per year (held > 1 year)
• STCG on Equity MF: 20% (held < 1 year)
• LTCG on Debt MF: As per income tax slab (held any duration)
• ELSS lock-in: 3 years, 80C deduction up to ₹1.5L
• STP strategy: Lumpsum → Liquid Fund → STP to Equity (reduces timing risk)
• Tax harvesting: Book LTCG up to ₹1.25L every year tax-free, reinvest

━━━━━━━━━━━━━━━━━━━━━━━━
RESPONSE FORMAT RULES
━━━━━━━━━━━━━━━━━━━━━━━━
For calculations/goals:
<div class="ai-section"><div class="section-title">🎯 Title</div>content</div>
<div class="stats-row">
<div class="stat-pill"><span class="sval">₹X</span><span class="slbl">Label</span></div>
</div>

For warnings/issues:
<div class="ai-section amber"><div class="section-title">⚠️ Title</div>content</div>

For recommendations:
<div class="ai-section green"><div class="section-title">✅ Title</div>content</div>

For insights:
<div class="ai-section purple"><div class="section-title">💡 Title</div>content</div>

━━━━━━━━━━━━━━━━━━━━━━━━
TONE & STYLE
━━━━━━━━━━━━━━━━━━━━━━━━
• Speak like a senior advisor to a junior advisor — practical, direct, no fluff
• Always use Indian number system (lakhs, crores)
• Always show real calculated numbers — never be vague
• End every response with 1-2 specific action steps the advisor can take
• For tax advice: add "consult CA for specific tax planning"
• Keep responses concise — advisor is in a client meeting, no time for essays"""


@app.route("/ai/wealth-assistant")
def ai_wealth_assistant():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("ai_wealth_assistant.html")


@app.route("/ai/wealth-assistant", methods=["POST"])
def ai_wealth_assistant_api():
    if "user_id" not in session:
        return jsonify({"error": "Not logged in"}), 401

    data = request.get_json()
    if not data or not data.get("message"):
        return jsonify({"error": "Please enter a message."}), 400

    message = data["message"].strip()
    history = data.get("history", [])

    if len(message) > 1000:
        return jsonify({"error": "Message too long. Please keep it under 1000 characters."}), 400

    GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
    if not GROQ_API_KEY:
        return jsonify({"error": "GROQ_API_KEY not set. Add it in Render Environment Variables."}), 500

    try:
        import json as json_lib
        import http.client
        import ssl

        # Build messages with conversation history
        messages = [{"role": "system", "content": build_wealth_assistant_prompt()}]
        # Add last 8 messages for context
        for h in history[-8:]:
            if h.get("role") in ("user", "assistant") and h.get("content"):
                messages.append({"role": h["role"], "content": str(h["content"])[:500]})

        payload = json_lib.dumps({
            "model": "llama-3.3-70b-versatile",
            "messages": messages,
            "max_tokens": 1500,
            "temperature": 0.7
        })

        context = ssl.create_default_context()
        conn = http.client.HTTPSConnection("api.groq.com", context=context, timeout=60)
        conn.request(
            "POST",
            "/openai/v1/chat/completions",
            body=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "User-Agent": "python-httpx/0.24.0"
            }
        )
        resp = conn.getresponse()
        body = resp.read().decode("utf-8")
        conn.close()

        if resp.status != 200:
            print(f"Groq error {resp.status}: {body}")
            return jsonify({"error": f"AI API error {resp.status}: {body[:300]}"}), 500

        result = json_lib.loads(body)
        ai_text = result["choices"][0]["message"]["content"]
        return jsonify({"result": ai_text})

    except Exception as e:
        print(f"AI Wealth Assistant error: {type(e).__name__}: {e}")
        return jsonify({"error": f"Error: {type(e).__name__}: {str(e)[:200]}"}), 500


# ================= WEALTH OPTIMIZER CALCULATOR =================

@app.route("/calculator/wealth-optimizer", methods=["GET"])
def wealth_optimizer():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("wealth_optimizer.html")


# ================= RISK PROFILE QUIZ =================

@app.route("/risk-quiz")
def risk_quiz():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return render_template("risk_quiz.html")


@app.route("/risk-quiz/result", methods=["POST"])
def risk_quiz_result():
    if "user_id" not in session:
        return redirect(url_for("login"))

    answers = {}
    total_score = 0
    for i in range(1, 16):
        val = request.form.get(f"q{i}")
        if val:
            answers[f"q{i}"] = int(val)
            total_score += int(val)

    # Determine profile (max score = 50)
    if total_score <= 15:
        profile     = "Conservative"
        emoji       = "🟢"
        color       = "#4CAF50"
        equity_pct  = 40
        debt_pct    = 60
        description = "You prefer capital protection over high returns. Stable, low-risk investments suit you best."
    elif total_score <= 30:
        profile     = "Moderate"
        emoji       = "🟡"
        color       = "#FF9800"
        equity_pct  = 60
        debt_pct    = 40
        description = "You seek a balance between growth and stability. A mix of equity and debt works well for you."
    elif total_score <= 40:
        profile     = "Aggressive"
        emoji       = "🟠"
        color       = "#FF5722"
        equity_pct  = 80
        debt_pct    = 20
        description = "You are comfortable with market volatility in pursuit of higher long-term returns."
    else:
        profile     = "Very Aggressive"
        emoji       = "🔴"
        color       = "#f44336"
        equity_pct  = 100
        debt_pct    = 0
        description = "You seek maximum growth and can tolerate significant short-term volatility."

    return render_template("risk_quiz_result.html",
        score=total_score,
        profile=profile,
        emoji=emoji,
        color=color,
        equity_pct=equity_pct,
        debt_pct=debt_pct,
        description=description,
        max_score=50
    )


if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug_mode)
