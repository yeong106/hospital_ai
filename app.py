from __future__ import annotations

import os
import re
import sqlite3
import smtplib
import ssl
import json
from email.message import EmailMessage
from functools import wraps
from datetime import datetime, timedelta, date
from typing import Any, Dict, List, Tuple, Optional

from flask import Flask, jsonify, render_template, request, redirect, url_for, session, g
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# ----------------------------
# Auth + SQLite config
# ----------------------------
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE_DIR, "app.db"))

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
)

def _utc_now_iso() -> str:
    return datetime.utcnow().isoformat(timespec="seconds")

def _json_dumps(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))

def _json_loads(s: Any, default: Any) -> Any:
    try:
        if s is None:
            return default
        if isinstance(s, (dict, list)):
            return s
        return json.loads(str(s))
    except Exception:
        return default

def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        # sqlite FK desteği
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db

@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()

# ----------------------------
# DB init + tiny migrations
# ----------------------------
def init_db():
    db = get_db()

    # users
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,              -- login email (değiştirmiyoruz)
            password_hash TEXT NOT NULL,
            name TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        )
        """
    )
    db.commit()

    # migration: display_email kolonu yoksa ekle (UI'de gösterilecek email)
    try:
        db.execute("ALTER TABLE users ADD COLUMN display_email TEXT")
        db.commit()
    except sqlite3.OperationalError:
        pass

    # condition weights
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS condition_weights (
            key TEXT PRIMARY KEY,
            weight INTEGER NOT NULL
        )
        """
    )
    db.commit()

    # default weights yükle (tablo boşsa)
    cnt = db.execute("SELECT COUNT(*) AS c FROM condition_weights").fetchone()["c"]
    if cnt == 0:
        defaults = {
            "acil": 50,
            "kalp": 35,
            "kanser": 45,
            "diyabet": 18,
            "hipertansiyon": 14,
            "astim": 12,
            "gebelik": 20,
            "psikiyatri": 10,
            "genel": 5,
        }
        db.executemany(
            "INSERT INTO condition_weights (key, weight) VALUES (?, ?)",
            [(k, int(v)) for k, v in defaults.items()],
        )
        db.commit()

    # ----------------------------
    # NEW: patients (hasta master)
    # ----------------------------
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS patients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            email TEXT DEFAULT '',
            phone TEXT DEFAULT '',
            national_id TEXT UNIQUE,         -- TC / pasaport vs (opsiyonel ama unique)
            birth_year INTEGER,              -- opsiyonel
            conditions_json TEXT NOT NULL DEFAULT '[]', -- kronik durumlar
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )
    db.commit()

    # indexler (aranabilir alanlar)
    try:
        db.execute("CREATE INDEX IF NOT EXISTS idx_patients_name ON patients(full_name)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_patients_phone ON patients(phone)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_patients_email ON patients(email)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_patients_nid ON patients(national_id)")
        db.commit()
    except Exception:
        pass

    # ----------------------------
    # NEW: appointments (randevu kayıtları)
    # ----------------------------
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS appointments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL,
            complaint TEXT DEFAULT '',
            severity REAL NOT NULL DEFAULT 0,
            conditions_json TEXT NOT NULL DEFAULT '[]',   -- bu randevuya özel durumlar
            age_override INTEGER,                         -- birth_year yoksa kullanılabilir
            status TEXT NOT NULL DEFAULT 'PENDING',       -- PENDING/SCHEDULED/NO_SHOW/DONE/CANCELED
            scheduled_slot TEXT,                          -- "YYYY-mm-dd HH:MM–HH:MM"
            score REAL,
            score_breakdown_json TEXT,
            email_preview TEXT,
            email_sent INTEGER NOT NULL DEFAULT 0,
            email_status TEXT DEFAULT 'preview_only',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(patient_id) REFERENCES patients(id) ON DELETE CASCADE
        )
        """
    )
    db.commit()

    try:
        db.execute("CREATE INDEX IF NOT EXISTS idx_appt_patient ON appointments(patient_id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_appt_status ON appointments(status)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_appt_created ON appointments(created_at)")
        db.commit()
    except Exception:
        pass

# ----------------------------
# helpers
# ----------------------------
def _valid_email(email: str) -> bool:
    email = (email or "").strip().lower()
    if len(email) < 5 or len(email) > 254:
        return False
    return re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email) is not None

def _as_int(x: Any, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return default

def _as_float(x: Any, default: float = 0.0) -> float:
    try:
        return float(x)
    except Exception:
        return default

def _clamp(v: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, v))

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("uid"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "login required"}), 401
            return redirect(url_for("login_page"))
        return fn(*args, **kwargs)
    return wrapper

# ----------------------------
# Weights (DB-backed)
# ----------------------------
def load_condition_weights(db: sqlite3.Connection) -> Dict[str, int]:
    rows = db.execute("SELECT key, weight FROM condition_weights").fetchall()
    out = {}
    for r in rows:
        out[str(r["key"]).strip().lower()] = int(r["weight"])
    if "genel" not in out:
        out["genel"] = 5
    return out

# ----------------------------
# AI-ish scoring + explainability
# ----------------------------
def compute_score_with_breakdown(p: Dict[str, Any], weights: Dict[str, int]) -> Tuple[float, Dict[str, Any]]:
    age = _as_int(p.get("age"), 0)
    missed = _as_int(p.get("missed"), 0)
    severity = _as_float(p.get("severity"), 0.0)
    conditions = p.get("conditions") or []
    if not isinstance(conditions, list):
        conditions = []

    cond_items = []
    cond_score = 0
    for c in conditions:
        key = str(c or "").strip().lower()
        w = int(weights.get(key, 0))
        cond_score += w
        if key:
            cond_items.append({"condition": key, "weight": w})

    age_score = min(age, 90) * 0.25
    sev_score = severity * 6.0
    missed_penalty = missed * 12.0

    total = cond_score + age_score + sev_score - missed_penalty
    total = round(total, 2)

    explanation = []
    if cond_items:
        top = sorted(cond_items, key=lambda x: x["weight"], reverse=True)[:3]
        explanation.append(
            "Kronik/önemli koşullar puanı etkiledi: "
            + ", ".join([f"{t['condition']}(+{t['weight']})" for t in top])
        )
    else:
        explanation.append("Koşul bilgisi yoksa 'genel' değerlendirme uygulanır.")

    if severity >= 7:
        explanation.append("Şiddet (severity) yüksek olduğu için öncelik arttı.")
    if age >= 60:
        explanation.append("Yaş yüksek olduğu için öncelik arttı.")
    if missed >= 2:
        explanation.append("2+ kez gelmeme (no-show) olduğu için ciddi ceza uygulandı.")
    elif missed == 1:
        explanation.append("1 kez gelmeme olduğu için ceza uygulandı.")

    breakdown = {
        "cond_score": cond_score,
        "age_score": round(age_score, 2),
        "severity_score": round(sev_score, 2),
        "missed_penalty": round(missed_penalty, 2),
        "total": total,
        "top_reasons": explanation,
        "conditions_used": cond_items,
    }
    return total, breakdown

def normalize_patient(p: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "name": str(p.get("name", "")).strip(),
        "email": str(p.get("email", "")).strip(),
        "age": _as_int(p.get("age"), 0),
        "missed": _as_int(p.get("missed"), 0),
        "severity": _as_float(p.get("severity"), 0.0),
        "conditions": [
            str(c).strip().lower()
            for c in (p.get("conditions") or [])
            if str(c).strip()
        ],
    }

def parse_slot_settings(s: Dict[str, Any], patient_count: int) -> Dict[str, Any]:
    start_date = str((s or {}).get("start_date") or "").strip()
    start_time = str((s or {}).get("start_time") or "09:00").strip()
    duration_min = _clamp(_as_int((s or {}).get("duration_min"), 20), 5, 240)
    slot_count = _as_int((s or {}).get("slot_count"), max(patient_count, 1))
    slot_count = _clamp(slot_count, 1, 200)

    if not start_date:
        d = date.today().isoformat()
    else:
        try:
            datetime.strptime(start_date, "%Y-%m-%d")
            d = start_date
        except Exception:
            d = date.today().isoformat()

    try:
        datetime.strptime(start_time, "%H:%M")
        t = start_time
    except Exception:
        t = "09:00"

    start_dt = datetime.strptime(f"{d} {t}", "%Y-%m-%d %H:%M")
    return {
        "start_dt": start_dt,
        "duration_min": duration_min,
        "slot_count": slot_count,
        "start_date": d,
        "start_time": t,
    }

def build_slots(start_dt: datetime, duration_min: int, slot_count: int) -> List[str]:
    out = []
    cur = start_dt
    for _ in range(slot_count):
        end = cur + timedelta(minutes=duration_min)
        out.append(f"{cur.strftime('%Y-%m-%d %H:%M')}–{end.strftime('%H:%M')}")
        cur = end
    return out

def make_email_preview(p: Dict[str, Any], score: float, assigned_slot: str) -> str:
    name = p.get("name") or "Hasta"
    email = p.get("email") or "(email yok)"
    missed = _as_int(p.get("missed"), 0)
    conditions = p.get("conditions") or []
    cond_txt = ", ".join([str(c).upper() for c in conditions]) if conditions else "GENEL"

    warning = ""
    if missed >= 2:
        warning = (
            "\n⚠ UYARI: 2+ kez randevuya gelmeme tespit edildi. "
            "Bu durum öncelik puanını ciddi şekilde düşürür ve ek onay gerekebilir.\n"
        )

    return (
        f"Kime: {email}\n"
        f"Konu: Randevu Bilgilendirme\n\n"
        f"Merhaba {name},\n\n"
        f"AI öncelik skorunuz: {score}\n"
        f"Durum/Koşullar: {cond_txt}\n"
        f"Atanan randevu slotu: {assigned_slot}\n"
        f"{warning}\n"
        f"Lütfen randevu saatinden 10 dakika önce hastanede olun.\n"
        f"İyi günler dileriz.\n"
        f"- Hastane Randevu Sistemi"
    )

# ----------------------------
# REAL email sending (SMTP) - opsiyonel
# ----------------------------
def smtp_configured() -> bool:
    return bool(os.environ.get("SMTP_HOST") and os.environ.get("SMTP_USER") and os.environ.get("SMTP_PASS"))

def send_email_smtp(to_email: str, subject: str, body: str) -> Tuple[bool, str]:
    """
    SMTP ayarı yoksa False döner. Varsa mail atmayı dener.
    Env:
      SMTP_HOST, SMTP_PORT(opsiyonel), SMTP_USER, SMTP_PASS, SMTP_USE_TLS(1/0), SMTP_FROM(opsiyonel)
    """
    to_email = (to_email or "").strip()
    if not to_email:
        return False, "no recipient"
    if not smtp_configured():
        return False, "smtp not configured"

    host = os.environ.get("SMTP_HOST")
    port = int(os.environ.get("SMTP_PORT", "587"))
    user = os.environ.get("SMTP_USER")
    pw = os.environ.get("SMTP_PASS")
    use_tls = os.environ.get("SMTP_USE_TLS", "1").strip() != "0"
    from_email = os.environ.get("SMTP_FROM", user)

    msg = EmailMessage()
    msg["From"] = from_email
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)

    try:
        if use_tls:
            context = ssl.create_default_context()
            with smtplib.SMTP(host, port, timeout=12) as server:
                server.ehlo()
                server.starttls(context=context)
                server.login(user, pw)
                server.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=12) as server:
                server.login(user, pw)
                server.send_message(msg)

        return True, "sent"
    except Exception as e:
        return False, f"send failed: {e}"

# ----------------------------
# NEW: Patient + Appointment DB helpers
# ----------------------------
def _compute_age_from_birth_year(birth_year: Any) -> int:
    by = _as_int(birth_year, 0)
    if by <= 0:
        return 0
    try:
        this_year = date.today().year
        age = this_year - by
        return _clamp(age, 0, 120)
    except Exception:
        return 0

def _get_patient_missed_count(db: sqlite3.Connection, patient_id: int) -> int:
    row = db.execute(
        "SELECT COUNT(*) AS c FROM appointments WHERE patient_id = ? AND status = 'NO_SHOW'",
        (patient_id,),
    ).fetchone()
    return int(row["c"]) if row else 0

def _merge_conditions(primary: List[str], fallback: List[str]) -> List[str]:
    # primary doluysa onu kullan; değilse fallback
    p = [str(x).strip().lower() for x in (primary or []) if str(x).strip()]
    if p:
        return p
    f = [str(x).strip().lower() for x in (fallback or []) if str(x).strip()]
    return f

# ----------------------------
# Pages
# ----------------------------
@app.get("/")
@login_required
def index():
    return render_template("index.html")

@app.get("/login")
def login_page():
    return render_template("login.html")

@app.get("/register")
def register_page():
    return render_template("register.html")

# ----------------------------
# NEW PAGE: Patient file (hasta dosyası)
# ----------------------------
@app.get("/patients/<int:pid>")
@login_required
def patient_file_page(pid: int):
    # Frontend bu sayfada /api/patients/<pid>/file endpoint'ini çağırıp
    # patient + visits (appointments) listesini ekrana basacak.
    return render_template("patient_file.html", patient_id=pid)

# ----------------------------
# Auth API
# ----------------------------
@app.get("/api/auth/me")
def auth_me():
    uid = session.get("uid")
    if not uid:
        return jsonify({"logged_in": False})

    db = get_db()
    row = db.execute("SELECT name, email, display_email FROM users WHERE id = ?", (uid,)).fetchone()
    if row:
        name = row["name"] or ""
        login_email = row["email"] or ""
        display_email = row["display_email"] or ""
        effective_email = display_email.strip() or login_email.strip()
    else:
        name = session.get("name", "") or ""
        effective_email = session.get("email", "") or ""

    session["name"] = name
    session["email"] = session.get("email", "")
    session["display_email"] = effective_email

    return jsonify(
        {
            "logged_in": True,
            "user": {
                "id": uid,
                "email": effective_email,
                "login_email": session.get("email", ""),
                "name": name,
            },
        }
    )

@app.post("/api/auth/register")
def auth_register():
    payload = request.get_json(silent=True) or {}
    email = str(payload.get("email") or "").strip().lower()
    password = str(payload.get("password") or "")
    name = str(payload.get("name") or "").strip()

    if not _valid_email(email):
        return jsonify({"error": "invalid email"}), 400
    if len(password) < 6:
        return jsonify({"error": "password must be at least 6 chars"}), 400
    if len(name) > 60:
        return jsonify({"error": "name too long"}), 400

    pw_hash = generate_password_hash(password)

    db = get_db()
    try:
        cur = db.execute(
            """
            INSERT INTO users (email, password_hash, name, created_at, display_email)
            VALUES (?, ?, ?, ?, ?)
            """,
            (email, pw_hash, name, _utc_now_iso(), email),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "email already registered"}), 409

    uid = cur.lastrowid
    session["uid"] = uid
    session["email"] = email
    session["name"] = name
    session["display_email"] = email

    return jsonify({"ok": True, "user": {"id": uid, "email": email, "name": name}})

@app.post("/api/auth/login")
def auth_login():
    payload = request.get_json(silent=True) or {}
    email = str(payload.get("email") or "").strip().lower()
    password = str(payload.get("password") or "")

    if not _valid_email(email) or not password:
        return jsonify({"error": "invalid credentials"}), 400

    db = get_db()
    row = db.execute(
        "SELECT id, email, password_hash, name, display_email FROM users WHERE email = ?",
        (email,),
    ).fetchone()

    if not row or not check_password_hash(row["password_hash"], password):
        return jsonify({"error": "invalid credentials"}), 401

    session["uid"] = int(row["id"])
    session["email"] = row["email"] or ""
    session["name"] = row["name"] or ""
    disp = (row["display_email"] or "").strip() or (row["email"] or "").strip()
    session["display_email"] = disp

    return jsonify({"ok": True, "user": {"id": session["uid"], "email": disp, "name": session["name"]}})

@app.post("/api/auth/logout")
def auth_logout():
    session.clear()
    return jsonify({"ok": True})

@app.post("/api/auth/profile")
@login_required
def auth_profile_update():
    payload = request.get_json(silent=True) or {}
    name = str(payload.get("name") or "").strip()
    email = str(payload.get("email") or "").strip()

    if not name:
        return jsonify({"error": "name required"}), 400
    if len(name) > 60:
        return jsonify({"error": "name too long"}), 400

    if email and not _valid_email(email):
        return jsonify({"error": "invalid email"}), 400
    if len(email) > 254:
        return jsonify({"error": "email too long"}), 400

    uid = int(session["uid"])
    db = get_db()

    disp_email = email.strip() if email else None

    db.execute(
        "UPDATE users SET name = ?, display_email = ? WHERE id = ?",
        (name, disp_email, uid),
    )
    db.commit()

    row = db.execute("SELECT email, name, display_email FROM users WHERE id = ?", (uid,)).fetchone()
    effective_email = (row["display_email"] or "").strip() or (row["email"] or "").strip()

    session["name"] = row["name"] or ""
    session["display_email"] = effective_email

    return jsonify({"ok": True, "user": {"id": uid, "name": session["name"], "email": effective_email}})

# ----------------------------
# AI weights API (kalibrasyon)
# ----------------------------
@app.get("/api/ai/weights")
@login_required
def get_weights():
    db = get_db()
    w = load_condition_weights(db)
    return jsonify({"ok": True, "weights": w})

@app.post("/api/ai/weights")
@login_required
def update_weights():
    payload = request.get_json(silent=True) or {}
    weights = payload.get("weights")
    if not isinstance(weights, dict) or not weights:
        return jsonify({"error": "weights must be a non-empty object"}), 400

    cleaned = []
    for k, v in weights.items():
        key = str(k or "").strip().lower()
        if not key:
            continue
        val = _as_int(v, None)
        if val is None:
            continue
        val = _clamp(val, 0, 200)
        cleaned.append((key, val))

    if not cleaned:
        return jsonify({"error": "no valid weights"}), 400

    db = get_db()
    db.executemany(
        "INSERT INTO condition_weights(key, weight) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET weight=excluded.weight",
        cleaned,
    )
    db.commit()

    return jsonify({"ok": True, "weights": load_condition_weights(db)})

# ----------------------------
# NEW: Patients API
# ----------------------------
@app.get("/api/patients/search")
@login_required
def patients_search():
    q = (request.args.get("q") or "").strip()
    if len(q) < 2:
        return jsonify([])

    like = f"%{q}%"
    db = get_db()
    rows = db.execute(
        """
        SELECT id, full_name, email, phone, national_id, birth_year, conditions_json
        FROM patients
        WHERE full_name LIKE ?
           OR email LIKE ?
           OR phone LIKE ?
           OR national_id LIKE ?
        ORDER BY full_name ASC
        LIMIT 10
        """,
        (like, like, like, like),
    ).fetchall()

    out = []
    for r in rows:
        out.append(
            {
                "id": int(r["id"]),
                "full_name": r["full_name"] or "",
                "email": r["email"] or "",
                "phone": r["phone"] or "",
                "national_id": r["national_id"] or "",
                "birth_year": _as_int(r["birth_year"], 0) or None,
                "conditions": _json_loads(r["conditions_json"], []),
            }
        )
    return jsonify(out)

@app.get("/api/patients/<int:pid>")
@login_required
def patients_get(pid: int):
    db = get_db()
    r = db.execute(
        """
        SELECT id, full_name, email, phone, national_id, birth_year, conditions_json, created_at, updated_at
        FROM patients
        WHERE id = ?
        """,
        (pid,),
    ).fetchone()
    if not r:
        return jsonify({"error": "patient not found"}), 404

    return jsonify(
        {
            "ok": True,
            "patient": {
                "id": int(r["id"]),
                "full_name": r["full_name"] or "",
                "email": r["email"] or "",
                "phone": r["phone"] or "",
                "national_id": r["national_id"] or "",
                "birth_year": _as_int(r["birth_year"], 0) or None,
                "conditions": _json_loads(r["conditions_json"], []),
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
            },
        }
    )

# ----------------------------
# NEW: Patient File API (patient + all visits/appointments history)
# ----------------------------
@app.get("/api/patients/<int:pid>/file")
@login_required
def patient_file_api(pid: int):
    db = get_db()

    p = db.execute(
        """
        SELECT id, full_name, email, phone, national_id, birth_year, conditions_json, created_at, updated_at
        FROM patients
        WHERE id = ?
        """,
        (pid,),
    ).fetchone()
    if not p:
        return jsonify({"error": "patient not found"}), 404

    visits = db.execute(
        """
        SELECT
          id, patient_id, complaint, severity, conditions_json, age_override,
          status, scheduled_slot, score, score_breakdown_json,
          email_sent, email_status,
          created_at, updated_at
        FROM appointments
        WHERE patient_id = ?
        ORDER BY created_at DESC
        LIMIT 500
        """,
        (pid,),
    ).fetchall()

    missed = _get_patient_missed_count(db, pid)

    out_visits = []
    for v in visits:
        out_visits.append(
            {
                "id": int(v["id"]),
                "patient_id": int(v["patient_id"]),
                "complaint": v["complaint"] or "",
                "severity": float(v["severity"] or 0.0),
                "conditions": _json_loads(v["conditions_json"], []),
                "age_override": _as_int(v["age_override"], 0) or None,
                "status": v["status"] or "PENDING",
                "scheduled_slot": v["scheduled_slot"] or "",
                "score": float(v["score"]) if v["score"] is not None else None,
                "score_breakdown": _json_loads(v["score_breakdown_json"], {}),
                "email_sent": bool(int(v["email_sent"] or 0)),
                "email_status": v["email_status"] or "preview_only",
                "created_at": v["created_at"],
                "updated_at": v["updated_at"],
            }
        )

    return jsonify(
        {
            "ok": True,
            "patient": {
                "id": int(p["id"]),
                "full_name": p["full_name"] or "",
                "email": p["email"] or "",
                "phone": p["phone"] or "",
                "national_id": p["national_id"] or "",
                "birth_year": _as_int(p["birth_year"], 0) or None,
                "conditions": _json_loads(p["conditions_json"], []),
                "missed_total": missed,
                "created_at": p["created_at"],
                "updated_at": p["updated_at"],
            },
            "visits": out_visits,
        }
    )

@app.post("/api/patients")
@login_required
def patients_create():
    payload = request.get_json(silent=True) or {}

    full_name = str(payload.get("full_name") or "").strip()
    if not full_name:
        return jsonify({"error": "full_name required"}), 400

    email = str(payload.get("email") or "").strip()
    phone = str(payload.get("phone") or "").strip()
    national_id = str(payload.get("national_id") or "").strip() or None
    birth_year = payload.get("birth_year")
    birth_year = _as_int(birth_year, 0) if birth_year is not None else 0
    birth_year = birth_year if birth_year > 0 else None

    conditions = payload.get("conditions") or []
    if not isinstance(conditions, list):
        conditions = []
    conditions = [str(c).strip().lower() for c in conditions if str(c).strip()]

    now = _utc_now_iso()
    db = get_db()

    # TC varsa ve zaten kayıtlıysa: aynı hastayı döndür (duplicate açma)
    if national_id:
        existing = db.execute(
            "SELECT id FROM patients WHERE national_id = ?",
            (national_id,),
        ).fetchone()
        if existing:
            return jsonify({"ok": True, "patient_id": int(existing["id"]), "note": "patient already exists"})

    try:
        cur = db.execute(
            """
            INSERT INTO patients (full_name, email, phone, national_id, birth_year, conditions_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (full_name, email, phone, national_id, birth_year, _json_dumps(conditions), now, now),
        )
        db.commit()
    except sqlite3.IntegrityError as e:
        # unique national_id vs.
        return jsonify({"error": f"insert failed: {e}"}), 409

    return jsonify({"ok": True, "patient_id": cur.lastrowid})

# ----------------------------
# NEW: Appointments API (hasta tekrar tekrar gelebilir)
# ----------------------------
@app.post("/api/appointments")
@login_required
def appointments_create():
    payload = request.get_json(silent=True) or {}
    patient_id = _as_int(payload.get("patient_id"), 0)
    if patient_id <= 0:
        return jsonify({"error": "patient_id required"}), 400

    complaint = str(payload.get("complaint") or "").strip()
    severity = _as_float(payload.get("severity"), 0.0)
    severity = max(0.0, min(10.0, severity))

    age_override = payload.get("age")
    age_override = _as_int(age_override, 0) if age_override is not None else 0
    age_override = age_override if age_override > 0 else None

    conditions = payload.get("conditions") or []
    if not isinstance(conditions, list):
        conditions = []
    conditions = [str(c).strip().lower() for c in conditions if str(c).strip()]

    db = get_db()
    p = db.execute("SELECT id FROM patients WHERE id = ?", (patient_id,)).fetchone()
    if not p:
        return jsonify({"error": "patient not found"}), 404

    now = _utc_now_iso()
    cur = db.execute(
        """
        INSERT INTO appointments
          (patient_id, complaint, severity, conditions_json, age_override, status, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, 'PENDING', ?, ?)
        """,
        (patient_id, complaint, severity, _json_dumps(conditions), age_override, now, now),
    )
    db.commit()
    return jsonify({"ok": True, "appointment_id": cur.lastrowid})

@app.get("/api/appointments")
@login_required
def appointments_list():
    status = str(request.args.get("status") or "").strip().upper()
    allowed = {"PENDING", "SCHEDULED", "NO_SHOW", "DONE", "CANCELED"}
    where = ""
    params: List[Any] = []
    if status and status in allowed:
        where = "WHERE a.status = ?"
        params.append(status)

    db = get_db()
    rows = db.execute(
        f"""
        SELECT
          a.id, a.patient_id, a.complaint, a.severity, a.conditions_json, a.age_override,
          a.status, a.scheduled_slot, a.score, a.created_at, a.updated_at,
          p.full_name, p.email, p.phone, p.national_id, p.birth_year, p.conditions_json AS p_conditions
        FROM appointments a
        JOIN patients p ON p.id = a.patient_id
        {where}
        ORDER BY a.created_at DESC
        LIMIT 200
        """,
        tuple(params),
    ).fetchall()

    out = []
    for r in rows:
        out.append(
            {
                "id": int(r["id"]),
                "patient_id": int(r["patient_id"]),
                "patient": {
                    "full_name": r["full_name"] or "",
                    "email": r["email"] or "",
                    "phone": r["phone"] or "",
                    "national_id": r["national_id"] or "",
                    "birth_year": _as_int(r["birth_year"], 0) or None,
                },
                "complaint": r["complaint"] or "",
                "severity": float(r["severity"] or 0.0),
                "conditions": _json_loads(r["conditions_json"], []),
                "status": r["status"],
                "scheduled_slot": r["scheduled_slot"] or "",
                "score": float(r["score"]) if r["score"] is not None else None,
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
            }
        )

    return jsonify({"ok": True, "appointments": out})

# ----------------------------
# Existing demo/schedule API
# ----------------------------
@app.get("/api/demo")
@login_required
def demo():
    patients = [
        {"name": "Ayşe Yılmaz", "email": "ayse@mail.com", "age": 68, "missed": 0, "severity": 8, "conditions": ["kalp", "hipertansiyon"]},
        {"name": "Mehmet Kaya", "email": "mehmet@gmail.com", "age": 41, "missed": 2, "severity": 6, "conditions": ["diyabet"]},
        {"name": "Zeynep Demir", "email": "zeynep@outlook.com", "age": 33, "missed": 0, "severity": 9, "conditions": ["acil"]},
        {"name": "Ali Çelik", "email": "ali@domain.com", "age": 57, "missed": 1, "severity": 5, "conditions": ["astim"]},
        {"name": "Elif Arslan", "email": "elif@mail.com", "age": 29, "missed": 0, "severity": 4, "conditions": ["gebelik"]},
        {"name": "Can Öztürk", "email": "can@mail.com", "age": 52, "missed": 3, "severity": 7, "conditions": ["kanser"]},
    ]
    return jsonify({"patients": patients})

@app.post("/api/schedule")
@login_required
def schedule():
    payload = request.get_json(silent=True) or {}

    db = get_db()
    weights = load_condition_weights(db)

    # ✅ NEW: appointment_ids gelirse DB’den randevuları çekip sırala + slot ata
    appointment_ids = payload.get("appointment_ids")
    use_db_appointments = isinstance(appointment_ids, list) and len(appointment_ids) > 0

    # slot ayarları
    slot_settings = payload.get("slot_settings") or {}

    # send mail?
    send_emails = bool(payload.get("send_emails", False))

    # ----------------------------
    # MODE A: DB appointments ile schedule
    # ----------------------------
    if use_db_appointments:
        appt_ids: List[int] = []
        for x in appointment_ids:
            ix = _as_int(x, 0)
            if ix > 0:
                appt_ids.append(ix)

        if not appt_ids:
            return jsonify({"error": "appointment_ids invalid"}), 400

        placeholders = ",".join(["?"] * len(appt_ids))
        rows = db.execute(
            f"""
            SELECT
              a.id AS appt_id, a.patient_id, a.complaint, a.severity, a.conditions_json, a.age_override, a.status,
              p.full_name, p.email, p.birth_year, p.conditions_json AS p_conditions
            FROM appointments a
            JOIN patients p ON p.id = a.patient_id
            WHERE a.id IN ({placeholders})
            """,
            tuple(appt_ids),
        ).fetchall()

        if not rows:
            return jsonify({"error": "no appointments found"}), 404

        # PENDING olmayanları da koyabilir; ama schedule ederken yine slot atayacağız
        # patient dict listesi çıkar
        appts: List[Dict[str, Any]] = []
        for r in rows:
            patient_id = int(r["patient_id"])
            missed = _get_patient_missed_count(db, patient_id)

            appt_conditions = _json_loads(r["conditions_json"], [])
            patient_conditions = _json_loads(r["p_conditions"], [])

            age = 0
            if r["age_override"] is not None:
                age = _as_int(r["age_override"], 0)
            else:
                age = _compute_age_from_birth_year(r["birth_year"])

            p = {
                "name": r["full_name"] or "",
                "email": r["email"] or "",
                "age": age,
                "missed": missed,
                "severity": float(r["severity"] or 0.0),
                "conditions": _merge_conditions(appt_conditions, patient_conditions),
            }

            appts.append(
                {
                    "appointment_id": int(r["appt_id"]),
                    "patient_id": patient_id,
                    "patient": p,
                    "complaint": r["complaint"] or "",
                }
            )

        settings = parse_slot_settings(slot_settings, len(appts))
        slots = build_slots(settings["start_dt"], settings["duration_min"], settings["slot_count"])

        ranked = []
        for it in appts:
            p = it["patient"]
            score, breakdown = compute_score_with_breakdown(p, weights)
            ranked.append({"it": it, "score": score, "breakdown": breakdown})

        ranked.sort(key=lambda x: (-x["score"], -x["it"]["patient"]["age"], x["it"]["patient"]["missed"]))

        results = []
        now = _utc_now_iso()

        for i, item in enumerate(ranked):
            it = item["it"]
            p = it["patient"]
            score = item["score"]
            breakdown = item["breakdown"]

            assigned_slot = slots[i] if i < len(slots) else "Slot yok"
            email_preview = make_email_preview(p, score, assigned_slot)

            mail_sent = False
            mail_status = "preview_only"
            if send_emails:
                ok, msg = send_email_smtp(
                    p.get("email", ""),
                    "Randevu Bilgilendirme",
                    email_preview,
                )
                mail_sent = ok
                mail_status = msg

            # ✅ DB update: appointment schedule sonucu yaz
            db.execute(
                """
                UPDATE appointments
                SET
                  scheduled_slot = ?,
                  status = ?,
                  score = ?,
                  score_breakdown_json = ?,
                  email_preview = ?,
                  email_sent = ?,
                  email_status = ?,
                  updated_at = ?
                WHERE id = ?
                """,
                (
                    assigned_slot,
                    ("SCHEDULED" if assigned_slot != "Slot yok" else "PENDING"),
                    score,
                    _json_dumps(breakdown),
                    email_preview,
                    (1 if mail_sent else 0),
                    mail_status,
                    now,
                    int(it["appointment_id"]),
                ),
            )

            results.append(
                {
                    "appointment_id": int(it["appointment_id"]),
                    "patient_id": int(it["patient_id"]),
                    "name": p["name"],
                    "email": p["email"],
                    "age": p["age"],
                    "missed": p["missed"],
                    "severity": p["severity"],
                    "conditions": p["conditions"],
                    "score": score,
                    "score_breakdown": breakdown,
                    "assigned_slot": assigned_slot,
                    "email_preview": email_preview,
                    "email_sent": mail_sent,
                    "email_status": mail_status,
                    "needs_manual_confirm": (p["missed"] >= 2),
                    "missed_level": ("severe" if p["missed"] >= 2 else ("warn" if p["missed"] == 1 else "ok")),
                    "missed_label": (
                        "⚠ 2+ kez gelmedi" if p["missed"] >= 2 else ("1 kez gelmedi" if p["missed"] == 1 else "Düzenli")
                    ),
                    "missed_penalty": (p["missed"] * 12.0),
                }
            )

        db.commit()

        return jsonify(
            {
                "slot_settings_used": {
                    "start_date": settings["start_date"],
                    "start_time": settings["start_time"],
                    "duration_min": settings["duration_min"],
                    "slot_count": settings["slot_count"],
                },
                "ai": {
                    "type": "rule-based scoring + calibrated weights",
                    "weights": weights,
                    "email_mode": ("smtp" if (send_emails and smtp_configured()) else "preview"),
                },
                "mode": "db_appointments",
                "results": results,
            }
        )

    # ----------------------------
    # MODE B: Eski davranış (payload.patients ile)
    # ----------------------------
    raw_patients = payload.get("patients") or []
    if not isinstance(raw_patients, list):
        return jsonify({"error": "patients must be a list"}), 400

    patients = [normalize_patient(p) for p in raw_patients]
    patients = [p for p in patients if p["name"]]

    settings = parse_slot_settings(slot_settings, len(patients))
    slots = build_slots(settings["start_dt"], settings["duration_min"], settings["slot_count"])

    ranked = []
    for p in patients:
        score, breakdown = compute_score_with_breakdown(p, weights)
        ranked.append({"p": p, "score": score, "breakdown": breakdown})

    ranked.sort(key=lambda x: (-x["score"], -x["p"]["age"], x["p"]["missed"]))

    results = []
    for i, item in enumerate(ranked):
        p = item["p"]
        score = item["score"]
        breakdown = item["breakdown"]

        assigned_slot = slots[i] if i < len(slots) else "Slot yok"
        email_preview = make_email_preview(p, score, assigned_slot)

        mail_sent = False
        mail_status = "preview_only"
        if send_emails:
            ok, msg = send_email_smtp(
                p.get("email", ""),
                "Randevu Bilgilendirme",
                email_preview,
            )
            mail_sent = ok
            mail_status = msg

        results.append(
            {
                "name": p["name"],
                "email": p["email"],
                "age": p["age"],
                "missed": p["missed"],
                "severity": p["severity"],
                "conditions": p["conditions"],
                "score": score,
                "score_breakdown": breakdown,
                "assigned_slot": assigned_slot,
                "email_preview": email_preview,
                "email_sent": mail_sent,
                "email_status": mail_status,
                "needs_manual_confirm": (p["missed"] >= 2),
                "missed_level": ("severe" if p["missed"] >= 2 else ("warn" if p["missed"] == 1 else "ok")),
                "missed_label": (
                    "⚠ 2+ kez gelmedi" if p["missed"] >= 2 else ("1 kez gelmedi" if p["missed"] == 1 else "Düzenli")
                ),
                "missed_penalty": (p["missed"] * 12.0),
            }
        )

    return jsonify(
        {
            "slot_settings_used": {
                "start_date": settings["start_date"],
                "start_time": settings["start_time"],
                "duration_min": settings["duration_min"],
                "slot_count": settings["slot_count"],
            },
            "ai": {
                "type": "rule-based scoring + calibrated weights",
                "weights": weights,
                "email_mode": ("smtp" if (send_emails and smtp_configured()) else "preview"),
            },
            "mode": "payload_patients",
            "results": results,
        }
    )

if __name__ == "__main__":
    with app.app_context():
        init_db()

    port = int(os.environ.get("PORT", "5000"))
    app.run(debug=True, host="127.0.0.1", port=port)
