import sqlite3
import hashlib
import datetime
import os
from pathlib import Path

DB_PATH = "screensentry.db"

def get_connection():
    """Get database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_database():
    """Initialize database tables."""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Evidence table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            image_path TEXT NOT NULL,
            confidence REAL,
            severity TEXT DEFAULT 'Medium',
            status TEXT DEFAULT 'Pending',
            deleted INTEGER DEFAULT 0,
            hash TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Audit log table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Admin credentials table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS admin_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email_encrypted TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Add email_encrypted column if upgrading from old DB
    try:
        cursor.execute("ALTER TABLE admin_users ADD COLUMN email_encrypted TEXT")
    except Exception:
        pass
    
    # Login attempts table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            success INTEGER DEFAULT 0,
            ip_address TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # App settings table (key-value store)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    """)

    # Insert defaults if not present
    defaults = [
        ("conf_threshold",      "0.3"),
        ("confirm_frames",      "2"),
        ("email_alerts",        "1"),
        ("smtp_host",           "smtp.gmail.com"),
        ("smtp_port",           "587"),
        ("smtp_user",           ""),
        ("smtp_pass_enc",       ""),
        ("registered_ip",       ""),
        ("lockdown_pin_enabled","0"),
        ("lockdown_pin_enc",    ""),
    ]
    for k, v in defaults:
        cursor.execute("INSERT OR IGNORE INTO app_settings (key, value) VALUES (?,?)", (k, v))

    conn.commit()
    conn.close()

def compute_hash(data):
    """Compute SHA256 hash of data."""
    return hashlib.sha256(str(data).encode()).hexdigest()

# ─── Email encryption ─────────────────────────────────────────────────────────
def _get_fernet():
    from cryptography.fernet import Fernet
    key_file = ".email.key"
    if os.path.exists(key_file):
        with open(key_file, "rb") as f:
            key = f.read()
    else:
        key = Fernet.generate_key()
        with open(key_file, "wb") as f:
            f.write(key)
        # Hide the key file on Windows
        if os.name == 'nt':
            import ctypes
            ctypes.windll.kernel32.SetFileAttributesW(key_file, 2)
    return Fernet(key)

def encrypt_email(email):
    return _get_fernet().encrypt(email.encode()).decode()

def decrypt_email(encrypted):
    try:
        return _get_fernet().decrypt(encrypted.encode()).decode()
    except Exception:
        return None

# ─── Admin registration ───────────────────────────────────────────────────────
def admin_exists():
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("SELECT COUNT(*) as c FROM admin_users")
    count = cur.fetchone()['c']
    conn.close()
    return count > 0

def register_admin(username, password, email, ip_address=""):
    import bcrypt
    conn = get_connection()
    cur  = conn.cursor()
    pw_hash   = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    email_enc = encrypt_email(email)
    cur.execute(
        "INSERT INTO admin_users (username, password_hash, email_encrypted) VALUES (?,?,?)",
        (username, pw_hash, email_enc)
    )
    conn.commit()
    conn.close()
    set_setting("registered_ip", ip_address)
    log_audit("Admin Registered", f"Username: {username}, IP: {ip_address}")

def get_admin_email(username):
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("SELECT email_encrypted FROM admin_users WHERE username=?", (username,))
    row  = cur.fetchone()
    conn.close()
    if row and row['email_encrypted']:
        return decrypt_email(row['email_encrypted'])
    return None

def get_masked_email(username):
    """Return masked email like k*****@gmail.com"""
    email = get_admin_email(username)
    if not email:
        return None
    parts = email.split("@")
    if len(parts) != 2:
        return None
    name   = parts[0]
    domain = parts[1]
    masked = name[0] + "*" * (len(name) - 1)
    return f"{masked}@{domain}"

def add_evidence(image_path, confidence, severity='Medium'):
    """Add evidence record to database."""
    conn = get_connection()
    cursor = conn.cursor()
    
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    record_data = f"{timestamp}|{image_path}|{confidence}|{severity}"
    record_hash = compute_hash(record_data)
    
    cursor.execute("""
        INSERT INTO evidence (timestamp, image_path, confidence, severity, hash)
        VALUES (?, ?, ?, ?, ?)
    """, (timestamp, image_path, confidence, severity, record_hash))
    
    evidence_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    log_audit("Evidence Captured", f"Evidence ID: {evidence_id}, Path: {image_path}")
    return evidence_id

def get_all_evidence(include_deleted=False):
    """Get all evidence records."""
    conn = get_connection()
    cursor = conn.cursor()
    
    if include_deleted:
        cursor.execute("SELECT * FROM evidence ORDER BY timestamp DESC")
    else:
        cursor.execute("SELECT * FROM evidence WHERE deleted = 0 ORDER BY timestamp DESC")
    
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_deleted_evidence():
    """Get all deleted evidence (recycle bin)."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM evidence WHERE deleted = 1 ORDER BY timestamp DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def soft_delete_evidence(evidence_id):
    """Soft delete evidence (move to recycle bin)."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE evidence SET deleted = 1 WHERE id = ?", (evidence_id,))
    conn.commit()
    conn.close()
    log_audit("Evidence Deleted", f"Evidence ID: {evidence_id} moved to recycle bin")

def restore_evidence(evidence_id):
    """Restore evidence from recycle bin."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE evidence SET deleted = 0 WHERE id = ?", (evidence_id,))
    conn.commit()
    conn.close()
    log_audit("Evidence Restored", f"Evidence ID: {evidence_id} restored from recycle bin")

def permanent_delete_evidence(evidence_id):
    """Permanently delete evidence."""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Get image path before deleting
    cursor.execute("SELECT image_path FROM evidence WHERE id = ?", (evidence_id,))
    row = cursor.fetchone()
    if row:
        image_path = row['image_path']
        # Delete from database
        cursor.execute("DELETE FROM evidence WHERE id = ?", (evidence_id,))
        conn.commit()
        # Delete physical file
        if os.path.exists(image_path):
            os.remove(image_path)
        log_audit("Evidence Permanently Deleted", f"Evidence ID: {evidence_id}, Path: {image_path}")
    
    conn.close()

def update_evidence_status(evidence_id, status):
    """Update evidence status (Pending/Confirmed/False Alarm)."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE evidence SET status = ? WHERE id = ?", (status, evidence_id))
    conn.commit()
    conn.close()
    log_audit("Evidence Status Updated", f"Evidence ID: {evidence_id}, Status: {status}")

def log_audit(action, details=""):
    """Log admin action to audit trail."""
    conn = get_connection()
    cursor = conn.cursor()
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute("""
        INSERT INTO audit_log (timestamp, action, details)
        VALUES (?, ?, ?)
    """, (timestamp, action, details))
    conn.commit()
    conn.close()

def get_audit_logs(limit=100):
    """Get recent audit logs."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def verify_integrity():
    """Verify integrity of all evidence records."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, timestamp, image_path, confidence, severity, hash FROM evidence")
    rows = cursor.fetchall()
    
    tampered = []
    for row in rows:
        record_data = f"{row['timestamp']}|{row['image_path']}|{row['confidence']}|{row['severity']}"
        computed_hash = compute_hash(record_data)
        if computed_hash != row['hash']:
            tampered.append(row['id'])
    
    conn.close()
    
    if tampered:
        log_audit("Integrity Check Failed", f"Tampered evidence IDs: {tampered}")
    
    return tampered

def get_statistics():
    """Get evidence statistics for analytics."""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Total threats
    cursor.execute("SELECT COUNT(*) as total FROM evidence WHERE deleted = 0")
    total = cursor.fetchone()['total']
    
    # By status
    cursor.execute("SELECT status, COUNT(*) as count FROM evidence WHERE deleted = 0 GROUP BY status")
    by_status = {row['status']: row['count'] for row in cursor.fetchall()}
    
    # By severity
    cursor.execute("SELECT severity, COUNT(*) as count FROM evidence WHERE deleted = 0 GROUP BY severity")
    by_severity = {row['severity']: row['count'] for row in cursor.fetchall()}
    
    # By date (last 7 days)
    cursor.execute("""
        SELECT DATE(timestamp) as date, COUNT(*) as count 
        FROM evidence 
        WHERE deleted = 0 AND DATE(timestamp) >= DATE('now', '-7 days')
        GROUP BY DATE(timestamp)
        ORDER BY date
    """)
    by_date = [(row['date'], row['count']) for row in cursor.fetchall()]

    # By hour (last 24 hours) for timeline
    cursor.execute("""
        SELECT strftime('%H', timestamp) as hour, COUNT(*) as count
        FROM evidence
        WHERE deleted = 0 AND DATE(timestamp) = DATE('now')
        GROUP BY strftime('%H', timestamp)
        ORDER BY hour
    """)
    by_hour = [(row['hour'], row['count']) for row in cursor.fetchall()]

    # By day (last 30 days) for month view
    cursor.execute("""
        SELECT DATE(timestamp) as day, COUNT(*) as count
        FROM evidence
        WHERE deleted = 0 AND DATE(timestamp) >= DATE('now', '-29 days')
        GROUP BY DATE(timestamp)
        ORDER BY day
    """)
    by_month = [(row['day'], row['count']) for row in cursor.fetchall()]

    # Today's count
    cursor.execute("SELECT COUNT(*) as c FROM evidence WHERE deleted=0 AND DATE(timestamp)=DATE('now')")
    today = cursor.fetchone()['c']

    # Latest threat
    cursor.execute("SELECT timestamp, severity FROM evidence WHERE deleted=0 ORDER BY timestamp DESC LIMIT 1")
    row = cursor.fetchone()
    latest = dict(row) if row else None

    conn.close()
    
    return {
        'total': total,
        'today': today,
        'by_status': by_status,
        'by_severity': by_severity,
        'by_date': by_date,
        'by_hour': by_hour,
        'by_month': by_month,
        'latest': latest,
    }

def get_evidence_by_id(evidence_id):
    """Get single evidence record by ID."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

# Initialize database on import
if __name__ == "__main__":
    init_database()
    print("Database initialized successfully!")

# ─── Protection status (shared with main.py via file) ─────────────────────────
STATUS_FILE = ".protection_status"

def set_protection_status(enabled: bool):
    with open(STATUS_FILE, "w") as f:
        f.write("1" if enabled else "0")

def get_protection_status() -> bool:
    try:
        with open(STATUS_FILE, "r") as f:
            return f.read().strip() == "1"
    except Exception:
        return True  # default: assume active

# ─── App settings ─────────────────────────────────────────────────────────────
def get_setting(key, default=None):
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("SELECT value FROM app_settings WHERE key=?", (key,))
    row  = cur.fetchone()
    conn.close()
    return row['value'] if row else default

def set_setting(key, value):
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("INSERT OR REPLACE INTO app_settings (key, value) VALUES (?,?)", (key, str(value)))
    conn.commit()
    conn.close()

def get_detection_settings():
    return {
        "conf_threshold": float(get_setting("conf_threshold", "0.3")),
        "confirm_frames": int(get_setting("confirm_frames", "3")),
    }

def get_all_settings():
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("SELECT key, value FROM app_settings")
    rows = cur.fetchall()
    conn.close()
    return {row['key']: row['value'] for row in rows}

# ─── Email alerts ─────────────────────────────────────────────────────────────
def get_smtp_password():
    enc = get_setting("smtp_pass_enc", "")
    if not enc:
        return ""
    try:
        return _get_fernet().decrypt(enc.encode()).decode()
    except Exception:
        return ""

def set_smtp_password(plain):
    enc = _get_fernet().encrypt(plain.encode()).decode()
    set_setting("smtp_pass_enc", enc)

def get_lockdown_pin():
    """Return decrypted PIN or empty string."""
    enc = get_setting("lockdown_pin_enc", "")
    if not enc:
        return ""
    try:
        return _get_fernet().decrypt(enc.encode()).decode()
    except Exception:
        return ""

def set_lockdown_pin(plain):
    """Encrypt and store PIN."""
    enc = _get_fernet().encrypt(plain.encode()).decode()
    set_setting("lockdown_pin_enc", enc)

def is_lockdown_pin_enabled():
    return get_setting("lockdown_pin_enabled", "0") == "1"

def send_threat_email(image_path=None, confidence=0.0, severity="Medium"):
    """Send email alert to admin when a threat is detected."""
    if get_setting("email_alerts", "1") != "1":
        return

    smtp_host = get_setting("smtp_host", "smtp.gmail.com")
    smtp_port = int(get_setting("smtp_port", "587"))
    smtp_user = get_setting("smtp_user", "")
    smtp_pass = get_smtp_password()

    if not smtp_user or not smtp_pass:
        print("[Email] SMTP not configured — skipping alert.")
        return

    # Get admin email
    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("SELECT email_encrypted FROM admin_users LIMIT 1")
    row  = cur.fetchone()
    conn.close()
    if not row or not row['email_encrypted']:
        print("[Email] No admin email found.")
        return

    to_email = decrypt_email(row['email_encrypted'])
    if not to_email:
        return

    try:
        import smtplib
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        from email.mime.image import MIMEImage

        now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        msg = MIMEMultipart('related')
        msg['Subject'] = f"🚨 ScreenSentry Alert — {severity} Threat Detected"
        msg['From']    = smtp_user
        msg['To']      = to_email

        html = f"""
        <div style="font-family:Arial,sans-serif;background:#0a0a0f;color:#e8e8ff;padding:24px;border-radius:12px;">
          <h2 style="color:#ff3366;margin-bottom:4px;">🚨 Threat Detected</h2>
          <p style="color:#aaaacc;margin-bottom:20px;">ScreenSentry has detected a phone near your screen.</p>
          <table style="width:100%;border-collapse:collapse;">
            <tr><td style="padding:8px;color:#4a4a6a;width:140px;">Time</td>
                <td style="padding:8px;color:#e8e8ff;font-weight:bold;">{now}</td></tr>
            <tr><td style="padding:8px;color:#4a4a6a;">Severity</td>
                <td style="padding:8px;color:{'#ff3366' if severity=='High' else '#ff9500' if severity=='Medium' else '#00ff88'};font-weight:bold;">{severity}</td></tr>
            <tr><td style="padding:8px;color:#4a4a6a;">Confidence</td>
                <td style="padding:8px;color:#e8e8ff;font-weight:bold;">{confidence*100:.1f}%</td></tr>
          </table>
          {"<br><img src='cid:evidence_img' style='width:100%;border-radius:8px;margin-top:12px;'>" if image_path else ""}
          <p style="color:#4a4a6a;font-size:12px;margin-top:20px;">ScreenSentry — Document Leakage Prevention</p>
        </div>
        """

        msg.attach(MIMEText(html, 'html'))

        if image_path and os.path.exists(image_path):
            with open(image_path, 'rb') as f:
                img = MIMEImage(f.read())
                img.add_header('Content-ID', '<evidence_img>')
                img.add_header('Content-Disposition', 'inline', filename=os.path.basename(image_path))
                msg.attach(img)

        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, to_email, msg.as_string())

        print(f"[Email] Alert sent to {to_email[:3]}***")
        log_audit("Email Alert Sent", f"Severity: {severity}, Confidence: {confidence:.2f}")

    except Exception as e:
        print(f"[Email] Failed to send alert: {e}")

def send_login_alert(ip_address, attempt_number):
    """Send email alert when a failed login attempt is detected."""
    if get_setting("email_alerts", "1") != "1":
        return

    smtp_host = get_setting("smtp_host", "smtp.gmail.com")
    smtp_port = int(get_setting("smtp_port", "587"))
    smtp_user = get_setting("smtp_user", "")
    smtp_pass = get_smtp_password()

    if not smtp_user or not smtp_pass:
        return

    conn = get_connection()
    cur  = conn.cursor()
    cur.execute("SELECT email_encrypted FROM admin_users LIMIT 1")
    row  = cur.fetchone()
    conn.close()
    if not row or not row['email_encrypted']:
        return

    to_email = decrypt_email(row['email_encrypted'])
    if not to_email:
        return

    try:
        import smtplib
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText

        now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"⚠️ ScreenSentry — Failed Login Attempt #{attempt_number}"
        msg['From']    = smtp_user
        msg['To']      = to_email

        html = f"""
        <div style="font-family:Arial,sans-serif;background:#0a0a0f;color:#e8e8ff;padding:24px;border-radius:12px;">
          <h2 style="color:#ff9500;margin-bottom:4px;">⚠️ Failed Login Attempt</h2>
          <p style="color:#aaaacc;margin-bottom:20px;">Someone tried to access your ScreenSentry admin panel.</p>
          <table style="width:100%;border-collapse:collapse;">
            <tr><td style="padding:8px;color:#4a4a6a;width:160px;">Time</td>
                <td style="padding:8px;color:#e8e8ff;font-weight:bold;">{now}</td></tr>
            <tr><td style="padding:8px;color:#4a4a6a;">IP Address</td>
                <td style="padding:8px;color:#ff9500;font-weight:bold;font-family:monospace;">{ip_address}</td></tr>
            <tr><td style="padding:8px;color:#4a4a6a;">Attempt #</td>
                <td style="padding:8px;color:#{'ff3366' if attempt_number >= 3 else 'ff9500'};font-weight:bold;">{attempt_number}</td></tr>
          </table>
          <div style="margin-top:16px;padding:12px;background:#1a0a00;border-radius:8px;border-left:3px solid #ff9500;">
            <p style="color:#ff9500;font-size:13px;margin:0;">
              {'🔒 Account is now locked for 10 minutes.' if attempt_number >= 3 else 'If this was not you, someone may be trying to access your panel.'}
            </p>
          </div>
          <p style="color:#4a4a6a;font-size:12px;margin-top:20px;">ScreenSentry — Document Leakage Prevention</p>
        </div>
        """
        msg.attach(MIMEText(html, 'html'))

        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, to_email, msg.as_string())

        print(f"[Email] Login alert sent — attempt #{attempt_number} from {ip_address}")

    except Exception as e:
        print(f"[Email] Login alert failed: {e}")
