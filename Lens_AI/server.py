from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file
import bcrypt
import os
import io
import csv
import time
import threading
import zipfile
import datetime
import socket
import database

app = Flask(__name__)
app.secret_key = "screensentry_secret_2026"

MAX_ATTEMPTS    = 3
LOCKOUT_MINUTES = 10
failed_attempts = {}
lockout_until   = {}

# ─── Generate self-signed SSL cert ────────────────────────────────────────────
def generate_ssl_cert():
    """Generate a self-signed SSL certificate if not already present."""
    cert_file = "cert.pem"
    key_file  = "key.pem"
    if os.path.exists(cert_file) and os.path.exists(key_file):
        return cert_file, key_file
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime as dt
        import ipaddress

        # Generate private key
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Get local IP
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)

        # Build certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"ScreenSentry"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"ScreenSentry"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(dt.datetime.utcnow())
            .not_valid_after(dt.datetime.utcnow() + dt.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(u"localhost"),
                    x509.IPAddress(ipaddress.IPv4Address(local_ip)),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )

        # Write cert and key
        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(key_file, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            ))
        print("[SSL] Certificate generated successfully.")
    except Exception as e:
        print(f"[SSL] Could not generate cert: {e}")
        return None, None
    return cert_file, key_file

# ─── Auth helpers ─────────────────────────────────────────────────────────────
def verify_password(username, password):
    conn = database.get_connection()
    cur  = conn.cursor()
    cur.execute("SELECT password_hash FROM admin_users WHERE username=?", (username,))
    row  = cur.fetchone()
    conn.close()
    return row and bcrypt.checkpw(password.encode(), row['password_hash'].encode())

def is_logged_in():
    return session.get('admin_logged_in') == True

def setup_default_admin():
    pass  # Registration page handles this now

# ─── Routes ───────────────────────────────────────────────────────────────────
@app.route("/", methods=["GET", "POST"])
def login():
    if not database.admin_exists():
        return redirect(url_for("register"))
    error = ""
    ip    = request.remote_addr

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        if ip in lockout_until and time.time() < lockout_until[ip]:
            rem   = int((lockout_until[ip] - time.time()) / 60) + 1
            error = f"Locked out. Try again in {rem} minute(s)."
        elif verify_password(username, password):
            failed_attempts[ip] = 0
            session['admin_logged_in'] = True
            session['username']        = username
            database.log_audit("Mobile Login", f"Login from {ip}")
            return redirect(url_for("dashboard"))
        else:
            failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
            database.log_audit("Failed Mobile Login", f"Attempt {failed_attempts[ip]} from {ip}")
            # Send email alert for every failed attempt
            threading.Thread(
                target=database.send_login_alert,
                args=(ip, failed_attempts[ip]),
                daemon=True
            ).start()
            if failed_attempts[ip] >= MAX_ATTEMPTS:
                lockout_until[ip] = time.time() + LOCKOUT_MINUTES * 60
                error = f"Too many attempts. Locked for {LOCKOUT_MINUTES} mins."
            else:
                left  = MAX_ATTEMPTS - failed_attempts[ip]
                error = f"Invalid credentials. {left} attempt(s) left."

    return render_template("login.html", error=error)

@app.route("/register", methods=["GET", "POST"])
def register():
    if database.admin_exists():
        return redirect(url_for("login"))

    ip = request.remote_addr
    registered_ip = database.get_setting("registered_ip", "")

    if registered_ip and registered_ip != ip:
        return render_template("login.html", error="Registration is closed.")

    error = ""
    if request.method == "POST":
        u  = request.form.get("username", "").strip()
        p  = request.form.get("password", "").strip()
        cp = request.form.get("confirm", "").strip()
        em = request.form.get("email", "").strip()
        if not all([u, p, cp, em]):
            error = "All fields are required."
        elif len(u) < 3:
            error = "Username must be at least 3 characters."
        elif len(p) < 6:
            error = "Password must be at least 6 characters."
        elif p != cp:
            error = "Passwords do not match."
        elif "@" not in em or "." not in em:
            error = "Enter a valid email address."
        else:
            database.register_admin(u, p, em, ip)
            return redirect(url_for("login"))
    return render_template("register.html", error=error)

@app.route("/logout")
def logout():
    database.log_audit("Mobile Logout", f"Logout: {session.get('username','?')}")
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard")
def dashboard():
    if not is_logged_in():
        return redirect(url_for("login"))
    stats = database.get_statistics()
    return render_template("dashboard.html", stats=stats)

@app.route("/evidence")
def evidence():
    if not is_logged_in():
        return redirect(url_for("login"))
    records = database.get_all_evidence()
    return render_template("evidence.html", records=records)

@app.route("/evidence/<int:eid>/status/<status>")
def update_status(eid, status):
    if not is_logged_in():
        return redirect(url_for("login"))
    database.update_evidence_status(eid, status)
    return redirect(url_for("evidence"))

@app.route("/evidence/<int:eid>/delete")
def delete_evidence(eid):
    if not is_logged_in():
        return redirect(url_for("login"))
    database.soft_delete_evidence(eid)
    return redirect(url_for("evidence"))

@app.route("/recycle")
def recycle():
    if not is_logged_in():
        return redirect(url_for("login"))
    records = database.get_deleted_evidence()
    return render_template("recycle.html", records=records)

@app.route("/recycle/<int:eid>/restore")
def restore(eid):
    if not is_logged_in():
        return redirect(url_for("login"))
    database.restore_evidence(eid)
    return redirect(url_for("recycle"))

@app.route("/recycle/<int:eid>/permanent")
def permanent_delete(eid):
    if not is_logged_in():
        return redirect(url_for("login"))
    database.permanent_delete_evidence(eid)
    return redirect(url_for("recycle"))

@app.route("/audit")
def audit():
    if not is_logged_in():
        return redirect(url_for("login"))
    logs = database.get_audit_logs(50)
    return render_template("audit.html", logs=logs)

@app.route("/image/<path:img_path>")
def serve_image(img_path):
    if not is_logged_in():
        return "", 403
    full = os.path.join(".evidence", os.path.basename(img_path))
    if os.path.exists(full):
        return send_file(full, mimetype="image/jpeg")
    return "", 404

@app.route("/integrity")
def integrity():
    if not is_logged_in():
        return redirect(url_for("login"))
    tampered = database.verify_integrity()
    return render_template("integrity.html", tampered=tampered)

def api_stats():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    return jsonify(database.get_statistics())

@app.route("/api/status")
def api_status():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    active = database.get_protection_status()
    stats  = database.get_statistics()
    return jsonify({"active": active, "stats": stats})

@app.route("/api/toggle", methods=["POST"])
def api_toggle():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    current = database.get_protection_status()
    database.set_protection_status(not current)
    state = "Enabled" if not current else "Disabled"
    database.log_audit(f"Protection {state} via Mobile", f"By {session.get('username','?')}")
    return jsonify({"active": not current})

@app.route("/evidence/<int:eid>")
def evidence_detail(eid):
    if not is_logged_in():
        return redirect(url_for("login"))
    rec = database.get_evidence_by_id(eid)
    if not rec:
        return redirect(url_for("evidence"))
    return render_template("evidence_detail.html", rec=rec)

@app.route("/evidence/<int:eid>/download/jpg")
def download_jpg(eid):
    if not is_logged_in():
        return "", 403
    rec = database.get_evidence_by_id(eid)
    if not rec:
        return "", 404
    img_path = rec["image_path"]
    if not os.path.exists(img_path):
        return "Image file not found", 404
    fname = f"evidence_{eid}_{rec['timestamp'].replace(' ','_').replace(':','-')}.jpg"
    return send_file(img_path, mimetype="image/jpeg", as_attachment=True, download_name=fname)

@app.route("/evidence/<int:eid>/download/pdf")
def download_pdf(eid):
    if not is_logged_in():
        return "", 403
    rec = database.get_evidence_by_id(eid)
    if not rec:
        return "", 404
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.units import cm
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image as RLImage
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        import io as _io

        buf = _io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4,
                                leftMargin=2*cm, rightMargin=2*cm,
                                topMargin=2*cm, bottomMargin=2*cm)

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle('title', fontSize=18, fontName='Helvetica-Bold',
                                     textColor=colors.HexColor('#0066cc'), spaceAfter=6)
        sub_style   = ParagraphStyle('sub',   fontSize=10, fontName='Helvetica',
                                     textColor=colors.HexColor('#666666'), spaceAfter=20)
        label_style = ParagraphStyle('label', fontSize=9,  fontName='Helvetica-Bold',
                                     textColor=colors.HexColor('#333333'))

        story = []

        # Header
        story.append(Paragraph("ScreenSentry", title_style))
        story.append(Paragraph("Evidence Report — Document Leakage Prevention System", sub_style))

        # Metadata table
        sev_color = {'High': '#ff3366', 'Medium': '#ff9500', 'Low': '#00aa55'}.get(rec['severity'], '#333')
        data = [
            ["Field", "Value"],
            ["Evidence ID",  f"#{rec['id']}"],
            ["Timestamp",    rec['timestamp']],
            ["Severity",     rec['severity']],
            ["Confidence",   f"{rec['confidence']*100:.1f}%"],
            ["Status",       rec['status']],
            ["Image File",   os.path.basename(rec['image_path'])],
            ["Hash (SHA256)", rec['hash'][:32] + "..."],
        ]
        t = Table(data, colWidths=[4*cm, 13*cm])
        t.setStyle(TableStyle([
            ('BACKGROUND',  (0,0), (-1,0), colors.HexColor('#0066cc')),
            ('TEXTCOLOR',   (0,0), (-1,0), colors.white),
            ('FONTNAME',    (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE',    (0,0), (-1,0), 10),
            ('BACKGROUND',  (0,1), (-1,-1), colors.HexColor('#f8f9fa')),
            ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f0f4ff')]),
            ('FONTNAME',    (0,1), (0,-1), 'Helvetica-Bold'),
            ('FONTSIZE',    (0,1), (-1,-1), 9),
            ('GRID',        (0,0), (-1,-1), 0.5, colors.HexColor('#dddddd')),
            ('PADDING',     (0,0), (-1,-1), 8),
            ('VALIGN',      (0,0), (-1,-1), 'MIDDLE'),
        ]))
        story.append(t)
        story.append(Spacer(1, 0.5*cm))

        # Evidence image
        img_path = rec['image_path']
        if os.path.exists(img_path):
            story.append(Paragraph("Evidence Snapshot", ParagraphStyle('h2', fontSize=12,
                         fontName='Helvetica-Bold', textColor=colors.HexColor('#0066cc'),
                         spaceBefore=10, spaceAfter=8)))
            rl_img = RLImage(img_path, width=15*cm, height=10*cm, kind='proportional')
            story.append(rl_img)

        story.append(Spacer(1, 0.5*cm))
        story.append(Paragraph(
            f"Generated by ScreenSentry v1.0.0 — {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            ParagraphStyle('footer', fontSize=8, textColor=colors.HexColor('#aaaaaa'))
        ))

        doc.build(story)
        buf.seek(0)
        fname = f"evidence_{eid}_{rec['timestamp'].replace(' ','_').replace(':','-')}.pdf"
        database.log_audit("Evidence PDF Downloaded", f"ID: {eid}")
        return send_file(buf, mimetype="application/pdf", as_attachment=True, download_name=fname)

    except ImportError:
        return "reportlab not installed. Run: pip install reportlab", 500
    except Exception as e:
        return f"PDF generation failed: {e}", 500
    if not is_logged_in():
        return redirect(url_for("login"))
    rec = database.get_evidence_by_id(eid)
    if not rec:
        return redirect(url_for("evidence"))
    return render_template("evidence_detail.html", rec=rec)

@app.route("/settings")
def settings():
    if not is_logged_in():
        return redirect(url_for("login"))
    hostname = socket.gethostname()
    try:
        local_ip = socket.gethostbyname(hostname)
    except Exception:
        local_ip = "unknown"
    s = database.get_all_settings()
    info = {
        "hostname":       hostname,
        "local_ip":       local_ip,
        "username":       session.get("username", "admin"),
        "db_path":        os.path.abspath(database.DB_PATH),
        "evidence_count": database.get_statistics()["total"],
        "version":        "1.0.0",
        "conf_threshold": s.get("conf_threshold", "0.3"),
        "confirm_frames": s.get("confirm_frames", "3"),
        "email_alerts":   s.get("email_alerts", "1"),
        "smtp_host":      s.get("smtp_host", "smtp.gmail.com"),
        "smtp_port":      s.get("smtp_port", "587"),
        "smtp_user":      s.get("smtp_user", ""),
        "masked_email":   database.get_masked_email(session.get("username", "")) or "Not set",
        "lockdown_pin_enabled": s.get("lockdown_pin_enabled", "0"),
        "lockdown_pin_set": bool(database.get_lockdown_pin()),
    }
    return render_template("settings.html", info=info)

@app.route("/api/test_email", methods=["POST"])
def test_email():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    try:
        database.send_threat_email(None, 0.95, "High")
        return jsonify({"ok": True, "msg": "Test email sent! Check your inbox."})
    except Exception as e:
        return jsonify({"ok": False, "msg": str(e)})

@app.route("/settings/save", methods=["POST"])
def settings_save():
    if not is_logged_in():
        return redirect(url_for("login"))
    # Detection sensitivity
    conf = request.form.get("conf_threshold", "0.3")
    frames = request.form.get("confirm_frames", "3")
    try:
        conf   = max(0.1, min(0.9, float(conf)))
        frames = max(1, min(10, int(frames)))
    except ValueError:
        conf, frames = 0.3, 3
    database.set_setting("conf_threshold", conf)
    database.set_setting("confirm_frames", frames)
    # Email settings
    database.set_setting("email_alerts", "1" if request.form.get("email_alerts") else "0")
    database.set_setting("smtp_host", request.form.get("smtp_host", "smtp.gmail.com").strip())
    database.set_setting("smtp_port", request.form.get("smtp_port", "587").strip())
    database.set_setting("smtp_user", request.form.get("smtp_user", "").strip())
    smtp_pass = request.form.get("smtp_pass", "").strip()
    if smtp_pass:
        database.set_smtp_password(smtp_pass)
    # Lockdown PIN
    pin_enabled = "1" if request.form.get("lockdown_pin_enabled") else "0"
    database.set_setting("lockdown_pin_enabled", pin_enabled)
    new_pin = request.form.get("lockdown_pin", "").strip()
    if new_pin:
        database.set_lockdown_pin(new_pin)
    database.log_audit("Settings Updated", f"By {session.get('username','?')}")
    return redirect(url_for("settings") + "?saved=1")

@app.route("/export/csv")
def export_csv():
    if not is_logged_in():
        return redirect(url_for("login"))
    records = database.get_all_evidence()
    output  = io.StringIO()
    writer  = csv.writer(output)
    writer.writerow(["ID", "Timestamp", "Image Path", "Confidence", "Severity", "Status"])
    for r in records:
        writer.writerow([r["id"], r["timestamp"], r["image_path"],
                         r["confidence"], r["severity"], r["status"]])
    output.seek(0)
    database.log_audit("Export CSV", f"By {session.get('username','?')}")
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype="text/csv",
        as_attachment=True,
        download_name=f"evidence_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    )

@app.route("/export/zip")
def export_zip():
    if not is_logged_in():
        return redirect(url_for("login"))
    records = database.get_all_evidence()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # Add CSV manifest
        csv_out = io.StringIO()
        writer  = csv.writer(csv_out)
        writer.writerow(["ID", "Timestamp", "Image Path", "Confidence", "Severity", "Status"])
        for r in records:
            writer.writerow([r["id"], r["timestamp"], r["image_path"],
                             r["confidence"], r["severity"], r["status"]])
            img_path = r["image_path"]
            if os.path.exists(img_path):
                zf.write(img_path, os.path.basename(img_path))
        zf.writestr("evidence.csv", csv_out.getvalue())
    buf.seek(0)
    database.log_audit("Export ZIP", f"By {session.get('username','?')}")
    return send_file(
        buf, mimetype="application/zip", as_attachment=True,
        download_name=f"evidence_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
    )

if __name__ == "__main__":
    database.init_database()
    setup_default_admin()

    hostname = socket.gethostname()
    try:
        local_ip = socket.gethostbyname(hostname)
    except Exception:
        local_ip = "localhost"

    print(f"\n{'='*52}")
    print(f"  ScreenSentry Mobile Admin")
    print(f"  Local access: http://{local_ip}:5000")
    print(f"  For mobile via ngrok: ngrok http 5000")
    print(f"{'='*52}\n")

    app.run(host="0.0.0.0", port=5000, debug=False)
