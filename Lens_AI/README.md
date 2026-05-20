# ScreenSentry — Document Leakage Prevention System

A real-time document protection system that detects phones near your screen using AI (YOLOv8), triggers lockdown, captures evidence, and alerts the admin via email.

---

## Project Structure

```
ScreenSentry/
├── main.py          # Core protection app (detection, lockdown, document viewer)
├── server.py        # Mobile web admin panel (Flask)
├── admin.py         # Desktop admin panel (Tkinter)
├── database.py      # SQLite database layer
├── launch.py        # Single launcher for all services
├── config.py        # Configuration (ngrok token)
├── yolo26n.pt       # YOLOv8 detection model
├── best.pt          # Backup model
├── cert.pem         # SSL certificate (auto-generated)
├── key.pem          # SSL key (auto-generated)
├── screensentry.db  # SQLite database (auto-created)
├── security_log.txt # Detection log file
├── .evidence/       # Hidden folder for evidence snapshots
└── templates/       # Mobile web HTML templates
    ├── base.html
    ├── login.html
    ├── register.html
    ├── dashboard.html
    ├── evidence.html
    ├── evidence_detail.html
    ├── recycle.html
    ├── audit.html
    ├── integrity.html
    └── settings.html
```

---

## How to Run

### Start everything
```
python launch.py
```
This starts `server.py` and `main.py` silently in the background.

### Mobile access (ngrok)
Run in a separate terminal:
```
ngrok http 5000
```
Copy the `https://xxxx.ngrok-free.app` URL and open on your phone.

### Local browser access
```
http://localhost:5000
```

---

## First Time Setup

1. Run `python launch.py`
2. Open `http://localhost:5000` in browser
3. Registration page appears — fill in username, password, email
4. Login with your credentials
5. Go to Settings → Email Alerts → enter Gmail + App Password → Save

---

## Core Features

### Phone Detection
- Uses YOLOv8 model to detect phones via webcam
- Confirmation buffer (default 3 frames) to avoid false positives
- Runs fully in background — no camera preview window by default

### Lockdown
- Black fullscreen overlay appears when phone detected
- Countdown timer (30 seconds) — cannot be reset by repeated detections
- Yes/No popup — Yes resumes, No closes document
- At zero → workstation locks automatically

### Camera Tamper Detection
- Detects if camera is covered (tape/sticker) → mean brightness < 8
- Detects flashlight attack → mean brightness > 247
- Detects smeared lens → blur variance < 1.5
- On tamper → document closes instantly, evidence saved, email sent

### Evidence Capture
- Webcam snapshot saved to hidden `.evidence/` folder on every detection
- Saved to SQLite with timestamp, confidence, severity (Low/Medium/High)
- SHA256 hash stored for integrity verification

### Screenshot Protection
- Blocks PrintScreen key
- Blocks Win+Shift+S (Snipping Tool)
- Blocks Alt+PrintScreen
- Clears clipboard if screenshot detected

### Screen Recorder Detection
- Detects OBS, Bandicam, Fraps, Camtasia, ShareX and more
- Triggers lockdown if recorder found running

---

## Mobile Web Admin (Flask)

### Pages
| Page | URL | Description |
|------|-----|-------------|
| Login | `/` | Admin login with lockout |
| Register | `/register` | First time setup (localhost only) |
| Dashboard | `/dashboard` | Stats, threat level, timeline, toggle |
| Evidence | `/evidence` | All evidence with thumbnails |
| Evidence Detail | `/evidence/<id>` | Full image, metadata, download |
| Recycle Bin | `/recycle` | Deleted evidence |
| Audit Log | `/audit` | All admin actions |
| Integrity | `/integrity` | Hash verification |
| Settings | `/settings` | Sensitivity, email, system info |

### API Endpoints
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/status` | GET | Protection status + stats |
| `/api/toggle` | POST | Enable/disable protection |
| `/api/test_email` | POST | Send test email alert |
| `/export/csv` | GET | Download evidence as CSV |
| `/export/zip` | GET | Download evidence + images as ZIP |
| `/evidence/<id>/download/jpg` | GET | Download evidence image |
| `/evidence/<id>/download/pdf` | GET | Download PDF report |

### Security
- bcrypt password hashing
- Fernet AES email encryption
- 3 attempt lockout (10 min timeout)
- Registration locked to localhost only
- Failed login email alerts
- Session-based authentication

---

## Database Schema

### `evidence`
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| timestamp | TEXT | Detection time |
| image_path | TEXT | Path to snapshot |
| confidence | REAL | Detection confidence (0-1) |
| severity | TEXT | Low / Medium / High |
| status | TEXT | Pending / Confirmed / False Alarm |
| deleted | INTEGER | Soft delete flag |
| hash | TEXT | SHA256 integrity hash |

### `audit_log`
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| timestamp | TEXT | Action time |
| action | TEXT | Action name |
| details | TEXT | Action details |

### `admin_users`
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| username | TEXT | Admin username |
| password_hash | TEXT | bcrypt hash |
| email_encrypted | TEXT | Fernet encrypted email |

### `app_settings`
| Column | Type | Description |
|--------|------|-------------|
| key | TEXT | Setting name |
| value | TEXT | Setting value |

### Default Settings
| Key | Default | Description |
|-----|---------|-------------|
| conf_threshold | 0.3 | Detection confidence threshold |
| confirm_frames | 3 | Frames needed to confirm threat |
| email_alerts | 1 | Email alerts on/off |
| smtp_host | smtp.gmail.com | SMTP server |
| smtp_port | 587 | SMTP port |
| smtp_user | (empty) | Sender Gmail address |
| smtp_pass_enc | (empty) | Encrypted app password |

---

## Email Alerts

Sent on:
- Phone detected (with evidence snapshot attached)
- Camera tamper detected
- Failed login attempt (every attempt, with IP address)

Setup:
1. Enable 2-Step Verification on Google Account
2. Go to Google Account → Security → App Passwords
3. Generate password for "ScreenSentry"
4. Enter in Settings → Email Alerts

---

## Detection Sensitivity

Adjustable from mobile Settings page:

| Setting | Range | Default | Effect |
|---------|-------|---------|--------|
| Confidence Threshold | 10%-90% | 30% | Higher = stricter, fewer false alarms |
| Confirm Frames | 1-10 | 3 | Higher = slower but more accurate |

---

## Document Viewer

Supported formats:
- `.pptx` — PowerPoint (dark theme rendering)
- `.png`, `.jpg`, `.jpeg`, `.bmp`, `.gif` — Images
- `.txt` — Text files

---

## Dependencies

```
pip install ultralytics opencv-python keyboard pystray pillow
pip install flask bcrypt cryptography python-pptx reportlab psutil
```

---

## Future Scope

- WhatsApp / Telegram instant alerts
- Scheduled protection (active hours)
- Multi-camera support
- SaaS version with multi-tenant architecture
- Mobile APK version
- Forgot password via email

---

## Developer

For support or queries:
📧 mrtechieguys@gmail.com
