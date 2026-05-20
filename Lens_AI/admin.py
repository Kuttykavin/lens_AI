import tkinter as tk
from tkinter import ttk, messagebox
import bcrypt
import datetime
import os
import time
import threading
from PIL import Image, ImageTk, ImageDraw, ImageFilter
import database

# ─── Theme Colors ─────────────────────────────────────────────────────────────
BG          = "#0a0a0f"
BG2         = "#0f0f1a"
BG3         = "#1a1a2e"
BG4         = "#16213e"
ACCENT      = "#00d4ff"
ACCENT2     = "#7b2fff"
GREEN       = "#00ff88"
RED         = "#ff3366"
ORANGE      = "#ff9500"
WHITE       = "#e8e8ff"
GRAY        = "#4a4a6a"
CARD_BG     = "#12122a"

# ─── Config ───────────────────────────────────────────────────────────────────
MAX_ATTEMPTS    = 3
LOCKOUT_MINUTES = 10
SESSION_TIMEOUT = 300

DEFAULT_USERNAME = "admin"
DEFAULT_PASSWORD = "admin123"

# ─── Globals ──────────────────────────────────────────────────────────────────
failed_attempts = 0
lockout_until   = None
last_activity   = time.time()
root            = None

# ─── Helpers ──────────────────────────────────────────────────────────────────
def verify_password(username, password):
    conn = database.get_connection()
    cur  = conn.cursor()
    cur.execute("SELECT password_hash FROM admin_users WHERE username=?", (username,))
    row  = cur.fetchone()
    conn.close()
    return row and bcrypt.checkpw(password.encode(), row['password_hash'].encode())

def make_gradient_image(w, h, c1, c2, vertical=True):
    """Create a gradient PIL image."""
    img  = Image.new("RGB", (w, h))
    r1,g1,b1 = int(c1[1:3],16), int(c1[3:5],16), int(c1[5:7],16)
    r2,g2,b2 = int(c2[1:3],16), int(c2[3:5],16), int(c2[5:7],16)
    for i in range(h if vertical else w):
        t = i / (h if vertical else w)
        r = int(r1 + (r2-r1)*t)
        g = int(g1 + (g2-g1)*t)
        b = int(b1 + (b2-b1)*t)
        if vertical:
            img.paste((r,g,b), (0, i, w, i+1))
        else:
            img.paste((r,g,b), (i, 0, i+1, h))
    return img

# ─── Registration Window ──────────────────────────────────────────────────────
class RegisterWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("ScreenSentry — Setup Admin Account")
        self.root.geometry("480x580")
        self.root.resizable(False, False)
        self.root.configure(bg=BG)
        self.root.eval('tk::PlaceWindow . center')
        self._build()

    def _build(self):
        banner = tk.Canvas(self.root, width=480, height=140, highlightthickness=0, bg=BG)
        banner.pack()
        grad = make_gradient_image(480, 140, "#0a0a1a", "#1a0a3a")
        self._grad = ImageTk.PhotoImage(grad)
        banner.create_image(0, 0, anchor="nw", image=self._grad)
        banner.create_oval(175, 15, 305, 125, fill="#0d0d2a", outline=ACCENT, width=2)
        banner.create_text(240, 68, text="🛡", font=("Segoe UI Emoji", 36), fill=WHITE)
        banner.create_text(240, 118, text="FIRST TIME SETUP", font=("Arial", 11, "bold"), fill=ACCENT)
        banner.create_text(240, 133, text="Create your admin account", font=("Arial", 8), fill=GRAY)

        card = tk.Frame(self.root, bg=CARD_BG)
        card.pack(fill=tk.BOTH, expand=True, padx=40, pady=15)

        tk.Label(card, text="Register Admin", font=("Arial", 16, "bold"),
                 bg=CARD_BG, fg=WHITE).pack(pady=(20, 3))
        tk.Label(card, text="This account will have full access to ScreenSentry",
                 font=("Arial", 9), bg=CARD_BG, fg=GRAY).pack(pady=(0, 15))

        self.username_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.confirm_var  = tk.StringVar()
        self.email_var    = tk.StringVar()

        for label, var, show in [
            ("USERNAME",         self.username_var, None),
            ("PASSWORD",         self.password_var, "●"),
            ("CONFIRM PASSWORD", self.confirm_var,  "●"),
            ("EMAIL ADDRESS",    self.email_var,    None),
        ]:
            tk.Label(card, text=label, font=("Arial", 8, "bold"),
                     bg=CARD_BG, fg=ACCENT, anchor="w").pack(fill=tk.X, padx=25)
            frame = tk.Frame(card, bg=GRAY)
            frame.pack(fill=tk.X, padx=25, ipady=1, pady=(2, 10))
            inner = tk.Frame(frame, bg=BG3)
            inner.pack(fill=tk.X, padx=1, pady=1)
            e = tk.Entry(inner, textvariable=var, show=show or "",
                         font=("Consolas", 11), bg=BG3, fg=WHITE,
                         insertbackground=ACCENT, relief=tk.FLAT)
            e.pack(fill=tk.X, padx=10, ipady=7)
            e.bind("<FocusIn>",  lambda ev, f=frame: f.config(bg=ACCENT))
            e.bind("<FocusOut>", lambda ev, f=frame: f.config(bg=GRAY))

        self.error_var = tk.StringVar()
        tk.Label(card, textvariable=self.error_var, font=("Arial", 9),
                 bg=CARD_BG, fg=RED).pack(pady=4)

        btn = tk.Canvas(card, width=320, height=42, bg=CARD_BG, highlightthickness=0, cursor="hand2")
        btn.pack()
        btn.create_rectangle(0, 0, 320, 42, fill=ACCENT2, outline="")
        btn.create_rectangle(2, 2, 318, 40, fill="#5a1fcc", outline="")
        btn.create_text(160, 21, text="CREATE ACCOUNT  →", font=("Arial", 10, "bold"), fill=WHITE)
        btn.bind("<Button-1>", lambda e: self._register())
        self.root.bind("<Return>", lambda e: self._register())

    def _register(self):
        u  = self.username_var.get().strip()
        p  = self.password_var.get().strip()
        cp = self.confirm_var.get().strip()
        em = self.email_var.get().strip()

        if not all([u, p, cp, em]):
            self.error_var.set("⚠  All fields are required.")
            return
        if len(u) < 3:
            self.error_var.set("⚠  Username must be at least 3 characters.")
            return
        if len(p) < 6:
            self.error_var.set("⚠  Password must be at least 6 characters.")
            return
        if p != cp:
            self.error_var.set("⚠  Passwords do not match.")
            return
        if "@" not in em or "." not in em:
            self.error_var.set("⚠  Enter a valid email address.")
            return

        database.register_admin(u, p, em)
        self.root.destroy()
        open_login()

# ─── Login Window ─────────────────────────────────────────────────────────────
class LoginWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("ScreenSentry — Admin")
        self.root.geometry("480x600")
        self.root.resizable(False, False)
        self.root.configure(bg=BG)
        self.root.eval('tk::PlaceWindow . center')
        self._build()

    def _build(self):
        # Gradient top banner
        banner_canvas = tk.Canvas(self.root, width=480, height=180,
                                  highlightthickness=0, bg=BG)
        banner_canvas.pack()
        grad = make_gradient_image(480, 180, "#0a0a1a", "#1a0a3a")
        self._grad_img = ImageTk.PhotoImage(grad)
        banner_canvas.create_image(0, 0, anchor="nw", image=self._grad_img)

        # Glowing circle behind shield
        banner_canvas.create_oval(175, 20, 305, 150, fill="#0d0d2a", outline=ACCENT, width=2)
        banner_canvas.create_oval(185, 30, 295, 140, fill="#0a0a1f", outline=ACCENT2, width=1)
        banner_canvas.create_text(240, 88, text="🛡", font=("Segoe UI Emoji", 42),
                                  fill=WHITE)
        banner_canvas.create_text(240, 158, text="SCREENSENTRY", font=("Arial", 13, "bold"),
                                  fill=ACCENT, tags="title")
        banner_canvas.create_text(240, 175, text="ADMIN PORTAL", font=("Arial", 9),
                                  fill=GRAY)

        # Card frame
        card = tk.Frame(self.root, bg=CARD_BG, bd=0)
        card.pack(fill=tk.BOTH, expand=True, padx=40, pady=20)

        tk.Label(card, text="Sign In", font=("Arial", 18, "bold"),
                 bg=CARD_BG, fg=WHITE).pack(pady=(25, 5))
        tk.Label(card, text="Enter your admin credentials to continue",
                 font=("Arial", 9), bg=CARD_BG, fg=GRAY).pack(pady=(0, 20))

        # Username field
        self._field(card, "USERNAME", show=None)
        self.username_var = tk.StringVar()
        self.u_entry = self._entry(card, self.username_var)

        tk.Label(card, bg=CARD_BG).pack(pady=6)

        # Password field
        self._field(card, "PASSWORD", show=None)
        self.password_var = tk.StringVar()
        self.p_entry = self._entry(card, self.password_var, show="●")

        # Error label
        self.error_var = tk.StringVar()
        tk.Label(card, textvariable=self.error_var, font=("Arial", 9),
                 bg=CARD_BG, fg=RED).pack(pady=8)

        # Login button
        self.btn = tk.Canvas(card, width=320, height=44, bg=CARD_BG,
                             highlightthickness=0, cursor="hand2")
        self.btn.pack()
        self._draw_btn(self.btn, "LOGIN  →")
        self.btn.bind("<Button-1>", lambda e: self._attempt_login())
        self.root.bind("<Return>", lambda e: self._attempt_login())

        tk.Label(card, text="ScreenSentry v2.0  •  Secured Access",
                 font=("Arial", 8), bg=CARD_BG, fg=GRAY).pack(pady=(15, 0))

        self.u_entry.focus()

    def _field(self, parent, label, show):
        tk.Label(parent, text=label, font=("Arial", 8, "bold"),
                 bg=CARD_BG, fg=ACCENT, anchor="w").pack(fill=tk.X, padx=30)

    def _entry(self, parent, var, show=None):
        frame = tk.Frame(parent, bg=GRAY, bd=0)
        frame.pack(fill=tk.X, padx=30, ipady=1)
        inner = tk.Frame(frame, bg=BG3)
        inner.pack(fill=tk.X, padx=1, pady=1)
        e = tk.Entry(inner, textvariable=var, show=show or "",
                     font=("Consolas", 12), bg=BG3, fg=WHITE,
                     insertbackground=ACCENT, relief=tk.FLAT,
                     bd=0)
        e.pack(fill=tk.X, padx=10, ipady=8)
        e.bind("<FocusIn>",  lambda ev, f=frame: f.config(bg=ACCENT))
        e.bind("<FocusOut>", lambda ev, f=frame: f.config(bg=GRAY))
        return e

    def _draw_btn(self, canvas, text):
        canvas.delete("all")
        canvas.create_rectangle(0, 0, 320, 44, fill=ACCENT2, outline="", tags="bg")
        canvas.create_rectangle(2, 2, 318, 42, fill="#5a1fcc", outline="", tags="inner")
        canvas.create_text(160, 22, text=text, font=("Arial", 11, "bold"),
                           fill=WHITE, tags="txt")
        canvas.tag_bind("bg",    "<Enter>", lambda e: canvas.itemconfig("bg", fill=ACCENT))
        canvas.tag_bind("inner", "<Enter>", lambda e: canvas.itemconfig("bg", fill=ACCENT))
        canvas.tag_bind("txt",   "<Enter>", lambda e: canvas.itemconfig("bg", fill=ACCENT))

    def _attempt_login(self):
        global failed_attempts, lockout_until
        if lockout_until and time.time() < lockout_until:
            rem = int((lockout_until - time.time()) / 60) + 1
            self.error_var.set(f"⛔  Locked out. Try again in {rem} min.")
            return

        u = self.u_entry.get().strip()
        p = self.p_entry.get().strip()
        if not u or not p:
            self.error_var.set("⚠  Please enter both fields.")
            return

        if verify_password(u, p):
            failed_attempts = 0
            lockout_until   = None
            database.log_audit("Admin Login", f"Successful: {u}")
            self.root.destroy()
            open_dashboard()
        else:
            failed_attempts += 1
            database.log_audit("Failed Login", f"Attempt {failed_attempts}/3: {u}")
            if failed_attempts >= MAX_ATTEMPTS:
                lockout_until = time.time() + LOCKOUT_MINUTES * 60
                self.error_var.set(f"⛔  Too many attempts. Locked {LOCKOUT_MINUTES} mins.")
            else:
                self.error_var.set(f"✗  Invalid credentials. {MAX_ATTEMPTS - failed_attempts} left.")
            self.p_entry.delete(0, tk.END)

# ─── Dashboard ────────────────────────────────────────────────────────────────
class Dashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("ScreenSentry — Admin Dashboard")
        self.root.geometry("1200x720")
        self.root.configure(bg=BG)
        self.root.eval('tk::PlaceWindow . center')
        self._build()
        self._auto_refresh()

    def _auto_refresh(self):
        self.load_evidence()
        self.load_recycle()
        self.root.after(5000, self._auto_refresh)

    def _build(self):
        # ── Sidebar ───────────────────────────────────────────────────────────
        self.sidebar = tk.Frame(self.root, bg=BG4, width=220)
        self.sidebar.pack(side=tk.LEFT, fill=tk.Y)
        self.sidebar.pack_propagate(False)

        # Logo
        logo_frame = tk.Frame(self.sidebar, bg=BG4, height=100)
        logo_frame.pack(fill=tk.X)
        logo_frame.pack_propagate(False)
        tk.Label(logo_frame, text="🛡", font=("Segoe UI Emoji", 28),
                 bg=BG4, fg=ACCENT).place(relx=0.2, rely=0.5, anchor="center")
        tk.Label(logo_frame, text="Screen\nSentry", font=("Arial", 13, "bold"),
                 bg=BG4, fg=WHITE, justify="left").place(relx=0.55, rely=0.5, anchor="center")

        # Divider
        tk.Frame(self.sidebar, bg=GRAY, height=1).pack(fill=tk.X, padx=15)

        # Nav buttons
        self.nav_btns = []
        nav_items = [
            ("📋", "Evidence",   self._show_evidence),
            ("🗑", "Recycle Bin", self._show_recycle),
            ("📊", "Analytics",  self._show_analytics),
            ("📜", "Audit Log",  self._show_audit),
        ]
        for icon, label, cmd in nav_items:
            btn = self._nav_btn(icon, label, cmd)
            self.nav_btns.append(btn)

        # Bottom logout
        tk.Frame(self.sidebar, bg=BG4).pack(expand=True)
        tk.Frame(self.sidebar, bg=GRAY, height=1).pack(fill=tk.X, padx=15)
        self._nav_btn("⏻", "Logout", self._logout, danger=True)

        # ── Main content area ─────────────────────────────────────────────────
        self.content = tk.Frame(self.root, bg=BG)
        self.content.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Top bar
        topbar = tk.Frame(self.content, bg=BG2, height=55)
        topbar.pack(fill=tk.X)
        topbar.pack_propagate(False)

        self.page_title = tk.Label(topbar, text="Evidence", font=("Arial", 16, "bold"),
                                   bg=BG2, fg=WHITE)
        self.page_title.pack(side=tk.LEFT, padx=25, pady=12)

        # Live indicator
        self.live_dot = tk.Label(topbar, text="● LIVE", font=("Arial", 9, "bold"),
                                 bg=BG2, fg=GREEN)
        self.live_dot.pack(side=tk.RIGHT, padx=20)
        self._blink_live()

        self.time_label = tk.Label(topbar, font=("Arial", 10), bg=BG2, fg=GRAY)
        self.time_label.pack(side=tk.RIGHT, padx=10)
        self._update_clock()

        # Pages
        self.pages = {}
        self._build_evidence_page()
        self._build_recycle_page()
        self._build_analytics_page()
        self._build_audit_page()

        self._show_evidence()

    def _nav_btn(self, icon, label, cmd, danger=False):
        fg    = RED if danger else GRAY
        hover = RED if danger else ACCENT
        frame = tk.Frame(self.sidebar, bg=BG4, cursor="hand2")
        frame.pack(fill=tk.X, padx=8, pady=2)
        lbl = tk.Label(frame, text=f"  {icon}  {label}", font=("Arial", 11),
                       bg=BG4, fg=fg, anchor="w", padx=10, pady=10)
        lbl.pack(fill=tk.X)
        bar = tk.Frame(frame, bg=BG4, width=4)
        bar.place(x=0, y=0, relheight=1)

        def on_enter(e):
            frame.config(bg=BG3); lbl.config(bg=BG3, fg=hover)
            bar.config(bg=hover)
        def on_leave(e):
            frame.config(bg=BG4); lbl.config(bg=BG4, fg=fg)
            bar.config(bg=BG4)

        frame.bind("<Enter>", on_enter); frame.bind("<Leave>", on_leave)
        lbl.bind("<Enter>",   on_enter); lbl.bind("<Leave>",   on_leave)
        frame.bind("<Button-1>", lambda e: cmd())
        lbl.bind("<Button-1>",   lambda e: cmd())
        return frame

    def _show_page(self, name, title):
        for p in self.pages.values():
            p.pack_forget()
        self.pages[name].pack(fill=tk.BOTH, expand=True)
        self.page_title.config(text=title)

    def _show_evidence(self):  self._show_page("evidence",  "📋  Evidence")
    def _show_recycle(self):   self._show_page("recycle",   "🗑  Recycle Bin")
    def _show_analytics(self): self._show_page("analytics", "📊  Analytics"); self._refresh_analytics()
    def _show_audit(self):     self._show_page("audit",     "📜  Audit Log");  self.load_audit()

    def _blink_live(self):
        cur = self.live_dot.cget("fg")
        self.live_dot.config(fg=GREEN if cur == BG2 else BG2)
        self.root.after(800, self._blink_live)

    def _update_clock(self):
        self.time_label.config(text=datetime.datetime.now().strftime("%d %b %Y  %H:%M:%S"))
        self.root.after(1000, self._update_clock)

    def _logout(self):
        database.log_audit("Admin Logout", "Manual logout")
        self.root.destroy()
        restart_login()

    # ── Styled widgets ────────────────────────────────────────────────────────
    def _action_btn(self, parent, text, color, cmd):
        btn = tk.Label(parent, text=text, font=("Arial", 9, "bold"),
                       bg=color, fg=WHITE, padx=12, pady=6, cursor="hand2")
        btn.bind("<Button-1>", lambda e: cmd())
        btn.bind("<Enter>", lambda e: btn.config(bg=self._lighten(color)))
        btn.bind("<Leave>", lambda e: btn.config(bg=color))
        return btn

    def _lighten(self, hex_color):
        r,g,b = int(hex_color[1:3],16), int(hex_color[3:5],16), int(hex_color[5:7],16)
        r,g,b = min(255,r+30), min(255,g+30), min(255,b+30)
        return f"#{r:02x}{g:02x}{b:02x}"

    def _styled_tree(self, parent, cols, widths):
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Fancy.Treeview",
                        background=BG3, foreground=WHITE,
                        fieldbackground=BG3, rowheight=34,
                        font=("Consolas", 10))
        style.configure("Fancy.Treeview.Heading",
                        background=BG4, foreground=ACCENT,
                        font=("Arial", 10, "bold"), relief="flat")
        style.map("Fancy.Treeview",
                  background=[("selected", ACCENT2)],
                  foreground=[("selected", WHITE)])

        frame = tk.Frame(parent, bg=BG)
        tree  = ttk.Treeview(frame, columns=cols, show="headings",
                              style="Fancy.Treeview", selectmode="browse")
        for col, w in zip(cols, widths):
            tree.heading(col, text=col)
            tree.column(col, width=w, anchor="center")

        sb = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.LEFT, fill=tk.Y)
        return frame, tree

    # ── Evidence Page ─────────────────────────────────────────────────────────
    def _build_evidence_page(self):
        page = tk.Frame(self.content, bg=BG)
        self.pages["evidence"] = page

        # Toolbar
        tb = tk.Frame(page, bg=BG2, height=52)
        tb.pack(fill=tk.X, padx=0, pady=(0,2))
        tb.pack_propagate(False)

        self._action_btn(tb, "✅  Confirmed",   "#1b5e20", lambda: self._update_status("Confirmed")).pack(side=tk.LEFT, padx=(15,4), pady=10)
        self._action_btn(tb, "❌  False Alarm",  "#7f0000", lambda: self._update_status("False Alarm")).pack(side=tk.LEFT, padx=4, pady=10)
        self._action_btn(tb, "🗑  Delete",       "#333355", self._delete_evidence).pack(side=tk.LEFT, padx=4, pady=10)
        self._action_btn(tb, "🔍  Verify Integrity", "#0d47a1", self._verify_integrity).pack(side=tk.RIGHT, padx=15, pady=10)

        # Main split
        split = tk.Frame(page, bg=BG)
        split.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)

        # Table
        cols   = ("ID", "Timestamp", "Severity", "Confidence", "Status")
        widths = [50, 190, 100, 110, 130]
        tree_frame, self.evidence_tree = self._styled_tree(split, cols, widths)
        tree_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.evidence_tree.tag_configure("High",   foreground=RED)
        self.evidence_tree.tag_configure("Medium", foreground=ORANGE)
        self.evidence_tree.tag_configure("Low",    foreground=GREEN)
        self.evidence_tree.bind("<<TreeviewSelect>>", self._on_evidence_select)

        # Preview panel
        preview = tk.Frame(split, bg=CARD_BG, width=240)
        preview.pack(side=tk.RIGHT, fill=tk.Y, padx=(12,0))
        preview.pack_propagate(False)

        tk.Label(preview, text="EVIDENCE PREVIEW", font=("Arial", 9, "bold"),
                 bg=CARD_BG, fg=ACCENT).pack(pady=(15,5))
        tk.Frame(preview, bg=GRAY, height=1).pack(fill=tk.X, padx=15)

        self.preview_canvas = tk.Canvas(preview, bg="#0a0a15", width=210, height=160,
                                        highlightthickness=1, highlightbackground=GRAY)
        self.preview_canvas.pack(pady=12, padx=15)
        self.preview_canvas.create_text(105, 80, text="Select a record",
                                        fill=GRAY, font=("Arial", 10))

        self.detail_frame = tk.Frame(preview, bg=CARD_BG)
        self.detail_frame.pack(fill=tk.X, padx=15)

    def load_evidence(self):
        sel = self.evidence_tree.selection()
        for row in self.evidence_tree.get_children():
            self.evidence_tree.delete(row)
        for rec in database.get_all_evidence():
            tag = rec['severity']
            self.evidence_tree.insert("", tk.END, iid=str(rec['id']),
                values=(rec['id'], rec['timestamp'], rec['severity'],
                        f"{rec['confidence']:.0%}", rec['status']), tags=(tag,))
        if sel:
            try: self.evidence_tree.selection_set(sel)
            except Exception: pass

    def _on_evidence_select(self, event):
        sel = self.evidence_tree.selection()
        if not sel:
            return
        eid  = int(sel[0])
        recs = database.get_all_evidence()
        rec  = next((r for r in recs if r['id'] == eid), None)
        if not rec:
            return

        self.preview_canvas.delete("all")
        if os.path.exists(rec['image_path']):
            try:
                img = Image.open(rec['image_path'])
                img.thumbnail((210, 160))
                self._prev_img = ImageTk.PhotoImage(img)
                self.preview_canvas.create_image(105, 80, anchor="center", image=self._prev_img)
            except Exception:
                self.preview_canvas.create_text(105, 80, text="Cannot load", fill=RED)
        else:
            self.preview_canvas.create_text(105, 80, text="Image not found", fill=GRAY)

        for w in self.detail_frame.winfo_children():
            w.destroy()
        details = [
            ("ID",         str(rec['id'])),
            ("Time",       rec['timestamp']),
            ("Severity",   rec['severity']),
            ("Confidence", f"{rec['confidence']:.0%}"),
            ("Status",     rec['status']),
        ]
        for k, v in details:
            row = tk.Frame(self.detail_frame, bg=CARD_BG)
            row.pack(fill=tk.X, pady=2)
            tk.Label(row, text=k, font=("Arial", 8), bg=CARD_BG, fg=GRAY, width=10, anchor="w").pack(side=tk.LEFT)
            tk.Label(row, text=v, font=("Arial", 8, "bold"), bg=CARD_BG, fg=WHITE, anchor="w").pack(side=tk.LEFT)

    def _update_status(self, status):
        sel = self.evidence_tree.selection()
        if not sel:
            messagebox.showwarning("No Selection", "Select a record first.", parent=self.root)
            return
        database.update_evidence_status(int(sel[0]), status)
        self.load_evidence()

    def _delete_evidence(self):
        sel = self.evidence_tree.selection()
        if not sel:
            messagebox.showwarning("No Selection", "Select a record first.", parent=self.root)
            return
        if messagebox.askyesno("Delete", "Move to recycle bin?", parent=self.root):
            database.soft_delete_evidence(int(sel[0]))
            self.load_evidence()
            self.load_recycle()

    def _verify_integrity(self):
        tampered = database.verify_integrity()
        if tampered:
            messagebox.showerror("Tampered!", f"Records tampered: {tampered}", parent=self.root)
        else:
            messagebox.showinfo("All Clear", "All evidence records are intact ✓", parent=self.root)

    # ── Recycle Bin Page ──────────────────────────────────────────────────────
    def _build_recycle_page(self):
        page = tk.Frame(self.content, bg=BG)
        self.pages["recycle"] = page

        tb = tk.Frame(page, bg=BG2, height=52)
        tb.pack(fill=tk.X, pady=(0,2))
        tb.pack_propagate(False)
        self._action_btn(tb, "♻  Restore",          "#1b5e20", self._restore_evidence).pack(side=tk.LEFT, padx=(15,4), pady=10)
        self._action_btn(tb, "🗑  Permanent Delete",  "#7f0000", self._permanent_delete).pack(side=tk.LEFT, padx=4, pady=10)

        cols   = ("ID", "Timestamp", "Severity", "Confidence")
        widths = [60, 220, 130, 130]
        tree_frame, self.recycle_tree = self._styled_tree(page, cols, widths)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)

    def load_recycle(self):
        sel = self.recycle_tree.selection()
        for row in self.recycle_tree.get_children():
            self.recycle_tree.delete(row)
        for rec in database.get_deleted_evidence():
            self.recycle_tree.insert("", tk.END, iid=str(rec['id']),
                values=(rec['id'], rec['timestamp'], rec['severity'],
                        f"{rec['confidence']:.0%}"))
        if sel:
            try: self.recycle_tree.selection_set(sel)
            except Exception: pass

    def _restore_evidence(self):
        sel = self.recycle_tree.selection()
        if not sel:
            messagebox.showwarning("No Selection", "Select a record first.", parent=self.root)
            return
        database.restore_evidence(int(sel[0]))
        self.load_recycle()
        self.load_evidence()

    def _permanent_delete(self):
        sel = self.recycle_tree.selection()
        if not sel:
            messagebox.showwarning("No Selection", "Select a record first.", parent=self.root)
            return
        if messagebox.askyesno("Permanent Delete",
                               "This cannot be undone. Delete permanently?", parent=self.root):
            database.permanent_delete_evidence(int(sel[0]))
            self.load_recycle()

    # ── Analytics Page ────────────────────────────────────────────────────────
    def _build_analytics_page(self):
        page = tk.Frame(self.content, bg=BG)
        self.pages["analytics"] = page

    def _refresh_analytics(self):
        page = self.pages["analytics"]
        for w in page.winfo_children():
            w.destroy()

        stats = database.get_statistics()

        # Stat cards row
        cards = tk.Frame(page, bg=BG)
        cards.pack(fill=tk.X, padx=20, pady=20)

        card_data = [
            ("TOTAL THREATS",  str(stats['total']),                              ACCENT),
            ("CONFIRMED",      str(stats['by_status'].get('Confirmed', 0)),      RED),
            ("FALSE ALARMS",   str(stats['by_status'].get('False Alarm', 0)),    ORANGE),
            ("PENDING",        str(stats['by_status'].get('Pending', 0)),        GREEN),
            ("HIGH SEVERITY",  str(stats['by_severity'].get('High', 0)),         RED),
        ]
        for title, val, color in card_data:
            c = tk.Frame(cards, bg=CARD_BG, width=170, height=100)
            c.pack(side=tk.LEFT, padx=8)
            c.pack_propagate(False)
            tk.Frame(c, bg=color, height=3).pack(fill=tk.X)
            tk.Label(c, text=val, font=("Arial", 32, "bold"),
                     bg=CARD_BG, fg=color).pack(expand=True)
            tk.Label(c, text=title, font=("Arial", 8, "bold"),
                     bg=CARD_BG, fg=GRAY).pack(pady=(0,8))

        # Bar chart
        chart_frame = tk.Frame(page, bg=CARD_BG)
        chart_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0,20))

        tk.Label(chart_frame, text="THREATS — LAST 7 DAYS",
                 font=("Arial", 11, "bold"), bg=CARD_BG, fg=ACCENT).pack(pady=(15,5))
        tk.Frame(chart_frame, bg=GRAY, height=1).pack(fill=tk.X, padx=20)

        canvas = tk.Canvas(chart_frame, bg=CARD_BG, height=220, highlightthickness=0)
        canvas.pack(fill=tk.X, padx=30, pady=15)

        if stats['by_date']:
            max_c = max(c for _, c in stats['by_date']) or 1
            bw, gap, x = 55, 25, 50
            for date, count in stats['by_date']:
                bh = int((count / max_c) * 160)
                y1 = 190 - bh
                # Bar gradient effect
                for i in range(bh):
                    t = i / bh
                    r = int(0x00 + (0x7b - 0x00) * t)
                    g = int(0xd4 + (0x2f - 0xd4) * t)
                    b = int(0xff + (0xff - 0xff) * t)
                    canvas.create_line(x, y1+i, x+bw, y1+i, fill=f"#{r:02x}{g:02x}{b:02x}")
                canvas.create_rectangle(x, y1, x+bw, 190, outline=ACCENT, width=1)
                canvas.create_text(x+bw//2, 205, text=date[-5:], fill=GRAY, font=("Arial", 8))
                canvas.create_text(x+bw//2, y1-12, text=str(count), fill=WHITE, font=("Arial", 9, "bold"))
                x += bw + gap
        else:
            canvas.create_text(300, 110, text="No threat data yet",
                               fill=GRAY, font=("Arial", 14))

    # ── Audit Log Page ────────────────────────────────────────────────────────
    def _build_audit_page(self):
        page = tk.Frame(self.content, bg=BG)
        self.pages["audit"] = page

        cols   = ("ID", "Timestamp", "Action", "Details")
        widths = [50, 190, 200, 500]
        tree_frame, self.audit_tree = self._styled_tree(page, cols, widths)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

    def load_audit(self):
        for row in self.audit_tree.get_children():
            self.audit_tree.delete(row)
        for log in database.get_audit_logs():
            self.audit_tree.insert("", tk.END,
                values=(log['id'], log['timestamp'], log['action'], log['details']))


# ─── App flow ─────────────────────────────────────────────────────────────────
def open_dashboard():
    global root
    root = tk.Tk()
    Dashboard(root)
    root.mainloop()

def open_login():
    global root
    root = tk.Tk()
    LoginWindow(root)
    root.mainloop()

def restart_login():
    global root
    root = tk.Tk()
    LoginWindow(root)
    root.mainloop()

if __name__ == "__main__":
    database.init_database()
    root = tk.Tk()
    if database.admin_exists():
        LoginWindow(root)
    else:
        RegisterWindow(root)
    root.mainloop()
