import os
import time
import uuid
import random
import string
import logging

from flask import (
    Flask, render_template, request,session,redirect,
    make_response, url_for
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from captcha.image import ImageCaptcha
from captcha.audio import AudioCaptcha
import numpy as np
import cv2
import openpyxl
import requests
import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration

from pydub import AudioSegment

# ──────────────────────────────────────────────────────────────────────────────
# App & Config
# ──────────────────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'ChangeThisSecretKey')

# Sentry for error & performance monitoring
sentry_sdk.init(
    dsn=os.environ.get('SENTRY_DSN'),
    integrations=[FlaskIntegration()],
    traces_sample_rate=0.1,
    environment=os.environ.get('FLASK_ENV', 'production')
)

# HTTPS redirect + strict CSP
csp = {
    'default-src': ["'self'"],
    'script-src': ["'self'", 'https://www.google.com/recaptcha/'],
    'style-src':  ["'self'"],
    'img-src':    ["'self'", 'data:'],
    'media-src':  ["'self'"]
}
Talisman(
    app,
    content_security_policy=csp,
    force_https=True,
    strict_transport_security=True,
    strict_transport_security_max_age=31536000
)

# Rate Limiting (Redis backend via REDIS_URL)
app.config['RATELIMIT_STORAGE_URL'] = os.environ.get('REDIS_URL', 'memory://')
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["10 per minute"]
)
limiter.init_app(app)

# Google reCAPTCHA v2 keys
RECAPTCHA_SITE_KEY   = os.environ.get('RECAPTCHA_SITE_KEY', '')
RECAPTCHA_SECRET_KEY = os.environ.get('RECAPTCHA_SECRET_KEY', '')

# Excel files for session storage & logs
SESSIONS_FILE = 'sessions.xlsx'
LOG_FILE      = 'captcha_logs.xlsx'
for fname, headers in [
    (SESSIONS_FILE, ['session_id','captcha','timestamp','used']),
    (LOG_FILE,      ['timestamp','ip','event','detail'])
]:
    if not os.path.exists(fname):
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.append(headers)
        wb.save(fname)

# App-level logger
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s'
)

quotes = [
  "Trust the process, not the outcome.",
  "Even bots need a break from logic.",
  "Security is humanity’s best puzzle.",
  "Only a human reads this far."
]
ai_quote = random.choice(quotes)

# ──────────────────────────────────────────────────────────────────────────────
# Excel helpers
# ──────────────────────────────────────────────────────────────────────────────
def store_session(sid, text):
    wb = openpyxl.load_workbook(SESSIONS_FILE)
    ws = wb.active
    ws.append([sid, text, time.time(), False])
    wb.save(SESSIONS_FILE)

def get_session(sid):
    wb = openpyxl.load_workbook(SESSIONS_FILE)
    ws = wb.active
    for row in ws.iter_rows(min_row=2, values_only=True):
        if row[0] == sid:
            return {'captcha': row[1], 'timestamp': row[2], 'used': row[3]}
    return None

def mark_used(sid):
    wb = openpyxl.load_workbook(SESSIONS_FILE)
    ws = wb.active
    for row in ws.iter_rows(min_row=2):
        if row[0].value == sid:
            row[3].value = True
            break
    wb.save(SESSIONS_FILE)

def log_event(ip, event, detail=''):
    wb = openpyxl.load_workbook(LOG_FILE)
    ws = wb.active
    ws.append([time.time(), ip, event, detail])
    wb.save(LOG_FILE)
    logging.info(f"{ip} - {event}: {detail}")

# ──────────────────────────────────────────────────────────────────────────────
# Bot-pattern detection (simple blur-variance check)
# ──────────────────────────────────────────────────────────────────────────────
def is_bot_image(image_bytes):
    arr = np.frombuffer(image_bytes, np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_GRAYSCALE)
    lap = cv2.Laplacian(img, cv2.CV_64F).var()
    return lap < 50  # low variance = possible bot

# ──────────────────────────────────────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────────────────────────────────────
@app.route('/')
@limiter.limit("5 per minute")
def index():
    # 1) Generate a new session ID and puzzle
    sid = str(uuid.uuid4())
    a, b = random.randint(1, 9), random.randint(1, 9)
    puzzle_q = f"What is {a} + {b}?"
    session['puzzle_ans'] = str(a + b)
    ai_quote = random.choice([
        "Trust the process, not the outcome.",
        "Even bots need a break from logic.",
        "Security is humanity’s best puzzle.",
        "Only a human reads this far."
    ])

    # 2) Store the CAPTCHA text
    text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    store_session(sid, text)

    # 3) Generate and trim audio CAPTCHA
    os.makedirs('static', exist_ok=True)
    audio = AudioCaptcha()
    audio.write(text, f'static/{sid}.wav')
    # trim to 2 seconds (requires pydub & ffmpeg)
    sound = AudioSegment.from_wav(f'static/{sid}.wav')
    sound[:2000].export(f'static/{sid}.wav', format="wav")

    # 4) Build the response
    resp = make_response(render_template(
        'index.html',
        captcha_sid=sid,
        recaptcha_site_key=RECAPTCHA_SITE_KEY,
        puzzle_question=puzzle_q,
        ai_quote=ai_quote
    ))
    resp.set_cookie('captcha_sid', sid, max_age=300)
    return resp

@app.route('/captcha_image/<sid>')
def captcha_image(sid):
    sess = get_session(sid)
    if not sess or sess['used'] or time.time() - sess['timestamp'] > 300:
        return '', 404
    image = ImageCaptcha(width=280, height=90)
    return image.generate(sess['captcha']).read(), 200, {'Content-Type':'image/png'}

@app.route('/verify', methods=['POST'])
@limiter.limit("10 per minute")
def verify():
    ip = get_remote_address()

    # 1) Puzzle check
    user_puzzle = request.form.get('puzzle_answer', '').strip()
    if user_puzzle != session.get('puzzle_ans'):
        log_event(ip, 'puzzle_failed', f"got={user_puzzle}")
        return "❌ Puzzle incorrect", 400

    # 2) reCAPTCHA check
    recaptcha_resp = requests.post(
        'https://www.google.com/recaptcha/api/siteverify',
        data={
            'secret':   RECAPTCHA_SECRET_KEY,
            'response': request.form.get('g-recaptcha-response')
        }
    ).json()
    if not recaptcha_resp.get('success'):
        log_event(ip, 'recaptcha_failed', str(recaptcha_resp))
        return "reCAPTCHA failed", 400

    # 3) Session/CAPTCHA expiry check
    sid = request.cookies.get('captcha_sid')
    sess = get_session(sid)
    if not sess or sess['used'] or time.time() - sess['timestamp'] > 300:
        log_event(ip, 'captcha_expired', sid)
        return "Expired, reload", 400

    # 4) Bot-image detection
    file_storage = request.files.get('captcha_image')
    if file_storage and is_bot_image(file_storage.read()):
        log_event(ip, 'bot_detected', sid)
        return "Bot-like activity detected", 400

    # 5) CAPTCHA text check
    user_input = request.form.get('captcha_input', '').upper()
    if user_input == sess['captcha']:
        mark_used(sid)
        log_event(ip, 'success', sid)
        return "✅ Verified!"
    else:
        log_event(ip, 'captcha_failed', f"input={user_input}")
        return "❌ Incorrect", 400

@app.route("/generate-audio")
def generate_audio():
    text = "1234"
    sid = str(uuid.uuid4())
    audio = AudioCaptcha()

    # Make sure the static/ folder exists
    os.makedirs("static", exist_ok=True)

    # Save audio captcha
    audio.write(text, f'static/{sid}.wav')
    return f"Audio CAPTCHA saved as static/{sid}.wav"

if __name__=='__main__': app.run(host='0.0.0.0',port=5000)

