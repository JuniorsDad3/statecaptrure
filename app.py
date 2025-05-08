from flask import Flask, render_template, request, session, make_response, url_for, redirect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from captcha.image import ImageCaptcha
from captcha.audio import AudioCaptcha
import random, string, time, uuid, logging, cv2, numpy as np, openpyxl, os, requests

import sentry_sdk
from sentry_sdk.integrations.flask import FlaskIntegration

# Configuration
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'ChangeThisSecretKey')

sentry_sdk.init(
    dsn=os.environ.get('SENTRY_DSN'),
    integrations=[FlaskIntegration()],
    traces_sample_rate=0.1,
    environment=os.environ.get('FLASK_ENV', 'production')
)

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

# Rate Limiting
limiter = Limiter(app, key_func=get_remote_address, default_limits=["10 per minute"])

# Google reCAPTCHA v2
RECAPTCHA_SITE_KEY = os.environ.get('RECAPTCHA_SITE_KEY', 'your_site_key')
RECAPTCHA_SECRET_KEY = os.environ.get('RECAPTCHA_SECRET_KEY', 'your_secret_key')

# Excel session & log files
SESSIONS_FILE = 'sessions.xlsx'
LOG_FILE = 'captcha_logs.xlsx'
for fname, headers in [(SESSIONS_FILE, ['session_id','captcha','timestamp','used']),
                       (LOG_FILE, ['timestamp','ip','event','detail'])]:
    if not os.path.exists(fname):
        wb = openpyxl.Workbook(); ws = wb.active; ws.append(headers); wb.save(fname)

# Logging
logging.basicConfig(filename='app.log', level=logging.INFO,
                    format='%(asctime)s %(levelname)s: %(message)s')

# Excel helpers
def store_session(sid, text):
    wb, ws = openpyxl.load_workbook(SESSIONS_FILE), openpyxl.load_workbook(SESSIONS_FILE).active
    ws.append([sid, text, time.time(), False]); wb.save(SESSIONS_FILE)

def get_session(sid):
    wb, ws = openpyxl.load_workbook(SESSIONS_FILE), openpyxl.load_workbook(SESSIONS_FILE).active
    for row in ws.iter_rows(min_row=2, values_only=True):
        if row[0]==sid: return {'captcha':row[1],'timestamp':row[2],'used':row[3]}
    return None

def mark_used(sid):
    wb, ws = openpyxl.load_workbook(SESSIONS_FILE), openpyxl.load_workbook(SESSIONS_FILE).active
    for row in ws.iter_rows(min_row=2):
        if row[0].value==sid: row[3].value=True; break
    wb.save(SESSIONS_FILE)

def log_event(ip, event, detail=''):
    wb, ws = openpyxl.load_workbook(LOG_FILE), openpyxl.load_workbook(LOG_FILE).active
    ws.append([time.time(), ip, event, detail]); wb.save(LOG_FILE)
    logging.info(f"{ip} - {event}: {detail}")

# Bot-pattern detection using OpenCV (simple motion blur detection)
def is_bot_image(image_bytes):
    arr = np.frombuffer(image_bytes, np.uint8)
    img = cv2.imdecode(arr, cv2.IMREAD_GRAYSCALE)
    lap = cv2.Laplacian(img, cv2.CV_64F).var()
    # low variance => likely bot-generated blur
    return lap < 50

# Routes
@app.route('/')
@limiter.limit("5 per minute")
def index():
    sid = str(uuid.uuid4())
    text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    store_session(sid, text)

    # Generate CAPTCHA image & audio
    image = ImageCaptcha(width=280, height=90)
    img_data = image.generate(text)
    audio = AudioCaptcha(); audio.generate(text).save(f'static/{sid}.wav')

    resp = make_response(render_template('index.html',
                                         captcha_sid=sid,
                                         recaptcha_site_key=RECAPTCHA_SITE_KEY))
    resp.set_cookie('captcha_sid', sid, max_age=300)
    return resp

@app.route('/captcha_image/<sid>')
def captcha_image(sid):
    sess = get_session(sid)
    if not sess or sess['used'] or time.time()-sess['timestamp']>300:
        return '', 404
    image = ImageCaptcha(width=280, height=90)
    return image.generate(sess['captcha']).read(), 200, {'Content-Type':'image/png'}

@app.route('/verify', methods=['POST'])
@limiter.limit("10 per minute")
def verify():
    sid = request.cookies.get('captcha_sid')
    user_input = request.form.get('captcha_input','').upper()
    recaptcha_resp = requests.post(
        'https://www.google.com/recaptcha/api/siteverify',
        data={'secret': RECAPTCHA_SECRET_KEY, 'response': request.form.get('g-recaptcha-response')}
    ).json()
    ip = get_remote_address()
    if not recaptcha_resp.get('success'):
        log_event(ip,'recaptcha_failed',str(recaptcha_resp))
        return "reCAPTCHA failed", 400
    sess = get_session(sid)
    if not sess or sess['used'] or time.time()-sess['timestamp']>300:
        log_event(ip,'captcha_expired',sid)
        return "Expired, reload", 400
    # Bot detection example
    if is_bot_image(request.files['captcha_image'].read()):
        log_event(ip,'bot_detected',sid)
        return "Bot-like activity detected", 400
    if user_input==sess['captcha']:
        mark_used(sid); log_event(ip,'success',sid)
        return "Verified!"
    log_event(ip,'captcha_failed',f"input={user_input}")
    return "Incorrect", 400

if __name__=='__main__': app.run(host='0.0.0.0',port=5000)
``` 

