import os
import uuid
import datetime
import requests
import random
import string
import time
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, make_response
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.utils import secure_filename
import firebase_admin
from firebase_admin import credentials, db
from telebot import TeleBot

app = Flask(__name__)

app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "fallback_local_key_change_in_prod")

csrf = CSRFProtect(app)

app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(minutes=30)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["2000 per day", "500 per hour"],
    storage_uri=os.environ.get("REDIS_URL", "memory://"),
    storage_options={"socket_connect_timeout": 30},
    strategy="fixed-window"
)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
OWNER_ID = int(os.environ.get("OWNER_ID", 7480892660))

# API URL
EMAIL_API_URL = "https://khelo-gamers.vercel.app/api/"
FIREBASE_DB_URL = "https://khelo-gamers-of-bd-default-rtdb.asia-southeast1.firebasedatabase.app/"

bot = TeleBot(TOKEN) if TOKEN else None

if not firebase_admin._apps:
    try:
        private_key = os.environ.get("FIREBASE_PRIVATE_KEY")
        if private_key:
            private_key = private_key.replace('\\n', '\n')

        svi = {
            "type": "service_account",
            "project_id": "khelo-gamers-of-bd",
            "private_key_id": os.environ.get("FIREBASE_KEY_ID"),
            "private_key": private_key,
            "client_email": os.environ.get("FIREBASE_CLIENT_EMAIL"),
            "client_id": "115627786098574748067",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-fbsvc%40khelo-gamers-of-bd.iam.gserviceaccount.com",
            "universe_domain": "googleapis.com"
        }
        
        if private_key and os.environ.get("FIREBASE_CLIENT_EMAIL"):
            cred = credentials.Certificate(svi)
            firebase_admin.initialize_app(cred, {'databaseURL': FIREBASE_DB_URL})
        else:
            print("Error: Firebase credentials missing.")

    except Exception as e:
        print(f"Firebase Init Error: {e}")

def get_db(path):
    try:
        return db.reference(path).get()
    except:
        return None

def is_logged_in():
    return 'user_id' in session

def current_user():
    if not is_logged_in(): return None
    users = get_db('users')
    if not users: return None
    return users.get(session['user_id'])

def generate_otp():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

# --- EMAIL FUNCTION ---
def send_email_otp(email, otp, endpoint="vmail"):
    try:
        headers = {"User-Agent": "Mozilla/5.0", "Accept": "application/json"}
        # endpoint will be 'vmail' for signup, 'fpass' for forgot password
        response = requests.get(f"{EMAIL_API_URL}{endpoint}?to={email}&otp={otp}", headers=headers, timeout=10)
        return response.status_code == 200 and response.json().get("status") == "success"
    except:
        return False

def deduct_balance_atomic(user_uid, amount):
    user_ref = db.reference(f'users/{user_uid}/main_balance')
    
    def transaction_func(current_balance):
        if current_balance is None:
            return None
        
        current_balance = float(current_balance)
        if current_balance >= amount:
            return current_balance - amount
        else:
            raise ValueError("Insufficient Balance")

    try:
        user_ref.transaction(transaction_func)
        return True
    except firebase_admin.db.TransactionError:
        return False
    except ValueError:
        return False

@app.route('/')
def index():
    if is_logged_in(): return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    if not is_logged_in(): return redirect(url_for('auth'))
    user = current_user()
    if not user:
        session.clear()
        return redirect(url_for('auth'))
    return render_template('dashboard.html', user=user)

@app.route('/auth', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def auth():
    if request.headers.getlist("X-Forwarded-For"):
        user_ip = request.headers.getlist("X-Forwarded-For")[0]
    else:
        user_ip = request.remote_addr
    
    sanitized_ip = user_ip.replace('.', '_').replace(':', '_')
    device_id = request.cookies.get('device_id')
    if not device_id:
        device_id = str(uuid.uuid4())

    step = request.args.get('step', 'init')

    if request.method == 'POST':
        action = request.form.get('action')
        
        # --- LOGIN ---
        if action == 'login':
            login_id = request.form.get('login_id', '').strip()
            password = request.form.get('password', '').strip()
            users = get_db('users') or {}
            
            found_uid = None
            for uid, u in users.items():
                if (str(u.get('phone')) == login_id or u.get('email') == login_id) and u.get('password') == password:
                    found_uid = uid
                    break
            
            if found_uid:
                if users[found_uid].get('is_banned'):
                    flash("Account Banned.", "danger")
                else:
                    db.reference(f'users/{found_uid}/is_logged_in').set(True)
                    session['user_id'] = found_uid
                    session.permanent = True
                    
                    resp = make_response(redirect(url_for('dashboard')))
                    resp.set_cookie('device_id', device_id, max_age=315360000, secure=True, httponly=True)
                    return resp
            else:
                flash("Invalid ID or Password", "danger")

        # --- FORGOT PASSWORD INIT ---
        elif action == 'forgot_init':
            identifier = request.form.get('identifier', '').strip()
            users = get_db('users') or {}
            
            target_user = None
            target_uid = None
            
            for uid, u in users.items():
                if str(u.get('phone')) == identifier or u.get('email') == identifier:
                    target_user = u
                    target_uid = uid
                    break
            
            if target_user:
                email = target_user.get('email')
                otp = generate_otp()
                
                if send_email_otp(email, otp, endpoint="fpass"):
                    session['reset_data'] = {
                        'uid': target_uid,
                        'otp': otp,
                        'otp_time': time.time(),
                        'attempts': 0
                    }
                    flash(f"OTP sent to email ending in ***{email[-4:]}", "info")
                    return render_template('auth.html', step='forgot_verify')
                else:
                    flash("Failed to send OTP via Email.", "danger")
            else:
                flash("User not found or Email failed.", "danger")
            
            return render_template('auth.html', step='forgot_init')

        # --- FORGOT PASSWORD VERIFY ---
        elif action == 'forgot_verify':
            user_otp = request.form.get('otp', '').strip()
            new_password = request.form.get('new_password', '').strip()
            data = session.get('reset_data')

            if not data:
                flash("Session expired.", "danger")
                return redirect(url_for('auth', step='forgot_init'))

            if time.time() - data.get('otp_time', 0) > 300:
                session.pop('reset_data', None)
                flash("OTP Expired.", "danger")
                return redirect(url_for('auth', step='forgot_init'))

            if data.get('attempts', 0) >= 3:
                session.pop('reset_data', None)
                flash("Too many failed attempts.", "danger")
                return redirect(url_for('auth', step='forgot_init'))

            if str(data['otp']) == user_otp:
                uid = data['uid']
                db.reference(f'users/{uid}/password').set(new_password)
                session.pop('reset_data', None)
                flash("Password Reset Successfully! Please Login.", "success")
                return redirect(url_for('auth'))
            else:
                data['attempts'] += 1
                session['reset_data'] = data
                flash(f"Invalid OTP. Attempts left: {3 - data['attempts']}", "danger")
                return render_template('auth.html', step='forgot_verify')

        # --- SIGNUP INIT ---
        elif action == 'signup_init':
            if get_db(f'used_devices/{device_id}'):
                flash("Device Policy: Account exists.", "warning")
                return render_template('auth.html', step='init')

            existing_uid_on_ip = get_db(f'used_ips/{sanitized_ip}')
            if existing_uid_on_ip:
                flash("Registration blocked: IP Limit reached.", "danger")
                return redirect(url_for('auth'))

            name = request.form.get('name')
            phone = request.form.get('phone', '').strip()
            email = request.form.get('email', '').strip()
            
            users = get_db('users') or {}
            for u in users.values():
                if str(u.get('phone')) == phone or u.get('email') == email:
                    flash("Phone or Email already registered.", "danger")
                    return redirect(url_for('auth'))
            
            otp = generate_otp()
            if send_email_otp(email, otp, endpoint="vmail"):
                session['signup_data'] = {
                    'name': name, 'phone': phone, 'email': email, 
                    'otp': otp,
                    'otp_time': time.time(),
                    'attempts': 0
                }
                resp = make_response(render_template('auth.html', step='verify_otp'))
                resp.set_cookie('device_id', device_id, max_age=315360000, secure=True, httponly=True)
                return resp
            else:
                flash("Failed to send OTP.", "danger")

        # --- SIGNUP VERIFY ---
        elif action == 'verify_otp':
            if get_db(f'used_devices/{device_id}'):
                 flash("Error: Device already registered.", "danger")
                 return redirect(url_for('auth'))

            user_otp = request.form.get('otp', '').strip()
            password = request.form.get('password')
            data = session.get('signup_data')
            
            if not data:
                flash("Session expired.", "danger"); return redirect(url_for('auth'))
            
            if time.time() - data.get('otp_time', 0) > 300:
                session.pop('signup_data', None)
                flash("OTP Expired.", "danger"); return redirect(url_for('auth'))

            if data.get('attempts', 0) >= 3:
                session.pop('signup_data', None)
                flash("Too many failed attempts.", "danger"); return redirect(url_for('auth'))

            if str(data['otp']) == user_otp:
                new_uid = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
                
                new_user = {
                    "userid": new_uid,
                    "name": data.get('name', 'New User'),
                    "phone": data['phone'],
                    "email": data['email'],
                    "password": password,
                    "main_balance": 0.0,
                    "winning_balance": 0.0,
                    "role": "U",
                    "joined_matches": [],
                    "is_banned": False,
                    "is_logged_in": True,
                    "device_id": device_id,
                    "signup_ip": user_ip
                }
                
                db.reference(f'users/{new_uid}').set(new_user)
                db.reference(f'used_devices/{device_id}').set(new_uid)
                db.reference(f'used_ips/{sanitized_ip}').set(new_uid)

                if bot:
                    try:
                        msg = (f"👤 NEW USER\nName: {new_user['name']}\nUID: {new_uid}")
                        bot.send_message(OWNER_ID, msg)
                    except: pass
                
                session['user_id'] = new_uid
                session.pop('signup_data', None)
                
                resp = make_response(redirect(url_for('dashboard')))
                return resp
            else:
                data['attempts'] += 1
                session['signup_data'] = data
                flash(f"Invalid OTP. Attempts left: {3 - data['attempts']}", "danger")
                return render_template('auth.html', step='verify_otp')

    return render_template('auth.html', step=step)

@app.route('/logout')
def logout():
    if is_logged_in():
        uid = session['user_id']
        db.reference(f'users/{uid}/is_logged_in').set(False)
    session.clear()
    return redirect(url_for('index'))

@app.route('/matches')
def matches_hub():
    if not is_logged_in(): return redirect(url_for('auth'))
    all_matches = get_db('matches') or {}
    counts = {
        'BR': 0,
        'CS': 0,
        'LW': 0
    }
    for m in all_matches.values():
        if m.get('status') == 'upcoming':
            m_type = m.get('type', '').upper()
            if m_type in counts:
                counts[m_type] += 1
    return render_template('matches.html', counts=counts)

@app.route('/matches/<m_type>')
def matches_list(m_type):
    if not is_logged_in(): return redirect(url_for('auth'))
    
    all_matches = get_db('matches') or {}
    filtered = {}
    user_id = session['user_id']
    
    sorted_items = sorted(all_matches.items(), key=lambda x: x[1].get('time', ''), reverse=True)
    
    for mid, m in sorted_items:
        current_count = 0
        participants = m.get('participants', [])
        
        if isinstance(participants, list):
            for p in participants: 
                if p: current_count += len(p.get('players', []))
        elif isinstance(participants, dict):
            for p in participants.values(): 
                if p: current_count += len(p.get('players', []))
        
        m['filled_slots'] = current_count

        if m_type == 'joined':
            joined_list = m.get('joined', [])
            if isinstance(joined_list, dict): joined_list = list(joined_list.values())
            if user_id in joined_list: filtered[mid] = m
        elif m.get('type') == m_type.upper() and m.get('status') == 'upcoming': 
            filtered[mid] = m
            
    # --- UPDATED TEMPLATE MAP FOR LONE WOLF (LW) ---
    template_map = {
        'br': 'matches/brmatches.html', 
        'cs': 'matches/csmatches.html', 
        'lw': 'matches/lwmatches.html', # Added LW here
        'joined': 'matches/myjoinedmatch.html'
    }
    
    return render_template(template_map.get(m_type, 'matches.html'), matches=filtered)

@app.route('/match/join/<mid>', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def join_match(mid):
    if not is_logged_in(): return redirect(url_for('auth'))
    user_id = session['user_id']
    match = get_db(f'matches/{mid}')
    
    if not match or match['status'] != 'upcoming':
        flash("Match unavailable.", "danger"); return redirect(url_for('matches_hub'))
    
    joined_list = match.get('joined', [])
    if isinstance(joined_list, dict): joined_list = list(joined_list.values())
    if user_id in joined_list:
        flash("Already joined.", "warning"); return redirect(url_for('matches_list', m_type='joined'))
    
    current_count = 0
    participants = match.get('participants', [])
    if isinstance(participants, list):
        for p in participants: 
            if p: current_count += len(p.get('players', []))
    elif isinstance(participants, dict):
        for p in participants.values(): 
            if p: current_count += len(p.get('players', []))
    slots_left = match['limit'] - current_count

    if request.method == 'POST':
        try:
            player_count = int(request.form.get('player_count'))
            if player_count < 1:
                flash("Minimum 1 player required.", "danger"); return redirect(url_for('join_match', mid=mid))
            
            # --- VALIDATION FOR LONE WOLF ---
            if match.get('type') == 'LW' and player_count > 2:
                flash("Lone Wolf is restricted to Solo or Duo only.", "danger")
                return redirect(url_for('join_match', mid=mid))
            # -------------------------------

        except ValueError:
            flash("Invalid number.", "danger"); return redirect(url_for('join_match', mid=mid))

        player_names = request.form.getlist('player_name[]')
        player_uids = request.form.getlist('player_uid[]')
        total_fee = match['fee'] * player_count
        
        if player_count > slots_left:
             flash("Not enough slots.", "danger"); return redirect(url_for('join_match', mid=mid))
        
        if deduct_balance_atomic(user_id, total_fee):
            if user_id not in joined_list:
                joined_list.append(user_id)
                db.reference(f'matches/{mid}/joined').set(joined_list)
            
            u_joined = get_db(f'users/{user_id}/joined_matches') or []
            if isinstance(u_joined, dict): u_joined = list(u_joined.values())
            if mid not in u_joined:
                u_joined.append(mid)
                db.reference(f'users/{user_id}/joined_matches').set(u_joined)
            
            players_data = []
            for i in range(player_count):
                players_data.append({"game_uid": player_uids[i], "game_name": player_names[i], "added_by": user_id, "type": "fixed"})
            
            new_participant = {"userid": user_id, "team_type": match.get('team_type', 'SOLO'), "players": players_data}
            
            fresh_participants = get_db(f'matches/{mid}/participants') or []
            next_idx = len(fresh_participants) if isinstance(fresh_participants, list) else len(fresh_participants.keys())
            db.reference(f'matches/{mid}/participants/{next_idx}').set(new_participant)
            
            flash("Joined Successfully!", "success"); return redirect(url_for('matches_list', m_type='joined'))
        else:
            flash("Insufficient Balance or Transaction Error.", "danger")
            return redirect(url_for('join_match', mid=mid))

    return render_template('matches/joinmatch.html', match=match, slots=slots_left)

@app.route('/wallet')
def wallet(): return render_template('wallet.html', user=current_user())

@app.route('/wallet/deposit', methods=['GET', 'POST'])
@limiter.limit("5 per hour")
def deposit():
    if not is_logged_in(): return redirect(url_for('auth'))
    settings = get_db('settings')
    if request.method == 'POST':
        method = request.form.get('method'); sender = request.form.get('sender'); trx_id = request.form.get('trx_id')
        
        try:
            amount = float(request.form.get('amount'))
            if amount <= 0:
                flash("Amount must be positive.", "danger"); return redirect(url_for('deposit'))
        except ValueError:
             flash("Invalid amount.", "danger"); return redirect(url_for('deposit'))

        if amount < 10: flash("Minimum deposit 10.", "danger"); return redirect(url_for('deposit'))

        txns = get_db('transactions') or {}
        for t in txns.values():
            if t.get('trx_id') == trx_id: flash("TrxID used.", "danger"); return redirect(url_for('deposit'))
            
        tid = str(uuid.uuid4())[:8]
        data = {"id": tid, "userid": session['user_id'], "type": "deposit", "method": method, "amount": amount, "sender": sender, "trx_id": trx_id, "status": "pending", "time": str(datetime.datetime.now())}
        db.reference(f'transactions/{tid}').set(data)

        if bot:
            try: bot.send_message(OWNER_ID, f"🔔 Deposit: {amount} by {session['user_id']}")
            except: pass

        flash("Deposit submitted.", "success"); return redirect(url_for('wallet'))
    return render_template('wallet/deposit.html', settings=settings)

@app.route('/wallet/withdraw', methods=['GET', 'POST'])
@limiter.limit("3 per hour")
def withdraw():
    if not is_logged_in(): return redirect(url_for('auth'))
    settings = get_db('settings')
    user = current_user()
    if request.method == 'POST':
        method = request.form.get('method'); number = request.form.get('number')
        
        try:
            amount = float(request.form.get('amount'))
            if amount <= 0:
                 flash("Amount must be positive.", "danger"); return redirect(url_for('withdraw'))
        except ValueError:
            flash("Invalid amount.", "danger"); return redirect(url_for('withdraw'))

        min_wd = float(settings.get('min_withdraw', 100))
        
        if amount < min_wd: flash(f"Min withdraw {min_wd}", "danger")
        elif user['winning_balance'] < amount: flash("Insufficient Winning Balance", "danger")
        else:
            new_bal = user['winning_balance'] - amount
            db.reference(f'users/{session["user_id"]}/winning_balance').set(new_bal)
            
            tid = str(uuid.uuid4())[:8]
            data = {"id": tid, "userid": session['user_id'], "type": "withdraw", "method": method, "amount": amount, "number": number, "status": "pending", "time": str(datetime.datetime.now())}
            db.reference(f'transactions/{tid}').set(data)

            if bot:
                try: bot.send_message(OWNER_ID, f"🔔 Withdraw: {amount} by {session['user_id']}")
                except: pass

            flash("Withdraw submitted.", "success"); return redirect(url_for('wallet'))
    return render_template('wallet/withdraw.html', settings=settings, user=user)

@app.route('/wallet/convert', methods=['GET', 'POST'])
def convert():
    if not is_logged_in(): return redirect(url_for('auth'))
    user = current_user()
    if request.method == 'POST':
        try:
            amount = float(request.form.get('amount'))
            if amount <= 0:
                flash("Amount must be positive.", "danger"); return redirect(url_for('wallet'))
        except ValueError:
            flash("Invalid amount.", "danger"); return redirect(url_for('wallet'))

        if user['winning_balance'] >= amount:
            db.reference(f'users/{session["user_id"]}').update({
                'winning_balance': user['winning_balance'] - amount, 
                'main_balance': user['main_balance'] + amount
            })
            flash("Converted!", "success"); return redirect(url_for('wallet'))
        else: flash("Insufficient Winning Balance.", "danger")
    return render_template('wallet/convert.html', user=user)

@app.route('/wallet/transactions')
def transactions():
    if not is_logged_in(): return redirect(url_for('auth'))
    all_txns = get_db('transactions') or {}
    uid = session['user_id']
    my_txns = [t for t in all_txns.values() if str(t.get('userid')) == str(uid)]
    my_txns.sort(key=lambda x: x['time'], reverse=True)
    return render_template('wallet/mytransection.html', transactions=my_txns)

@app.route('/profile')
def profile(): return render_template('myprofile.html', user=current_user())

@app.route('/profile/edit/<field>', methods=['GET', 'POST'])
@limiter.limit("10 per hour")
def edit_profile(field):
    if not is_logged_in(): return redirect(url_for('auth'))
    uid = session['user_id']
    ALLOWED_FIELDS = ['name', 'email', 'phone', 'password']
    
    if field not in ALLOWED_FIELDS:
        flash("Invalid field.", "danger"); return redirect(url_for('profile'))
    
    if request.method == 'POST':
        value = request.form.get('value', '').strip()
        
        if field in ['email', 'phone']:
            users = get_db('users') or {}
            for other_uid, u in users.items():
                if other_uid != uid and str(u.get(field)) == value:
                    flash(f"{field} taken.", "danger"); return redirect(url_for('edit_profile', field=field))

        if field == 'password':
            old_pass = request.form.get('old_password')
            user = current_user()
            if not user or user.get('password') != old_pass: 
                flash("Wrong old password.", "danger")
                return redirect(url_for('edit_profile', field=field))
            db.reference(f'users/{uid}/password').set(value)
        else: 
            db.reference(f'users/{uid}/{field}').set(value)
            
        flash("Updated.", "success")
        return redirect(url_for('profile'))
        
    template_map = {'name': 'myprofile/editname.html', 'email': 'myprofile/editemail.html', 'phone': 'myprofile/editphone.html', 'password': 'myprofile/editpassword.html'}
    return render_template(template_map.get(field), user=current_user())

@app.route('/upload_proof', methods=['GET', 'POST'])
@limiter.limit("10 per hour")
def upload_proof():
    if not is_logged_in(): return redirect(url_for('auth'))
    if request.method == 'POST':
        mid = request.form.get('match_id')
        rid = request.form.get('room_id')
        file = request.files.get('proof_image')
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            if bot:
                caption = f"📸 PROOF\nUser: {session['user_id']}\nMatch: {mid}\nRoom: {rid}"
                try: bot.send_photo(OWNER_ID, file.read(), caption=caption); flash("Proof sent.", "success")
                except Exception as e: flash(f"Error: {e}", "danger")
            else:
                 flash("Bot not configured.", "warning")
        else:
            flash("Invalid file type (png, jpg only).", "danger")

        return redirect(url_for('dashboard'))
    return render_template('uploadproof.html')

@app.route('/uid_lookup')
@limiter.limit("20 per hour")
def uid_lookup():
    uid = request.args.get('uid'); result = None
    if uid:
        try:
            resp = requests.get(f"https://info-of-ff.vercel.app/info?uid={uid}&region=BD&key=TOC", timeout=5)
            if resp.status_code == 200: result = resp.json().get('AccountInfo')
        except: pass
    return render_template('uidlookup.html', result=result, searched_uid=uid)

@app.route('/leaderboard')
def leaderboard():
    users = get_db('users') or {}
    sorted_users = sorted(users.values(), key=lambda u: u.get('winning_balance', 0), reverse=True)
    return render_template('leaderboard.html', top_users=sorted_users[:10])

@app.route('/rules')
def rules_hub(): return render_template('rules.html')

@app.route('/rules/<rtype>')
def rules_detail(rtype):
    rules_data = get_db('rules') or {}
    # Handles lwrules.html automatically based on rtype='lw'
    return render_template(f'rules/{rtype}rules.html', content=rules_data.get(rtype.upper(), "No rules set."))

@app.route('/support')
def support(): return render_template('support.html')

@app.errorhandler(413)
def request_entity_too_large(error):
    flash("File too large! Max 5MB.", "danger")
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)


