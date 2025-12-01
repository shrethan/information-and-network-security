from flask import Flask, render_template, redirect, url_for, flash, session, request
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from config import Config
from models import db, User
from forms import RegistrationForm, LoginForm, TwoFactorForm
import qrcode
import io
import base64
from datetime import datetime

app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create database tables
with app.app_context():
    db.create_all()

@app.route('/')
def index():
    return redirect(url_for('dashboard') if current_user.is_authenticated else url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data
        )
        user.set_password(form.password.data)
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user and user.check_password(form.password.data):
            # Check if 2FA is enabled
            if user.two_factor_enabled:
                # Store user id in session temporarily
                session['pre_2fa_user_id'] = user.id
                session['remember_me'] = form.remember_me.data
                return redirect(url_for('verify_2fa'))
            else:
                # Login directly without 2FA
                login_user(user, remember=form.remember_me.data)
                user.last_login = datetime.utcnow()
                db.session.commit()
                flash('Login successful!', 'success')
                
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html', form=form)

@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    # Check if user has passed first authentication
    if 'pre_2fa_user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    
    user = User.query.get(session['pre_2fa_user_id'])
    if not user:
        session.pop('pre_2fa_user_id', None)
        return redirect(url_for('login'))
    
    form = TwoFactorForm()
    if form.validate_on_submit():
        token = form.token.data
        
        # Check if using backup code
        if form.use_backup_code.data:
            if user.verify_backup_code(token):
                # Complete login
                complete_2fa_login(user)
                flash('Login successful using backup code!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid backup code', 'danger')
        else:
            # Verify TOTP token
            if user.verify_totp(token):
                # Complete login
                complete_2fa_login(user)
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid authentication code', 'danger')
    
    return render_template('verify_2fa.html', form=form)

def complete_2fa_login(user):
    """Complete the 2FA login process"""
    remember = session.pop('remember_me', False)
    session.pop('pre_2fa_user_id', None)
    login_user(user, remember=remember)
    user.last_login = datetime.utcnow()
    db.session.commit()

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/setup-2fa')
@login_required
def setup_2fa():
    if current_user.two_factor_enabled:
        flash('2FA is already enabled', 'info')
        return redirect(url_for('dashboard'))
    
    # Generate OTP secret and QR code
    current_user.generate_otp_secret()
    db.session.commit()
    
    # Generate QR code
    uri = current_user.get_totp_uri()
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to base64 for display
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    qr_code = base64.b64encode(buffer.getvalue()).decode()
    
    return render_template('setup_2fa.html', 
                         qr_code=qr_code, 
                         secret=current_user.otp_secret)

@app.route('/confirm-2fa', methods=['POST'])
@login_required
def confirm_2fa():
    token = request.form.get('token')
    
    if current_user.verify_totp(token):
        current_user.two_factor_enabled = True
        
        # Generate backup codes
        backup_codes = current_user.generate_backup_codes()
        db.session.commit()
        
        flash('2FA has been successfully enabled!', 'success')
        return render_template('backup_codes.html', codes=backup_codes)
    else:
        flash('Invalid code. Please try again.', 'danger')
        return redirect(url_for('setup_2fa'))

@app.route('/disable-2fa', methods=['GET', 'POST'])
@login_required
def disable_2fa():
    if not current_user.two_factor_enabled:
        flash('2FA is not enabled', 'info')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        token = request.form.get('token')
        
        if current_user.check_password(password) and current_user.verify_totp(token):
            current_user.two_factor_enabled = False
            current_user.otp_secret = None
            current_user.backup_codes = None
            db.session.commit()
            
            flash('2FA has been disabled', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid password or authentication code', 'danger')
    
    return render_template('disable_2fa.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True) 