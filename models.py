from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    
    # 2FA fields
    two_factor_enabled = db.Column(db.Boolean, default=False)
    otp_secret = db.Column(db.String(32), nullable=True)
    
    # Backup codes for account recovery
    backup_codes = db.Column(db.Text, nullable=True)
    
    # Tracking
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def generate_otp_secret(self):
        """Generate a new OTP secret for the user"""
        self.otp_secret = pyotp.random_base32()
        return self.otp_secret
    
    def get_totp_uri(self):
        """Generate provisioning URI for QR code"""
        if not self.otp_secret:
            self.generate_otp_secret()
        return pyotp.totp.TOTP(self.otp_secret).provisioning_uri(
            name=self.email,
            issuer_name='Flask 2FA App'
        )
    
    def verify_totp(self, token):
        """Verify a TOTP token"""
        if not self.otp_secret:
            return False
        totp = pyotp.TOTP(self.otp_secret)
        return totp.verify(token, valid_window=1)  # Allow 1 step tolerance
    
    def generate_backup_codes(self, count=10):
        """Generate backup codes for account recovery"""
        codes = [pyotp.random_base32()[:8] for _ in range(count)]
        # Store hashed backup codes
        from werkzeug.security import generate_password_hash
        hashed_codes = [generate_password_hash(code) for code in codes]
        self.backup_codes = '|'.join(hashed_codes)
        return codes  # Return plain codes to show user once
    
    def verify_backup_code(self, code):
        """Verify and consume a backup code"""
        if not self.backup_codes:
            return False
        
        from werkzeug.security import check_password_hash
        codes = self.backup_codes.split('|')
        
        for i, hashed_code in enumerate(codes):
            if check_password_hash(hashed_code, code):
                # Remove used backup code
                codes.pop(i)
                self.backup_codes = '|'.join(codes)
                db.session.commit()
                return True
        return False