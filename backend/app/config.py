class Config:
    SECRET_KEY = 'super-secret-key'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///app.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    BCRYPT_LOG_ROUNDS = 12
    RATE_LIMIT = "100 per hour"
    SSL_REDIRECT = True
    TOTP_WINDOW = 1  # 30-sekundowe okno
    MAX_SHARE_USERS = 15
    PASSWORD_MIN_ENTROPY = 60