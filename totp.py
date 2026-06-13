import pyotp
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

GMAIL_ADDRESS = "youremail@gmail.com"
GMAIL_APP_PASSWORD = "xxxx xxxx xxxx xxxx"  # App Password, NOT your Gmail password

def generate_secret():
    return pyotp.random_base32()

def get_otp(secret: str) -> str:
    totp = pyotp.TOTP(secret, interval=300)  # valid for 5 minutes
    return totp.now()

def verify_otp(secret: str, otp_entered: str) -> bool:
    totp = pyotp.TOTP(secret, interval=300)
    return totp.verify(otp_entered, valid_window=1)

def send_otp_email(to_email: str, otp: str):
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Your Login OTP Code"
    msg["From"] = GMAIL_ADDRESS
    msg["To"] = to_email

    html = f"""
    <div style="font-family:sans-serif; max-width:400px; margin:auto; padding:24px;
                border:1px solid #eee; border-radius:8px;">
        <h2 style="margin-bottom:8px;">Your OTP Code</h2>
        <p style="color:#555;">Use the code below to complete your login.
           It expires in <strong>5 minutes</strong>.</p>
        <div style="font-size:36px; font-weight:bold; letter-spacing:10px;
                    text-align:center; padding:20px 0; color:#1a1a1a;">
            {otp}
        </div>
        <p style="color:#999; font-size:12px;">If you didn't request this, ignore this email.</p>
    </div>
    """
    msg.attach(MIMEText(html, "html"))

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(GMAIL_ADDRESS, GMAIL_APP_PASSWORD)
        server.sendmail(GMAIL_ADDRESS, to_email, msg.as_string())