import smtplib
import random
from email.mime.text import MIMEText

def generate_verification_code(length=6):
    return ''.join([str(random.randint(0, 9)) for _ in range(length)])

def send_verification_email(receiver_email, code):
    sender_email = "mynameishaxd@gmail.com"
    password = "xecd qqgq vzos qufs"

    subject = "Your Verification Code"
    body = f"Your verification code is: {code}"

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = receiver_email

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, msg.as_string())
            print("Verification email sent.")
    except Exception as e:
        print("Failed to send email:", e)


def verification ():
    user_email = input("Enter your email address: ")
    code = generate_verification_code()
    send_verification_email(user_email, code)

    user_input = input("Enter the verification code sent to your email: ")
    if user_input == code:
        print("Email verified successfully!")
        return True
    else:
        print("Invalid code. Verification failed.")
        return False