import smtplib
from email.mime.text import MIMEText
from datetime import datetime
from config import EMAIL_SETTINGS, LOG_FILE

def send_alert(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"[{timestamp}] ALERT: {message}\n"

    with open(LOG_FILE, "a") as f:
        f.write(log_message)

    if EMAIL_SETTINGS["enabled"]:
        msg = MIMEText(log_message)
        msg["Subject"] = "Network Anomaly Detected"
        msg["From"] = EMAIL_SETTINGS["sender_email"]
        msg["To"] = EMAIL_SETTINGS["receiver_email"]

        try:
            with smtplib.SMTP(EMAIL_SETTINGS["smtp_server"], EMAIL_SETTINGS["smtp_port"]) as server:
                server.starttls()
                server.login(EMAIL_SETTINGS["sender_email"], EMAIL_SETTINGS["password"])
                server.send_message(msg)
        except Exception as e:
            print(f"Failed to send email alert: {e}")
