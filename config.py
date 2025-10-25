# config.py
import os

# Get the user's home directory
HOME_DIR = os.path.expanduser("~")
DB_DIR = os.path.join(HOME_DIR, "packet_sniffer_data")

# Create the directory if it doesn't exist
if not os.path.exists(DB_DIR):
    os.makedirs(DB_DIR)

# Database and logging paths
DB_FILE = os.path.join(DB_DIR, "traffic.db")
LOG_FILE = os.path.join(DB_DIR, "alerts.log")

# Rest of your config remains the same...
EMAIL_SETTINGS = {
    "enabled": True,
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "sender_email": "s66114829@gmail.com",
    "receiver_email": "rvian220@gmail.com",
    "password": "oqhybxdkwwvliviv",
}

ALERT_THRESHOLD = {
    "port_scan": 100,
    "syn_flood": 500,
    "icmp_flood": 200,
    "udp_flood": 1000,
    "http_flood": 800,
    "unusual_protocol": True,
}

ALERT_TIME_WINDOW = 60

WHITELISTED_PROTOCOLS = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}
