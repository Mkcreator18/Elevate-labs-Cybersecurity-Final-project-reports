import plotly.express as px
import pandas as pd
import sqlite3
from database import DB_FILE

def plot_traffic_summary():
    conn = sqlite3.connect(DB_FILE)
    query = "SELECT src_ip, COUNT(*) as count FROM packets GROUP BY src_ip"
    df = pd.read_sql_query(query, conn)
    conn.close()

    fig = px.bar(df, x='src_ip', y='count', title='Traffic Summary by Source IP')
    fig.show()

def plot_protocol_distribution():
    conn = sqlite3.connect(DB_FILE)
    query = "SELECT protocol, COUNT(*) as count FROM packets GROUP BY protocol"
    df = pd.read_sql_query(query, conn)
    conn.close()

    fig = px.pie(df, values='count', names='protocol', title='Protocol Distribution')
    fig.show()

if __name__ == "__main__":
    plot_traffic_summary()
    plot_protocol_distribution()
