import dash
from dash import dcc, html, Input, Output
import plotly.express as px
import pandas as pd
import sqlite3
import time
import os

# Initialize Dash app
app = dash.Dash(__name__)
app.title = "Network Packet Sniffer Dashboard"

# Database path - adjust this to match your actual database location
DB_FILE = "traffic.db"  # Change this if your database is elsewhere

# Function to fetch data from SQLite
def fetch_data():
    try:
        # Check if database file exists
        if not os.path.exists(DB_FILE):
            print(f"Database file not found: {DB_FILE}")
            return pd.DataFrame()
        
        conn = sqlite3.connect(DB_FILE)
        # First check if the table exists
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='packets'")
        if not cursor.fetchone():
            print("Table 'packets' not found in database")
            conn.close()
            return pd.DataFrame()
        
        # Fetch the data
        query = "SELECT * FROM packets ORDER BY timestamp DESC LIMIT 1000"
        df = pd.read_sql_query(query, conn)
        conn.close()
        return df
    except Exception as e:
        print(f"Error fetching data: {str(e)}")
        return pd.DataFrame()

# Function to read alerts log
def read_alerts():
    try:
        alert_log_path = "alerts.log"  # Change this if your log file is elsewhere
        if not os.path.exists(alert_log_path):
            print(f"Alert log file not found: {alert_log_path}")
            return ["No alerts log found."]
        
        with open(alert_log_path, 'r') as f:
            alerts = f.readlines()[-5:]  # Show only last 5 alerts
        return alerts
    except Exception as e:
        print(f"Error reading alerts: {str(e)}")
        return ["Error reading alerts."]

# Layout
app.layout = html.Div([
    html.Div([
        html.H1("Network Packet Sniffer Dashboard", 
                style={'textAlign': 'center', 'fontSize': '24px', 'marginBottom': '20px'})
    ], style={'backgroundColor': '#2c3e50', 'padding': '10px', 'color': 'white'}),

    # Auto-refresh
    dcc.Interval(
        id='interval-component',
        interval=10*1000,  # Update every 10 seconds
        n_intervals=0
    ),

    # Debug info
    html.Div(id='debug-info', style={'display': 'none'}),

    # Statistics Cards
    html.Div([
        html.Div([
            html.H3("Total Packets", style={'fontSize': '16px', 'margin': '0'}),
            html.H4(id='total-packets', style={'fontSize': '20px', 'margin': '5px 0'})
        ], style={'width': '23%', 'display': 'inline-block', 'textAlign': 'center', 
                  'backgroundColor': '#ecf0f1', 'margin': '1%', 'padding': '10px', 
                  'borderRadius': '5px', 'boxShadow': '0 2px 4px rgba(0,0,0,0.1)'}),

        html.Div([
            html.H3("Unique IPs", style={'fontSize': '16px', 'margin': '0'}),
            html.H4(id='unique-ips', style={'fontSize': '20px', 'margin': '5px 0'})
        ], style={'width': '23%', 'display': 'inline-block', 'textAlign': 'center', 
                  'backgroundColor': '#ecf0f1', 'margin': '1%', 'padding': '10px', 
                  'borderRadius': '5px', 'boxShadow': '0 2px 4px rgba(0,0,0,0.1)'}),

        html.Div([
            html.H3("Alerts", style={'fontSize': '16px', 'margin': '0'}),
            html.H4(id='alerts-count', style={'fontSize': '20px', 'margin': '5px 0'})
        ], style={'width': '23%', 'display': 'inline-block', 'textAlign': 'center', 
                  'backgroundColor': '#ecf0f1', 'margin': '1%', 'padding': '10px', 
                  'borderRadius': '5px', 'boxShadow': '0 2px 4px rgba(0,0,0,0.1)'}),

        html.Div([
            html.H3("Last Update", style={'fontSize': '16px', 'margin': '0'}),
            html.H4(id='last-update', style={'fontSize': '14px', 'margin': '5px 0'})
        ], style={'width': '23%', 'display': 'inline-block', 'textAlign': 'center', 
                  'backgroundColor': '#ecf0f1', 'margin': '1%', 'padding': '10px', 
                  'borderRadius': '5px', 'boxShadow': '0 2px 4px rgba(0,0,0,0.1)'}),
    ], style={'margin': '10px 0'}),

    # Graphs
    html.Div([
        html.Div([
            html.H3("Traffic Over Time", style={'fontSize': '16px', 'margin': '10px 0'}),
            dcc.Graph(id='traffic-time-graph', style={'height': '300px'})
        ], style={'width': '48%', 'display': 'inline-block', 'margin': '1%'}),

        html.Div([
            html.H3("Top Source IPs", style={'fontSize': '16px', 'margin': '10px 0'}),
            dcc.Graph(id='top-ips-graph', style={'height': '300px'})
        ], style={'width': '48%', 'display': 'inline-block', 'margin': '1%'}),
    ]),

    # Recent Packets Table
    html.Div([
        html.H3("Recent Packets", style={'fontSize': '16px', 'margin': '10px 0'}),
        html.Div(id='packet-table-container', style={
            'maxHeight': '200px',
            'overflowY': 'auto',
            'border': '1px solid #ddd',
            'borderRadius': '5px'
        })
    ], style={'margin': '10px 0'}),

    # Alerts section
    html.Div([
        html.H3("Recent Alerts", style={'fontSize': '16px', 'margin': '10px 0'}),
        html.Div(id='alerts-log', style={
            'backgroundColor': '#f8f9fa',
            'padding': '10px',
            'borderRadius': '5px',
            'fontFamily': 'monospace',
            'fontSize': '12px',
            'maxHeight': '150px',
            'overflowY': 'auto'
        })
    ])
], style={'margin': '0', 'padding': '0', 'fontFamily': 'Arial, sans-serif'})

# Update callback
@app.callback(
    [Output('total-packets', 'children'),
     Output('unique-ips', 'children'),
     Output('alerts-count', 'children'),
     Output('last-update', 'children'),
     Output('traffic-time-graph', 'figure'),
     Output('top-ips-graph', 'figure'),
     Output('packet-table-container', 'children'),
     Output('alerts-log', 'children'),
     Output('debug-info', 'children')],
    Input('interval-component', 'n_intervals')
)
def update_dashboard(n):
    try:
        # Fetch data
        df = fetch_data()
        alerts = read_alerts()
        
        # Calculate statistics
        total_packets = len(df)
        unique_ips = df['src_ip'].nunique() if not df.empty else 0
        alerts_count = len(alerts)
        last_update = time.strftime("%H:%M:%S")
        
        # Debug info
        debug_info = f"Data shape: {df.shape}, Alerts: {len(alerts)}"
        
        # Create empty figures if no data
        if df.empty:
            empty_fig = {
                'data': [],
                'layout': {
                    'title': 'No data available',
                    'xaxis': {'visible': False},
                    'yaxis': {'visible': False},
                    'margin': {'l': 20, 'r': 20, 't': 40, 'b': 20}
                }
            }
            return (total_packets, unique_ips, alerts_count, last_update, 
                   empty_fig, empty_fig, ["No data available"], ["No alerts yet."], debug_info)
        
        # Traffic over time
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        time_df = df.groupby(pd.Grouper(key='timestamp', freq='5min')).size().reset_index(name='count')
        time_fig = px.line(time_df, x='timestamp', y='count', title='Traffic Over Time')
        time_fig.update_layout(
            margin={'l': 20, 'r': 20, 't': 40, 'b': 20},
            height=300
        )
        
        # Top source IPs
        ip_counts = df['src_ip'].value_counts().head(5).reset_index()
        ip_counts.columns = ['IP', 'Count']
        ip_fig = px.bar(ip_counts, x='IP', y='Count', title='Top Source IPs')
        ip_fig.update_layout(
            margin={'l': 20, 'r': 20, 't': 40, 'b': 20},
            height=300
        )
        
        # Recent packets table
        table_data = df.head(10).to_dict('records')
        table = html.Table([
            html.Thead([
                html.Tr([html.Th(col) for col in ['Time', 'Source IP', 'Dest IP', 'Protocol', 'Length']])
            ]),
            html.Tbody([
                html.Tr([
                    html.Td(str(row['timestamp'])[:19] if pd.notna(row['timestamp']) else ''),
                    html.Td(str(row['src_ip']) if pd.notna(row['src_ip']) else ''),
                    html.Td(str(row['dst_ip']) if pd.notna(row['dst_ip']) else ''),
                    html.Td(str(row['protocol']) if pd.notna(row['protocol']) else ''),
                    html.Td(str(row['length']) if pd.notna(row['length']) else '')
                ]) for row in table_data
            ])
        ], style={
            'width': '100%',
            'borderCollapse': 'collapse',
            'fontSize': '12px'
        })
        
        # Format alerts
        alerts_div = [html.P(alert[:100] + '...' if len(alert) > 100 else alert, 
                        style={'margin': '2px 0', 'padding': '2px'}) for alert in alerts]
        
        return (total_packets, unique_ips, alerts_count, last_update, 
               time_fig, ip_fig, table, alerts_div, debug_info)
    
    except Exception as e:
        print(f"Callback error: {str(e)}")
        error_fig = {
            'data': [],
            'layout': {
                'title': f'Error: {str(e)}',
                'xaxis': {'visible': False},
                'yaxis': {'visible': False}
            }
        }
        return ("Error", "Error", "Error", "Error", 
               error_fig, error_fig, ["Error loading data"], ["Error loading alerts"], 
               f"Error: {str(e)}")

if __name__ == '__main__':
    print(f"Dashboard starting...")
    print(f"Database path: {os.path.abspath(DB_FILE)}")
    print(f"Alert log path: {os.path.abspath('alerts.log')}")
    app.run(debug=True)
