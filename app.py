from flask import Flask, render_template
import pandas as pd
import dash
from dash import dcc, html
from dash.dependencies import Input, Output, State
import plotly.express as px
from sklearn.ensemble import IsolationForest
import os
import random
from datetime import datetime, timedelta
import threading
import time

app = dash.Dash(__name__)
server = app.server

app.layout = html.Div(style={'background': 'linear-gradient(to right, #ffffff, #f0f8ff)'}, children=[
    html.Div([
        html.H1("📊 Network Packet Analyzer - Simulation Mode", 
                style={'fontFamily': 'Arial, sans-serif', 'color': '#333333', 'textAlign': 'center'}),
        html.Div("🔬 AUTO-SIMULATION MODE: Automatically generating network traffic data", 
                style={'textAlign': 'center', 'color': '#666', 'marginBottom': '20px'})
    ]),
    
    html.Div([
        html.Button('⏹️ Stop Simulation', id='stop-simulation', n_clicks=0, 
                   style={'backgroundColor': '#dc3545', 'color': 'white', 'margin': '5px'}),
        html.Button('🔄 Reset Simulation', id='reset-simulation', n_clicks=0, 
                   style={'backgroundColor': '#ffc107', 'color': 'black', 'margin': '5px'}),
        html.Span(id='simulation-status', children='Status: 🟢 Auto-Running', 
                 style={'marginLeft': '20px', 'fontWeight': 'bold', 'color': '#28a745'})
    ], style={'textAlign': 'center', 'padding': '10px', 'backgroundColor': '#f8f9fa', 'borderRadius': '5px'}),
    
    dcc.Graph(id='live-update-plot'),
    
    html.Div([
        dcc.Input(id='source-ip-input', type='text', placeholder='Enter Source IP', 
                 style={'marginRight': '10px', 'padding': '8px'}),
        dcc.Input(id='destination-ip-input', type='text', placeholder='Enter Destination IP', 
                 style={'marginRight': '10px', 'padding': '8px'}),
        dcc.Dropdown(
            id='protocol-dropdown',
            options=[
                {'label': 'ICMP', 'value': 1},
                {'label': 'TCP', 'value': 6},
                {'label': 'UDP', 'value': 17},
                {'label': 'All Protocols', 'value': 'all'}
            ],
            placeholder='Select Protocol',
            style={'marginRight': '10px', 'width': '200px'}
        ),
        html.Button('Apply Filters', id='apply-filters-btn', n_clicks=0, 
                   style={'backgroundColor': '#007bff', 'color': '#ffffff', 'padding': '8px 15px'})
    ], style={'margin': '20px 0', 'textAlign': 'center'}),
    
    html.Div([
        html.Div([
            html.P(id='traffic-volume', style={'fontFamily': 'Arial, sans-serif', 'color': '#333333', 
                                             'fontSize': '16px', 'fontWeight': 'bold'}),
            html.P(id='average-packet-size', style={'fontFamily': 'Arial, sans-serif', 'color': '#333333',
                                                  'fontSize': '16px', 'fontWeight': 'bold'}),
            html.P(id='abnormal-packets', style={'fontFamily': 'Arial, sans-serif', 'color': '#333333',
                                               'fontSize': '16px', 'fontWeight': 'bold'}),
            html.P(id='protocol-counts', style={'fontFamily': 'Arial, sans-serif', 'color': '#333333',
                                              'fontSize': '16px', 'fontWeight': 'bold'}),
            html.P(id='anomaly-packet-count', style={'fontFamily': 'Arial, sans-serif', 'color': '#333333',
                                                   'fontSize': '16px', 'fontWeight': 'bold'})
        ], style={'backgroundColor': '#e9ecef', 'padding': '15px', 'borderRadius': '5px', 'margin': '10px'})
    ]),
    
    dcc.Interval(
        id='interval-component',
        interval=2*1000,
        n_intervals=0
    ),
    
    dcc.Store(id='simulation-state', data={'running': True, 'packet_count': 0}),
    dcc.Store(id='packet-data-store', data=[])
])

packet_data = []
simulation_running = True

class PacketSimulator:
    def __init__(self):
        self.protocols = [1, 6, 17]
        self.protocol_names = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        
        self.source_ips = [
            '192.168.1.' + str(i) for i in range(1, 50)
        ] + [
            '10.0.0.' + str(i) for i in range(1, 20)
        ]
        
        self.dest_ips = [
            '8.8.8.8', '8.8.4.4', '1.1.1.1',
            '142.251.42.206', '151.101.1.69',
            '13.107.42.14', '204.79.197.203',
            '185.199.108.153', '140.82.121.3',
            '52.114.128.66', '13.107.246.40'
        ]
        
        self.packet_sizes = [64, 128, 256, 512, 1024, 1500]
        self.ports = [80, 443, 53, 22, 25, 110, 993, 995, 143, 21, 8080, 8443]

    def generate_packet_batch(self, count=5):
        packets = []
        current_time = datetime.now()
        
        for i in range(count):
            if random.random() < 0.3:
                protocol = 6
                dest_port = random.choice([80, 443, 8080, 8443])
                size = random.choice([512, 1024, 1500])
            elif random.random() < 0.5:
                protocol = 17
                dest_port = 53
                size = random.choice([64, 128, 256])
            else:
                protocol = random.choice(self.protocols)
                dest_port = random.choice(self.ports)
                size = random.choice(self.packet_sizes)
            
            is_anomalous = random.random() < 0.05
            if is_anomalous:
                size = random.choice([5000, 8000, 10000])
                protocol = random.choice(self.protocols)
            
            packet = {
                'timestamp': current_time.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                'source_ip': random.choice(self.source_ips),
                'destination_ip': random.choice(self.dest_ips),
                'protocol': protocol,
                'protocol_name': self.protocol_names.get(protocol, 'Unknown'),
                'packet_size': size,
                'source_port': random.randint(10000, 65535),
                'destination_port': dest_port,
                'is_anomalous': is_anomalous,
                'packet_payload': f"Simulated payload for {self.protocol_names.get(protocol, 'Unknown')} packet"
            }
            packets.append(packet)
        
        return packets

packet_simulator = PacketSimulator()

def simulation_worker():
    global packet_data, simulation_running
    
    while True:
        if simulation_running:
            new_packets = packet_simulator.generate_packet_batch(random.randint(3, 8))
            packet_data.extend(new_packets)
            
            if len(packet_data) > 1000:
                packet_data = packet_data[-1000:]
        
        time.sleep(1)

simulation_thread = threading.Thread(target=simulation_worker)
simulation_thread.daemon = True
simulation_thread.start()

def detect_anomalies(df):
    try:
        if len(df) < 2:
            return df[df['packet_size'] > 0], pd.DataFrame()
        
        X = df[['packet_size', 'protocol']]
        isolation_forest = IsolationForest(contamination=0.05, random_state=42)
        isolation_forest.fit(X)
        df['anomaly'] = isolation_forest.predict(X)
        normal_packets = df[df['anomaly'] == 1]
        abnormal_packets = df[df['anomaly'] == -1]
        return normal_packets, abnormal_packets
    except Exception as e:
        print(f"Error in anomaly detection: {e}")
        return df, pd.DataFrame()

def perform_analysis_and_detection(df):
    try:
        if df.empty:
            return 0, 0, 0, "No data available", 0
        
        traffic_volume = len(df)
        average_packet_size = df['packet_size'].mean()
        
        if len(df) > 1:
            df['packet_size_zscore'] = (df['packet_size'] - df['packet_size'].mean()) / df['packet_size'].std()
            abnormal_packets_count = len(df[abs(df['packet_size_zscore']) > 3])
        else:
            abnormal_packets_count = 0
        
        protocol_counts = df['protocol_name'].value_counts().to_dict()
        protocol_counts_str = " | ".join([f"{protocol}: {count}" for protocol, count in protocol_counts.items()])
        
        anomaly_count = len(df[df['is_anomalous'] == True]) if 'is_anomalous' in df.columns else 0
        
        return traffic_volume, average_packet_size, abnormal_packets_count, protocol_counts_str, anomaly_count
    except Exception as e:
        print(f"Error in analysis: {e}")
        return 0, 0, 0, "Error in analysis", 0

@app.callback(
    [Output('simulation-state', 'data'),
     Output('simulation-status', 'children')],
    [Input('stop-simulation', 'n_clicks'),
     Input('reset-simulation', 'n_clicks')],
    [State('simulation-state', 'data')]
)
def control_simulation(stop_clicks, reset_clicks, state):
    global simulation_running, packet_data
    
    ctx = dash.callback_context
    if not ctx.triggered:
        return state, 'Status: 🟢 Auto-Running'
    
    button_id = ctx.triggered[0]['prop_id'].split('.')[0]
    
    if button_id == 'stop-simulation' and stop_clicks > 0:
        simulation_running = False
        new_state = {'running': False, 'packet_count': len(packet_data)}
        return new_state, 'Status: 🔴 Stopped'
    
    elif button_id == 'reset-simulation' and reset_clicks > 0:
        packet_data.clear()
        simulation_running = True
        new_state = {'running': True, 'packet_count': 0}
        return new_state, 'Status: 🟢 Auto-Running'
    
    return state, 'Status: 🟢 Auto-Running'

@app.callback(
    [Output('traffic-volume', 'children'),
     Output('average-packet-size', 'children'),
     Output('abnormal-packets', 'children'),
     Output('protocol-counts', 'children'),
     Output('anomaly-packet-count', 'children'),
     Output('live-update-plot', 'figure')],
    [Input('apply-filters-btn', 'n_clicks'),
     Input('interval-component', 'n_intervals')],
    [State('source-ip-input', 'value'),
     State('destination-ip-input', 'value'),
     State('protocol-dropdown', 'value'),
     State('simulation-state', 'data')]
)
def update_dashboard(n_clicks, n_intervals, source_ip, destination_ip, protocol, sim_state):
    global packet_data
    
    try:
        if packet_data:
            packet_df = pd.DataFrame(packet_data)
            
            if n_clicks > 0:
                if source_ip:
                    packet_df = packet_df[packet_df['source_ip'] == source_ip]
                if destination_ip:
                    packet_df = packet_df[packet_df['destination_ip'] == destination_ip]
                if protocol and protocol != 'all':
                    packet_df = packet_df[packet_df['protocol'] == protocol]
            
            traffic_volume, avg_size, abnormal_count, protocol_str, anomaly_count = perform_analysis_and_detection(packet_df)
            
            if not packet_df.empty:
                packet_df['time_index'] = range(len(packet_df))
                
                fig = px.scatter(
                    packet_df, 
                    x='time_index', 
                    y='packet_size', 
                    color='protocol_name',
                    title=f"Packet Size Distribution (Total: {len(packet_df)} packets)",
                    labels={'time_index': 'Packet Sequence', 'packet_size': 'Packet Size (bytes)'},
                    hover_data=['source_ip', 'destination_ip', 'protocol_name']
                )
                fig.update_layout(showlegend=True)
            else:
                fig = px.scatter(title="No data available")
            
            return (f"📊 Traffic Volume: {traffic_volume} packets",
                   f"📦 Average Packet Size: {avg_size:.2f} bytes",
                   f"⚠️ Abnormal Packets (Z-score > 3): {abnormal_count}",
                   f"🔧 Protocols: {protocol_str}",
                   f"🚨 Anomalous Packets: {anomaly_count}",
                   fig)
        else:
            empty_fig = px.scatter(title="Generating packet data...")
            return ("📊 Traffic Volume: 0 packets",
                   "📦 Average Packet Size: 0 bytes",
                   "⚠️ Abnormal Packets: 0",
                   "🔧 Protocols: None",
                   "🚨 Anomalous Packets: 0",
                   empty_fig)
    
    except Exception as e:
        print(f"Error in dashboard update: {e}")
        empty_fig = px.scatter(title="Error loading data")
        return ("📊 Traffic Volume: Error",
               "📦 Average Packet Size: Error",
               "⚠️ Abnormal Packets: Error",
               "🔧 Protocols: Error",
               "🚨 Anomalous Packets: Error",
               empty_fig)

@app.server.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f"🚀 Starting Packet Analyzer Simulation on port {port}")
    print("🔧 Auto-Simulation Mode: Automatically generating packet data")
    print("📊 Access the dashboard at: http://localhost:5000")
    print("🟢 Simulation is automatically running - use Stop/Reset to control")
    app.run(debug=True, host='0.0.0.0', port=port)
