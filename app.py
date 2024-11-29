from scapy.all import sniff, IP
import pandas as pd
import dash
from dash import dcc, html
from dash.dependencies import Input, Output, State
import plotly.express as px
from sklearn.ensemble import IsolationForest
import os

# Initialize Dash app
app = dash.Dash(__name__)
server = app.server  # For deployment

app.layout = html.Div(style={'background': 'linear-gradient(to right, #ffffff, #f0f8ff)'}, children=[
    html.H1("Packet Analysis Dashboard", style={'fontFamily': 'Arial, sans-serif', 'color': '#333333'}),
    dcc.Graph(id='live-update-plot'),
    html.Div([
        dcc.Input(id='source-ip-input', type='text', placeholder='Enter Source IP', style={'marginRight': '10px'}),
        dcc.Input(id='destination-ip-input', type='text', placeholder='Enter Destination IP', style={'marginRight': '10px'}),
        dcc.Dropdown(
            id='protocol-dropdown',
            options=[
                {'label': 'ICMP', 'value': 1},
                {'label': 'TCP', 'value': 6},
                {'label': 'UDP', 'value': 17}
            ],
            placeholder='Select Protocol',
            style={'marginRight': '10px'}
        ),
        html.Button('Apply Filters', id='apply-filters-btn', n_clicks=0, style={'backgroundColor': '#007bff', 'color': '#ffffff'})
    ]),
    html.Div([
        html.P(id='traffic-volume', style={'fontFamily': 'Arial, sans-serif', 'color': '#333333'}),
        html.P(id='average-packet-size', style={'fontFamily': 'Arial, sans-serif', 'color': '#333333'}),
        html.P(id='abnormal-packets', style={'fontFamily': 'Arial, sans-serif', 'color': '#333333'}),
        html.P(id='protocol-counts', style={'fontFamily': 'Arial, sans-serif', 'color': '#333333'}),
        html.P(id='anomaly-packet-count', style={'fontFamily': 'Arial, sans-serif', 'color': '#333333'})
    ]),
    dcc.Interval(
        id='interval-component',
        interval=2*1000,  # in milliseconds
        n_intervals=0
    )
])

# Packet data storage
packet_data = []

# Function to check if an IP address is malicious (replace with actual implementation)
def check_ip_malicious(ip):
    # Implement your IP malicious check logic here
    return False

# Packet handler function
def packet_handler(packet):
    if IP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        protocol = packet[IP].proto
        packet_size = len(packet)
        packet_payload = packet.load if hasattr(packet, 'load') else None

        # Check if IP is malicious
        if check_ip_malicious(source_ip) or check_ip_malicious(destination_ip):
            pass
            print("Malicious IP detected!")

        packet_info = {
            'source_ip': source_ip,
            'destination_ip': destination_ip,
            'protocol': protocol,
            'packet_size': packet_size,
            'packet_payload': packet_payload
        }
        packet_data.append(packet_info)

# Start packet sniffing in the background
import threading
sniff_thread = threading.Thread(target=lambda: sniff(prn=packet_handler, count=0))
sniff_thread.daemon = True
sniff_thread.start()

# Anomaly detection function
def detect_anomalies(df):
    try:
        X = df[['packet_size', 'protocol']]
        isolation_forest = IsolationForest(contamination=0.05)
        isolation_forest.fit(X)
        df['anomaly'] = isolation_forest.predict(X)
        normal_packets = df[df['anomaly'] == 1]
        abnormal_packets = df[df['anomaly'] == -1]
        return normal_packets, abnormal_packets
    except Exception as e:
        print(f"Error occurred during anomaly detection: {e}")
        return None, None

# Analysis and detection function
def perform_analysis_and_detection(df):
    try:
        traffic_volume = len(df)
        average_packet_size = df['packet_size'].mean()
        abnormal_packets_count = len(df[abs(df['packet_size_zscore']) > 3])
        protocol_counts = df['protocol_name'].value_counts().to_dict()

        protocol_counts_str = "Protocol Counts:\n" + "\n".join([f"{protocol}: {count} packets" for protocol, count in protocol_counts.items()])

        return traffic_volume, average_packet_size, abnormal_packets_count, protocol_counts_str
    except Exception as e:
        print(f"Error occurred during analysis: {e}")
        return None, None, None, None

# Update analysis results callback
@app.callback(
    [Output('traffic-volume', 'children'),
     Output('average-packet-size', 'children'),
     Output('abnormal-packets', 'children'),
     Output('protocol-counts', 'children'),
     Output('live-update-plot', 'figure')],
    [Input('apply-filters-btn', 'n_clicks'),
     Input('interval-component', 'n_intervals')],
    [State('source-ip-input', 'value'),
     State('destination-ip-input', 'value'),
     State('protocol-dropdown', 'value')]
)
def update_analysis_results(n_clicks, n_intervals, source_ip, destination_ip, protocol):
    try:
        if packet_data:
            packet_df = pd.DataFrame(packet_data)

            # Calculate z-score for packet sizes
            packet_df['packet_size_zscore'] = (packet_df['packet_size'] - packet_df['packet_size'].mean()) / packet_df['packet_size'].std()

            # Function to get protocol name from number
            def get_protocol_name(proto):
                protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
                return protocol_map.get(proto, 'Other')

            # Add protocol name column
            packet_df['protocol_name'] = packet_df['protocol'].apply(get_protocol_name)

            # Perform anomaly detection
            normal_packets, abnormal_packets = detect_anomalies(packet_df)

            # Apply filters if any
            if n_clicks > 0:
                if source_ip:
                    packet_df = packet_df[packet_df['source_ip'] == source_ip]
                if destination_ip:
                    packet_df = packet_df[packet_df['destination_ip'] == destination_ip]
                if protocol:
                    packet_df = packet_df[packet_df['protocol'] == protocol]

            traffic_volume, average_packet_size, abnormal_packets_count, protocol_counts_str = perform_analysis_and_detection(packet_df)

            # Create plot
            fig = px.scatter(packet_df, x=packet_df.index, y='packet_size', color='protocol_name', title="Packet Sizes over Time")

            return f"Traffic Volume: {traffic_volume}", \
                   f"Average Packet Size: {average_packet_size:.2f} bytes", \
                   f"Abnormal Packets: {abnormal_packets_count}", \
                   protocol_counts_str, \
                   fig
        else:
            return "", "", "", "", {}
    except Exception as e:
        pass

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))  # Use PORT from environment, default to 5000
    app.run(debug=True, host='0.0.0.0', port=port)
