# Packet Analysis Dashboard

This project provides a real-time network packet analysis dashboard. It uses a combination of **Scapy**, **Dash**, and **Plotly** to analyze network traffic and detect anomalies. The dashboard allows users to filter packets based on source IP, destination IP, and protocol while visualizing traffic metrics and anomaly detection results.

## Sample Dashboard:

![Packet Analysis Dashboard](https://i.imgur.com/vEx2loO.png)

## Features:

- Real-time packet capture using **Scapy**.
- Anomaly detection using **Isolation Forest**.
- Dynamic visualization of packet size and protocol types.
- Filtering based on source IP, destination IP, and protocol.

## Prerequisites:

1. Python 3.x
2. Elevated permissions for network sniffing (this project requires root access to capture network traffic).

## Installation Instructions:

### 1. Clone the repository:

```bash
git clone https://github.com/premkumaranubhav123/network-packet-hosting
cd network-packet-hosting
```

### 2. Install dependencies:

Make sure you have the necessary libraries installed by running the following command:

```bash
pip install -r requirements.txt
```

### 3. Run the application:

Since this project involves network sniffing, elevated permissions are required. Follow these steps:

- **Step 1**: Switch to the root user (or use `sudo` on Unix systems):

```bash
sudo -i
```

- **Step 2**: Run the Flask app:

```bash
python3 app.py
```

The application will start running on port `5000` by default.

### 4. Open the dashboard:

After running the app, open a browser and navigate to:

```
http://localhost:5000
```

You should see the packet analysis dashboard where you can view real-time packet statistics and visualize the packet data.

## Project Structure:

- **app.py**: Contains the main application logic and packet analysis features.
- **index.html**: The HTML file that embeds the Dash application into the page.
- **requirements.txt**: List of dependencies for the project.

## License:

This project is open source and available under the MIT License.
