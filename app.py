from flask import Flask, render_template, request, jsonify
import scapy.all as scapy
import folium
import plotly.graph_objs as go
import pandas as pd

app = Flask(__name__)
capturing = False

# List to store captured packets
captured_packets = []

# Function to start packet capture
def start_capture():
    def packet_callback(packet):
        captured_packets.append(packet)

    scapy.sniff(prn=packet_callback, store=False)

# Function to get source website from packet
def get_source_website(packet):
    if packet.haslayer(scapy.HTTP):
        http_layer = packet.getlayer(scapy.HTTP)
        if http_layer.fields.get('Host'):
            return http_layer.fields['Host']
    return 'Unknown'

# Function to analyze packets for potential malicious activity
def analyze_packets(packets):
    malicious_packets = []
    for packet in packets:
        if packet.haslayer('IP'):
            if packet['IP'].proto == 'TCP' and packet['TCP'].dport == 4444:
                malicious_packets.append(packet)

    return malicious_packets

# Function to get protocol distribution
def get_protocol_distribution(packets):
    protocols = []
    for packet in packets:
        if packet.haslayer('IP'):
            protocols.append(packet['IP'].proto)

    protocol_counts = pd.Series(protocols).value_counts().to_dict()
    protocol_distribution = {'labels': list(protocol_counts.keys()), 'values': list(protocol_counts.values())}
    return protocol_distribution

def get_website_distribution(packets):
    websites = []
    for packet in packets:
        website = 'Unknown'
        if packet.haslayer('IP') and packet.haslayer('HTTP'):
            http_layer = packet.getlayer('HTTP')
            if http_layer.fields.get('Host'):
                website = http_layer.fields['Host']
        websites.append(website)

    website_counts = pd.Series(websites).value_counts()
    website_distribution = go.Pie(labels=website_counts.index, values=website_counts.values)
    return website_distribution

# Function to create packet timeline
def create_packet_timeline(packets):
    packet_times = [packet.time for packet in packets]
    packet_timeline = go.Scatter(x=packet_times, y=[i for i in range(len(packet_times))])
    return packet_timeline

# Route for the main page
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start_capture', methods=['POST'])
def start_capture_route():
    global capturing
    if not capturing:
        capturing = True
        start_capture()
    return render_template('capture.html', capturing=capturing)

@app.route('/stop_capture', methods=['POST'])
def stop_capture_route():
    global capturing
    if capturing:
        capturing = False
        malicious_packets = analyze_packets(captured_packets)
        protocol_distribution = get_protocol_distribution(captured_packets)
        website_distribution = get_website_distribution(captured_packets)
        packet_timeline = create_packet_timeline(captured_packets)
        return render_template('results.html', packets=captured_packets, malicious_packets=malicious_packets,
                               protocol_distribution=protocol_distribution, website_distribution=website_distribution,
                               packet_timeline=packet_timeline, capturing=capturing)
    else:
        return render_template('index.html', message="Packet capture is not running.")

if __name__ == '__main__':
    app.run(debug=True)
