from flask import Flask, render_template, request, jsonify
import scapy.all as scapy
import folium  # (not yet fully implemented)
import plotly.graph_objs as go
import pandas as pd
import json

from flask import Flask, render_template, request, jsonify
import io
import base64
import matplotlib
matplotlib.use('Agg')  # Configure for headless rendering
import matplotlib.pyplot as plt


app = Flask(__name__)

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
    protocol_labels = list(protocol_counts.keys())
    protocol_values = list(protocol_counts.values())
    return protocol_labels, protocol_values


def get_website_distribution(packets):
    websites = []
    for packet in packets:
        website = 'Unknown'
        if packet.haslayer('IP') and packet.haslayer('HTTP'):
            http_layer = packet.getlayer('HTTP')
            if http_layer.fields.get('Host'):
                website = http_layer.fields['Host']
        websites.append(website)

    website_counts = pd.Series(websites).value_counts().to_dict()
    website_labels = [label for label in website_counts.keys() if label != 'Undefined']
    website_values = [website_counts[label] for label in website_labels]
    return website_labels, website_values


def get_summary_text(packets):
    protocol_labels, protocol_values = get_protocol_distribution(packets)
    top_protocols = sorted(zip(protocol_labels, protocol_values), key=lambda x: x[1], reverse=True)[:3]
    summary_text = "Top protocols observed: "
    for protocol, count in top_protocols:
        summary_text += f"{protocol} ({count / len(packets) * 100:.2f}%), "
    return summary_text[:-2]  # Remove the trailing comma and space


# Function to create packet timeline (not yet implemented)
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
        protocol_labels, protocol_values = get_protocol_distribution(captured_packets)
        website_labels, website_values = get_website_distribution(captured_packets)

        # Check if website_labels has a value before converting to JSON
        website_labels_json = None
        if website_labels:
            website_labels_json = json.dumps(website_labels)

        summary_text = get_summary_text(captured_packets)
        buf = io.BytesIO()
        plt.figure()
        plt.pie(website_values, labels=website_labels, autopct="%1.1f%%")
        plt.title("Source Distribution")
        plt.axis('equal')
        plt.savefig(buf, format='png')  # Save to in-memory buffer
        plt.close()  # Close the figure

        # Encode image data as base64
        data = base64.b64encode(buf.getvalue()).decode('utf-8')
        source_distribution_image = f'data:image/png;base64,{data}'

        # Repeat for protocol distribution plot
        buf = io.BytesIO()
        plt.figure()
        plt.pie(protocol_values, labels=protocol_labels, autopct="%1.1f%%")
        plt.title("Protocol Distribution")
        plt.axis('equal')
        plt.savefig(buf, format='png')
        plt.close()
        data = base64.b64encode(buf.getvalue()).decode('utf-8')
        protocol_distribution_image = f'data:image/png;base64,{data}'

        return render_template('results.html', packets=captured_packets, summary_text=summary_text,
                                source_distribution_image=source_distribution_image,
                                protocol_distribution_image=protocol_distribution_image)
    else:
        return render_template('index.html', message="Packet capture is not running.")


if __name__ == '__main__':
    app.run(debug=True)

