from flask import Flask, render_template, redirect, url_for
from scapy.all import sniff, Ether, IP
from threading import Thread, Event
from collections import Counter

app = Flask(__name__)

# Global variables
packet_data = []
stop_sniffing_event = Event()

# Packet sniffing function
def packet_sniffer():
    global packet_data
    packet_data = []
    sniffed_packets = sniff(prn=lambda x: process_packet(x), stop_filter=lambda x: stop_sniffing_event.is_set())

# Packet processing function
def process_packet(packet):
    global packet_data
    if IP in packet:
        packet_info = {
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst,
            'protocol': packet[IP].proto,
            'length': len(packet),
            'info': packet.summary()
        }
        packet_data.append(packet_info)

# Function to generate dashboard data
def generate_dashboard_data():
    global packet_data
    total_packets = len(packet_data)
    protocol_counts = Counter([p['protocol'] for p in packet_data])
    top_talkers = Counter([p['src_ip'] for p in packet_data]).most_common(5)
    sample_packets = packet_data[:10]  # Get a sample of packet details (first 10 packets)
    return {
        'total_packets': total_packets,
        'protocol_counts': protocol_counts,
        'top_talkers': top_talkers,
        'sample_packets': sample_packets
    }

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/start_capture')
def start_capture():
    global sniffing_thread
    # Clear stop_sniffing_event flag before starting capture
    stop_sniffing_event.clear()
    # Start a new thread for packet sniffing
    sniffing_thread = Thread(target=packet_sniffer)
    sniffing_thread.start()
    return redirect(url_for('capture'))

@app.route('/stop_capture')
def stop_capture():
    global stop_sniffing_event
    # Set stop_sniffing_event flag to stop packet capture
    stop_sniffing_event.set()
    sniffing_thread.join()
    return redirect(url_for('dashboard'))

@app.route('/capture')
def capture():
    return render_template('capture.html')

@app.route('/dashboard')
def dashboard():
    dashboard_data = generate_dashboard_data()
    return render_template('dashboard.html', data=dashboard_data)

if __name__ == '__main__':
    app.run(debug=True)
