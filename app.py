from flask import Flask, render_template, redirect, url_for
from scapy.all import sniff, Ether, IP
from threading import Thread, Event
from collections import Counter
import dns.resolver
import ipaddress
import socket

import geoip2.database

# Path to the GeoLite2 City database file
DATABASE_PATH = 'GeoLite2-City.mmdb'

PROTOCOL_NAMES = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    4: "IPv4",
    # ... Add more entries for relevant protocols
}

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
            'protocol': PROTOCOL_NAMES.get(packet[IP].proto),
            'length': len(packet),
            'info': packet.summary()
        }
        packet_data.append(packet_info)

import dns.resolver

def resolve_dns(ip_address):
  """
  Attempts to resolve an IP address to a hostname, handling private IP ranges.
  """
  try:
    if ipaddress.ip_interface(ip_address).is_private:
      return f"Private IP ({ip_address})"
    # Only resolve if IP is present in top_talkers
    # (assuming you have a variable containing the filtered top talkers)
    if ip_address not in Counter([p['src_ip'] for p in packet_data]).most_common(10):
      return ip_address  # Avoid unnecessary resolution
    hostname, aliases, addresses = socket.gethostbyaddr(ip_address)
    return hostname
  except Exception as e:
    print(f"Error resolving hostname for {ip_address}: {e}")
    return ""  # Or return a specific value to indicate failure

# Function to get location information from IP using GeoLite2 database
def get_location(ip):
    try:
        # Load the GeoLite2 database
        reader = geoip2.database.Reader(DATABASE_PATH)
        
        # Perform IP geolocation lookup
        response = reader.city(ip)
        
        # Extract relevant location information
        city = response.city.name
        country = response.country.name
        organization = response.traits.organization
        
        # Construct a meaningful description
        description = f"{city}, {country}, ({organization})"
        
        return description
    except geoip2.errors.AddressNotFoundError:
        # Handle the case where IP geolocation fails
        return ""
    finally:
        # Close the GeoLite2 database reader
        if reader:
            reader.close()

# Function to get website name from IP using DNS lookup
def get_website(ip):
    try:
        # Perform DNS lookup to get hostname from IP address
        hostname = socket.gethostbyaddr(ip)[0]
        
        # Check if the hostname is meaningful (not just the IP address itself)
        if hostname != ip:
            return hostname
        else:
            # If the hostname is not meaningful, use IP geolocation to get location information
            location = get_location(ip)
            return location
    except (socket.herror, socket.gaierror):
        # Handle the case where DNS lookup fails
        ""

def generate_dashboard_data():
    global packet_data
    total_packets = len(packet_data)
    protocol_counts = Counter([p['protocol'] for p in packet_data])

  # Resolve DNS for source and destination IPs
    resolved_packets = []
    for packet in packet_data:
        packet['src_domain'] = resolve_dns(packet['src_ip'])
        packet['dst_domain'] = resolve_dns(packet['dst_ip'])
        resolved_packets.append(packet.copy())

    resolved_ip_domains = {}
    for packet in resolved_packets:
        resolved_ip_domains[packet['src_ip']] = packet['src_domain']

    top_talkers = Counter([p['src_ip'] for p in packet_data]).most_common(10)
    resolved_top_talkers = []
    for ip, count in top_talkers:
        # Lookup domain using resolved_ip_domains dictionary
        domain_name = resolved_ip_domains.get(ip)  # Use get() to handle missing resolutions
        location = get_location(ip)
        website = get_website(ip)
        resolved_top_talkers.append({
            'src_ip': ip,
            'src_domain': domain_name,  # Use domain_name from lookup
            'count': count,
            'location': location,
            'website': website,
        })

    return {
        'total_packets': total_packets,
        'protocol_counts': protocol_counts,
        'top_talkers': resolved_top_talkers,  # Use resolved_top_talkers with domain names
        'sample_packets': resolved_packets[:10],
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
