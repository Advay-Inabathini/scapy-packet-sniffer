from scapy.all import sniff, Ether, IP, TCP, UDP
import threading
import matplotlib.pyplot as plt

captured_packets = []
stop_sniffing = False

def packet_callback(packet):
    if Ether in packet:
        captured_packets.append(packet)

def start_sniffing():
    print("Sniffing started. Press 'q' to stop.")
    # Sniff indefinitely until the user presses 'q'
    sniff(prn=packet_callback, stop_filter=lambda x: x.haslayer(Ether) and stop_sniffing, store=0)

def display_packet_info():
    # Display packet statistics
    print("\nPacket Statistics:")
    protocol_counts = {'IP': 0, 'TCP': 0, 'UDP': 0, 'Other': 0}

    for packet in captured_packets:
        if IP in packet:
            protocol_counts['IP'] += 1
            if TCP in packet:
                protocol_counts['TCP'] += 1
            elif UDP in packet:
                protocol_counts['UDP'] += 1
        else:
            protocol_counts['Other'] += 1

    for protocol, count in protocol_counts.items():
        print(f"{protocol}: {count} packets")

    # Plot pie chart for protocol distribution
    labels = list(protocol_counts.keys())
    values = list(protocol_counts.values())
    plt.pie(values, labels=labels, autopct='%1.1f%%')
    plt.title('Protocol Distribution')
    plt.show()

if __name__ == "__main__":
    # Start sniffing in a separate thread
    sniff_thread = threading.Thread(target=start_sniffing)
    sniff_thread.start()

    # Wait for user input to stop sniffing
    input("Press 'q' and Enter to stop sniffing\n")
    
    # Set the flag to stop sniffing
    stop_sniffing = True

    # Wait for the sniffing thread to finish
    sniff_thread.join()

    # Display captured packets
    display_packet_info()
