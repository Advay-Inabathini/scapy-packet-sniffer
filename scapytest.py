from scapy.all import sniff, Ether, IP
import threading

captured_packets = []
stop_sniffing = False

def packet_callback(packet):
    if Ether in packet and IP in packet:
        captured_packets.append(packet)

def start_sniffing():
    print("Sniffing started. Press 'q' to stop.")
    # Sniff indefinitely until the user presses 'q'
    sniff(prn=packet_callback, stop_filter=lambda x: x.haslayer(Ether) and x.haslayer(IP) and stop_sniffing, store=0)

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
    print("\nCaptured Packets:")
    for packet in captured_packets:
        print(packet.summary())
