from scapy.all import sniff, IP, TCP, UDP, ICMP

def process_packet(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto

        # Identify protocol name
        proto_name = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP'
        }.get(protocol, 'Other')

        print(f"\n[+] Packet Captured:")
        print(f"    Source IP      : {src_ip}")
        print(f"    Destination IP : {dst_ip}")
        print(f"    Protocol       : {proto_name}")

        if proto_name == 'TCP' and TCP in packet:
            print(f"    Source Port    : {packet[TCP].sport}")
            print(f"    Dest Port      : {packet[TCP].dport}")
            print(f"    Payload        : {str(bytes(packet[TCP].payload))[:50]}")
        elif proto_name == 'UDP' and UDP in packet:
            print(f"    Source Port    : {packet[UDP].sport}")
            print(f"    Dest Port      : {packet[UDP].dport}")
            print(f"    Payload        : {str(bytes(packet[UDP].payload))[:50]}")
        elif proto_name == 'ICMP' and ICMP in packet:
            print("    ICMP Packet")

print("Starting network sniffer... Press Ctrl+C to stop.\n")
sniff(filter="ip", prn=process_packet, store=False)
