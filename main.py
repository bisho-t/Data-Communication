# TASK 1:
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp

def arp_scan(subnet):
    arp_request = ARP(pdst=subnet)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    answered, _ = srp(packet, timeout=2, verbose=False)
    hosts = []
    for send, recv in answered:
        hosts.append({'IP': recv.psrc, 'MAC': recv.hwsrc})

    return hosts

# Example usage
subnet = "10.9.0.0/24"
active_hosts = arp_scan(subnet)

print("Active hosts discovered:")
for host in active_hosts:
    print(f"IP: {host['IP']}, MAC: {host['MAC']}")
    
# TASK 2,4:
import csv
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.sendrecv import send, sniff, sr1
def log_pkt(pkt):
    if IP in pkt:
        with open("log.csv", "a") as f:
            writer = csv.writer(f)
            writer.writerow([pkt[IP].src, pkt[IP].dst, pkt.summary(), len(pkt), pkt.time])


with open("log.csv", "w") as f:
    writer = csv.writer(f)
    writer.writerow(['Src IP', 'Dest IP', 'Protocol', 'Pkt Len', 'Timestamp'])


def analyze_traffic(ip_address):
    def packet_callback(packet):

        if IP in packet:

            if (TCP in packet or UDP in packet or ICMP in packet) and (
                packet[IP].src == ip_address or packet[IP].dst == ip_address
            ):
                print("=== Packet Details ===")
                packet.show()
                log_pkt(packet)


    print(f"Capturing traffic for IP address: {ip_address} (TCP, UDP, and ICMP only)... Press Ctrl+C to stop.")
    sniff(filter=f"tcp or udp or icmp and (host {ip_address})", prn=packet_callback, store=False)


analyze_traffic("10.9.0.5")

# TASK 3:
 
def ore_m():
    ip =IP(dst="10.9.0.5")
    icmp =ICMP()
    packet= ip/icmp
    return packet

def send_tcp_packets(dst_ip, dst_port=80):
    ip = IP(dst=dst_ip)
    tcp = TCP(dport=dst_port)
    packet = ip / tcp
    return packet


def send_udp_packets(dst_ip, dst_port=53):
    ip = IP(dst=dst_ip)
    udp = UDP(dport=dst_port)
    packet = ip / udp
    return packet

gg=ore_m()
oo=send_tcp_packets("10.9.0.5")
ll=send_udp_packets("10.9.0.5")
send(gg,count=3)
send(oo, count=3)
send(ll, count=3)


# TASK 5 :

# Log function to write packet details to a CSV file
def log_pkt(data_rate, throughput, protocol, latency, jitter):
    with open("loget.csv", "a") as f:
        writer = csv.writer(f)
        writer.writerow([data_rate, throughput, protocol, latency, jitter])

# Function to calculate the packet size
def get_packet_size(packet):
    return len(packet)

# Function to measure transmission time (RTT)
def measure_transmission_time(packet, target_ip):
    response = sr1(packet, timeout=2, verbose=False) # Send the packet
    if response:
        rtt = response.time - packet.sent_time # RTT is the difference in response and send times
        return rtt
    else:
        print("No response received.")
        return None

# Function to calculate throughput
def calculate_throughput(packet, transmission_time):
    if transmission_time is not None:
        packet_size_bits = len(packet) * 8 # Convert packet size to bits
        throughput = packet_size_bits / transmission_time # Throughput in bits per second
        return throughput
    else:
        print("Transmission time is None, cannot calculate throughput.")
        return None

# Function to calculate latency
def calculate_latency(transmission_time):
    if transmission_time is not None:
        latency = transmission_time / 2 # Assuming RTT, so latency is half the round trip time
        return latency
    else:
        print("Transmission time is None, cannot calculate latency.")
        return None

# Function to calculate jitter
def calculate_jitter(rtts):
    if len(rtts) > 1:
        # Calculate the differences between consecutive RTTs
        differences = [abs(rtts[i] - rtts[i-1]) for i in range(1, len(rtts))]
        
        # Calculate the mean of the differences
        mean_diff = sum(differences) / len(differences)
        
        # Calculate the variance (sum of squared differences from the mean)
        variance = sum((x - mean_diff) ** 2 for x in differences) / len(differences)
        
        # Instead of using math.sqrt, we'll use an approximation (basic square root calculation)
        jitter = variance ** 0.5 # Calculating the square root without math library
        return jitter
    else:
        print("Not enough RTT values to calculate jitter.")
        return None

# Write the header row to CSV (only if file is empty)
def write_header_if_empty():
    try:
        with open("loget.csv", "r") as f:
            if not f.read(1): # Check if the file is empty
                with open("loget.csv", "w") as write_f:
                    writer = csv.writer(write_f)
                    writer.writerow(['data rate', 'throughput', 'Protocol', 'latency', 'Jitter'])
    except FileNotFoundError:
        with open("loget.csv", "w") as write_f:
            writer = csv.writer(write_f)
            writer.writerow(['data rate', 'throughput', 'Protocol', 'latency', 'Jitter'])

# Example usage
write_header_if_empty() # Ensure header is written if the file is empty or non-existent

target_ip = "10.9.0.6" # Example target IP
icmp_packet = IP(dst=target_ip) / ICMP() # Create an ICMP packet

# Collect RTTs for multiple packets
rtts = []
for _ in range(5): # Sending 5 packets to measure jitter
    transmission_time = measure_transmission_time(icmp_packet, target_ip)
    if transmission_time is not None:
        # Calculate data rate
        data_rate = len(icmp_packet) * 8 / transmission_time # In bits per second
        print(f"Data Rate: {data_rate:.2f} bps")
        
        # Calculate throughput
        throughput = calculate_throughput(icmp_packet, transmission_time)
        print(f"Throughput: {throughput:.2f} bps")

        # Calculate latency
        latency = calculate_latency(transmission_time)
        print(f"Latency: {latency:.6f} seconds")

        # Append RTT for jitter calculation
        rtts.append(transmission_time)

# Calculate jitter based on collected RTTs
jitter = calculate_jitter(rtts)
if jitter is not None:
    print(f"Jitter: {jitter:.6f} seconds")

    # Log the results to a CSV file
    log_pkt(data_rate, throughput, "ICMP", latency, jitter)
