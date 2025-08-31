# ids_project/core/packet_sniffer.py
import platform
import threading
import time
from scapy.all import sniff, IP, TCP, UDP, ICMP
from scapy.layers import http
from collections import defaultdict
import datetime

class PacketSniffer:
    def __init__(self, interface=None, detection_callback=None):
        self.interface = interface or self.get_default_interface()
        self.detection_callback = detection_callback
        self.running = False
        self.sniffer_thread = None
        self.packet_count = 0
        self.start_time = None
        
        # Traffic statistics
        self.traffic_stats = {
            'total_packets': 0,
            'tcp_packets': 0,
            'udp_packets': 0,
            'icmp_packets': 0,
            'http_packets': 0,
            'bytes_transferred': 0,
            'source_ips': defaultdict(int),
            'destination_ips': defaultdict(int)
        }
    
    def get_default_interface(self):
        """Get default network interface based on OS"""
        system = platform.system()
        if system == "Windows":
            return None  # Let scapy choose default on Windows
        elif system == "Linux":
            try:
                import netifaces
                return netifaces.gateways()['default'][netifaces.AF_INET][1]
            except:
                return "eth0"
        else:
            return None
    
    def packet_handler(self, packet):
        """Process each captured packet"""
        self.packet_count += 1
        self.traffic_stats['total_packets'] += 1
        self.traffic_stats['bytes_transferred'] += len(packet)
        
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            self.traffic_stats['source_ips'][src_ip] += 1
            self.traffic_stats['destination_ips'][dst_ip] += 1
            
            if TCP in packet:
                self.traffic_stats['tcp_packets'] += 1
            elif UDP in packet:
                self.traffic_stats['udp_packets'] += 1
            elif ICMP in packet:
                self.traffic_stats['icmp_packets'] += 1
            
            # Check for HTTP packets
            if packet.haslayer(http.HTTPRequest):
                self.traffic_stats['http_packets'] += 1
        
        # Pass packet to detection callback if provided
        if self.detection_callback:
            self.detection_callback(packet)
    
    def start_sniffing(self):
        """Start packet sniffing in a separate thread"""
        if self.running:
            return False
        
        self.running = True
        self.start_time = datetime.datetime.now()
        
        def sniff_thread():
            try:
                sniff(
                    iface=self.interface,
                    prn=self.packet_handler,
                    store=False,
                    stop_filter=lambda x: not self.running
                )
            except Exception as e:
                print(f"Sniffing error: {e}")
                self.running = False
        
        self.sniffer_thread = threading.Thread(target=sniff_thread)
        self.sniffer_thread.daemon = True
        self.sniffer_thread.start()
        return True
    
    def stop_sniffing(self):
        """Stop packet sniffing"""
        self.running = False
        if self.sniffer_thread:
            self.sniffer_thread.join(timeout=2)
        return True
    
    def get_stats(self):
        """Get current traffic statistics"""
        uptime = datetime.datetime.now() - self.start_time if self.start_time else datetime.timedelta(0)
        return {
            **self.traffic_stats,
            'uptime_seconds': uptime.total_seconds(),
            'packets_per_second': self.packet_count / uptime.total_seconds() if uptime.total_seconds() > 0 else 0
        }