# ids_project/core/detector.py
import threading
import time
from collections import defaultdict, deque
import datetime

class IntrusionDetector:
    def __init__(self, alert_callback=None, block_callback=None):
        self.alert_callback = alert_callback
        self.block_callback = block_callback
        
        # Detection thresholds (configurable)
        self.thresholds = {
            'port_scan': {
                'max_ports_per_minute': 20,
                'max_unique_ports': 15,
                'time_window': 60  # seconds
            },
            'syn_flood': {
                'max_syn_per_second': 100,
                'time_window': 10  # seconds
            },
            'brute_force': {
                'max_attempts_per_minute': 10,
                'time_window': 60  # seconds
            },
            'dos_attack': {
                'max_packets_per_second': 1000,
                'time_window': 5  # seconds
            }
        }
        
        # Data structures for tracking suspicious activity
        self.port_scan_tracker = defaultdict(lambda: defaultdict(deque))
        self.syn_flood_tracker = defaultdict(deque)
        self.brute_force_tracker = defaultdict(lambda: defaultdict(deque))
        self.dos_tracker = defaultdict(deque)
        
        # Whitelist and blacklist
        self.whitelist = set()
        self.blacklist = set()
        
        # Cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_old_entries)
        self.cleanup_thread.daemon = True
        self.cleanup_thread.start()
    
    def analyze_packet(self, packet):
        """Analyze packet for suspicious patterns"""
        if not hasattr(packet, 'haslayer') or not packet.haslayer('IP'):
            return
        
        src_ip = packet['IP'].src
        
        # Skip whitelisted IPs
        if src_ip in self.whitelist:
            return
        
        # Check for various attack patterns
        self._detect_port_scan(packet, src_ip)
        self._detect_syn_flood(packet, src_ip)
        self._detect_brute_force(packet, src_ip)
        self._detect_dos_attack(packet, src_ip)
    
    def _detect_port_scan(self, packet, src_ip):
        """Detect port scanning activity"""
        if packet.haslayer('TCP'):
            dst_port = packet['TCP'].dport
            current_time = time.time()
            
            # Track port access
            self.port_scan_tracker[src_ip]['ports'].append((dst_port, current_time))
            
            # Clean old entries
            window_start = current_time - self.thresholds['port_scan']['time_window']
            self.port_scan_tracker[src_ip]['ports'] = [
                (port, ts) for port, ts in self.port_scan_tracker[src_ip]['ports'] 
                if ts > window_start
            ]
            
            # Check thresholds
            ports_in_window = self.port_scan_tracker[src_ip]['ports']
            unique_ports = len(set(port for port, ts in ports_in_window))
            
            if (len(ports_in_window) > self.thresholds['port_scan']['max_ports_per_minute'] or
                unique_ports > self.thresholds['port_scan']['max_unique_ports']):
                
                alert_msg = f"Port scan detected from {src_ip}: {len(ports_in_window)} attempts, {unique_ports} unique ports"
                self._trigger_alert('PORT_SCAN', src_ip, alert_msg, severity='HIGH')
                
                # Auto-block if configured
                if self.block_callback:
                    self.block_callback(src_ip, 'Port scanning detected')
    
    def _detect_syn_flood(self, packet, src_ip):
        """Detect SYN flood attack"""
        if packet.haslayer('TCP') and packet['TCP'].flags == 'S':  # SYN packet
            current_time = time.time()
            
            # Track SYN packets
            self.syn_flood_tracker[src_ip].append(current_time)
            
            # Clean old entries
            window_start = current_time - self.thresholds['syn_flood']['time_window']
            self.syn_flood_tracker[src_ip] = deque(
                ts for ts in self.syn_flood_tracker[src_ip] if ts > window_start
            )
            
            # Check threshold
            if len(self.syn_flood_tracker[src_ip]) > self.thresholds['syn_flood']['max_syn_per_second']:
                alert_msg = f"SYN flood detected from {src_ip}: {len(self.syn_flood_tracker[src_ip])} SYN packets"
                self._trigger_alert('SYN_FLOOD', src_ip, alert_msg, severity='CRITICAL')
                
                if self.block_callback:
                    self.block_callback(src_ip, 'SYN flood attack')
    
    def _detect_brute_force(self, packet, src_ip):
        """Detect brute force attempts"""
        if packet.haslayer('TCP') and packet.haslayer('Raw'):
            # Simple pattern matching for common brute force indicators
            payload = str(packet['Raw'].load).lower()
            brute_indicators = ['login', 'password', 'user', 'admin', 'root', 'ssh', 'ftp']
            
            if any(indicator in payload for indicator in brute_indicators):
                current_time = time.time()
                dst_port = packet['TCP'].dport
                
                # Track brute force attempts
                self.brute_force_tracker[src_ip][dst_port].append(current_time)
                
                # Clean old entries
                window_start = current_time - self.thresholds['brute_force']['time_window']
                self.brute_force_tracker[src_ip][dst_port] = deque(
                    ts for ts in self.brute_force_tracker[src_ip][dst_port] if ts > window_start
                )
                
                # Check threshold
                if len(self.brute_force_tracker[src_ip][dst_port]) > self.thresholds['brute_force']['max_attempts_per_minute']:
                    alert_msg = f"Brute force attempt from {src_ip} on port {dst_port}"
                    self._trigger_alert('BRUTE_FORCE', src_ip, alert_msg, severity='HIGH')
                    
                    if self.block_callback:
                        self.block_callback(src_ip, 'Brute force attempt')
    
    def _detect_dos_attack(self, packet, src_ip):
        """Detect DoS attack patterns"""
        current_time = time.time()
        
        # Track all packets for DoS detection
        self.dos_tracker[src_ip].append(current_time)
        
        # Clean old entries
        window_start = current_time - self.thresholds['dos_attack']['time_window']
        self.dos_tracker[src_ip] = deque(
            ts for ts in self.dos_tracker[src_ip] if ts > window_start
        )
        
        # Check threshold
        if len(self.dos_tracker[src_ip]) > self.thresholds['dos_attack']['max_packets_per_second']:
            alert_msg = f"DoS attack detected from {src_ip}: {len(self.dos_tracker[src_ip])} packets/second"
            self._trigger_alert('DOS_ATTACK', src_ip, alert_msg, severity='CRITICAL')
            
            if self.block_callback:
                self.block_callback(src_ip, 'DoS attack')
    
    def _trigger_alert(self, alert_type, src_ip, message, severity='MEDIUM'):
        """Trigger an alert with the provided callback"""
        alert = {
            'timestamp': datetime.datetime.now().isoformat(),
            'type': alert_type,
            'source_ip': src_ip,
            'message': message,
            'severity': severity
        }
        
        if self.alert_callback:
            self.alert_callback(alert)
    
    def _cleanup_old_entries(self):
        """Periodically clean up old tracking entries"""
        while True:
            time.sleep(300)  # Cleanup every 5 minutes
            current_time = time.time()
            
            # Clean port scan tracker
            for ip in list(self.port_scan_tracker.keys()):
                for key in list(self.port_scan_tracker[ip].keys()):
                    window_start = current_time - self.thresholds['port_scan']['time_window']
                    self.port_scan_tracker[ip][key] = deque(
                        item for item in self.port_scan_tracker[ip][key] 
                        if isinstance(item, tuple) and item[1] > window_start
                    )
    
    def add_to_whitelist(self, ip):
        """Add IP to whitelist"""
        self.whitelist.add(ip)
    
    def remove_from_whitelist(self, ip):
        """Remove IP from whitelist"""
        self.whitelist.discard(ip)
    
    def add_to_blacklist(self, ip):
        """Add IP to blacklist"""
        self.blacklist.add(ip)
        if self.block_callback:
            self.block_callback(ip, 'Manually blacklisted')
    
    def remove_from_blacklist(self, ip):
        """Remove IP from blacklist"""
        self.blacklist.discard(ip)