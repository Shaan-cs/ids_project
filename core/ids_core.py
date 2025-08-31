# ids_project/core/ids_core.py
import time
from datetime import datetime
from .packet_sniffer import PacketSniffer
from .detector import IntrusionDetector
from .firewall import FirewallManager
from .logger import IDSLogger
from database.db_manager import DatabaseManager

class IDSCore:
    def __init__(self, config=None):
        self.config = config or {}
        self.running = False
        
        # Initialize components
        self.db_manager = DatabaseManager(
            db_file=self.config.get('db_file', 'ids.db')
        )
        
        self.logger = IDSLogger(
            log_file=self.config.get('log_file', 'ids.log'),
            db_file=self.config.get('db_file', 'ids.db')
        )
        
        self.firewall = FirewallManager(
            block_duration=self.config.get('block_duration', 600)
        )
        
        self.detector = IntrusionDetector(
            alert_callback=self.handle_alert,
            block_callback=self.handle_block
        )
        
        self.sniffer = PacketSniffer(
            interface=self.config.get('interface'),
            detection_callback=self.detector.analyze_packet
        )
        
        # Stats tracking
        self.start_time = None
        self.last_stats_time = None
    
    def handle_alert(self, alert):
        """Handle detected alerts"""
        # Log the alert
        self.logger.log_alert(alert)
        self.db_manager.log_alert(alert)
        
        # Print to console
        print(f"ALERT: {alert['type']} from {alert['source_ip']} - {alert['message']}")
    
    def handle_block(self, ip, reason):
        """Handle IP blocking requests"""
        if self.firewall.block_ip(ip, reason):
            self.logger.log_blocked_ip(ip, reason)
            self.db_manager.log_blocked_ip({
                'ip_address': ip,
                'block_time': datetime.now().isoformat(),
                'unblock_time': (datetime.now() + timedelta(seconds=self.firewall.block_duration)).isoformat(),
                'reason': reason,
                'action': 'blocked'
            })
    
    def start(self):
        """Start the IDS system"""
        if self.running:
            print("IDS is already running")
            return False
        
        print("Starting IDS/IPS System...")
        print(f"Log file: {self.logger.log_file}")
        print(f"Database: {self.db_manager.db_file}")
        
        try:
            self.running = True
            self.start_time = time.time()
            self.last_stats_time = time.time()
            self.sniffer.start_sniffing()
            
            # Main loop
            while self.running:
                time.sleep(5)
                
                # Log traffic statistics periodically
                current_time = time.time()
                if current_time - self.last_stats_time >= 30:  # Every 30 seconds
                    stats = self.sniffer.get_stats()
                    self.logger.log_traffic_stats(stats)
                    self.db_manager.log_traffic_stats(stats)
                    self.last_stats_time = current_time
                
        except KeyboardInterrupt:
            print("\nShutting down IDS...")
            self.stop()
        except Exception as e:
            print(f"Error: {e}")
            self.stop()
        
        return True
    
    def stop(self):
        """Stop the IDS system"""
        self.running = False
        self.sniffer.stop_sniffing()
        print("IDS stopped")
    
    def status(self):
        """Get current status"""
        stats = self.sniffer.get_stats()
        blocked_ips = self.firewall.get_blocked_ips()
        
        return {
            'running': self.running,
            'uptime_seconds': stats.get('uptime_seconds', 0),
            'total_packets': stats.get('total_packets', 0),
            'blocked_ips_count': len(blocked_ips),
            'blocked_ips': blocked_ips
        }