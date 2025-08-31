# ids_project/main.py
#!/usr/bin/env python3
import argparse
import signal
import sys
import time
from core.packet_sniffer import PacketSniffer
from core.detector import IntrusionDetector
from core.firewall import FirewallManager
from core.logger import IDSLogger

class IDS:
    def __init__(self, config=None):
        self.config = config or {}
        self.running = False
        
        # Initialize components
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
    
    def handle_alert(self, alert):
        """Handle detected alerts"""
        # Log the alert
        self.logger.log_alert(alert)
        
        # Additional actions could be added here (email, notifications, etc.)
        print(f"ALERT: {alert['type']} from {alert['source_ip']} - {alert['message']}")
    
    def handle_block(self, ip, reason):
        """Handle IP blocking requests"""
        if self.firewall.block_ip(ip, reason):
            self.logger.log_blocked_ip(ip, reason)
    
    def start(self):
        """Start the IDS system"""
        if self.running:
            print("IDS is already running")
            return False
        
        print("Starting IDS/IPS System...")
        print(f"Log file: {self.logger.log_file}")
        print(f"Database: {self.logger.db_file}")
        
        try:
            self.running = True
            self.sniffer.start_sniffing()
            
            # Main loop
            while self.running:
                time.sleep(5)
                # Log traffic statistics periodically
                stats = self.sniffer.get_stats()
                self.logger.log_traffic_stats(stats)
                
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

def main():
    parser = argparse.ArgumentParser(description="Intrusion Detection and Prevention System")
    parser.add_argument('--interface', '-i', help="Network interface to monitor")
    parser.add_argument('--log-file', '-l', default='ids.log', help="Log file path")
    parser.add_argument('--db-file', '-d', default='ids.db', help="Database file path")
    parser.add_argument('--block-duration', '-b', type=int, default=600, 
                       help="Block duration in seconds (default: 600)")
    
    args = parser.parse_args()
    
    # Create IDS instance
    ids = IDS({
        'interface': args.interface,
        'log_file': args.log_file,
        'db_file': args.db_file,
        'block_duration': args.block_duration
    })
    
    # Setup signal handlers for graceful shutdown
    def signal_handler(sig, frame):
        print("\nReceived shutdown signal")
        ids.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start the IDS
    ids.start()

if __name__ == "__main__":
    main()