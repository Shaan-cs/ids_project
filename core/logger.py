# ids_project/core/logger.py
import logging
import sqlite3
import json
from datetime import datetime
import os

class IDSLogger:
    def __init__(self, log_file="ids.log", db_file="ids.db"):
        self.log_file = log_file
        self.db_file = db_file
        
        # Setup file logging
        self.setup_file_logging()
        
        # Setup database
        self.setup_database()
    
    def setup_file_logging(self):
        """Setup file-based logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.log_file),
                logging.StreamHandler()  # Also log to console
            ]
        )
        self.logger = logging.getLogger('IDS')
    
    def setup_database(self):
        """Setup SQLite database for structured logging"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # Create alerts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME,
                    alert_type TEXT,
                    source_ip TEXT,
                    severity TEXT,
                    message TEXT,
                    action_taken TEXT
                )
            ''')
            
            # Create traffic_stats table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS traffic_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME,
                    total_packets INTEGER,
                    tcp_packets INTEGER,
                    udp_packets INTEGER,
                    icmp_packets INTEGER,
                    http_packets INTEGER,
                    bytes_transferred INTEGER
                )
            ''')
            
            # Create blocked_ips table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT,
                    block_time DATETIME,
                    unblock_time DATETIME,
                    reason TEXT,
                    action TEXT
                )
            ''')
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Database setup failed: {e}")
    
    def log_alert(self, alert_data):
        """Log an alert to both file and database"""
        try:
            # File logging
            log_message = f"ALERT: {alert_data['type']} from {alert_data['source_ip']} - {alert_data['message']}"
            self.logger.warning(log_message)
            
            # Database logging
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO alerts (timestamp, alert_type, source_ip, severity, message, action_taken)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                alert_data['timestamp'],
                alert_data['type'],
                alert_data['source_ip'],
                alert_data.get('severity', 'MEDIUM'),
                alert_data['message'],
                alert_data.get('action_taken', 'Logged')
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Failed to log alert: {e}")
    
    def log_traffic_stats(self, stats_data):
        """Log traffic statistics to database"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO traffic_stats 
                (timestamp, total_packets, tcp_packets, udp_packets, icmp_packets, http_packets, bytes_transferred)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                stats_data.get('total_packets', 0),
                stats_data.get('tcp_packets', 0),
                stats_data.get('udp_packets', 0),
                stats_data.get('icmp_packets', 0),
                stats_data.get('http_packets', 0),
                stats_data.get('bytes_transferred', 0)
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Failed to log traffic stats: {e}")
    
    def log_blocked_ip(self, ip, reason, action="blocked"):
        """Log IP blocking action"""
        try:
            # File logging
            self.logger.info(f"IP {ip} {action}. Reason: {reason}")
            
            # Database logging
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO blocked_ips (ip_address, block_time, unblock_time, reason, action)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                ip,
                datetime.now().isoformat(),
                (datetime.now() + timedelta(minutes=10)).isoformat() if action == "blocked" else None,
                reason,
                action
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Failed to log blocked IP: {e}")
    
    def get_recent_alerts(self, limit=100):
        """Get recent alerts from database"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT timestamp, alert_type, source_ip, severity, message, action_taken
                FROM alerts 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
            
            alerts = []
            for row in cursor.fetchall():
                alerts.append({
                    'timestamp': row[0],
                    'type': row[1],
                    'source_ip': row[2],
                    'severity': row[3],
                    'message': row[4],
                    'action_taken': row[5]
                })
            
            conn.close()
            return alerts
            
        except Exception as e:
            self.logger.error(f"Failed to get alerts: {e}")
            return []
    
    def export_alerts(self, format_type='json', filename=None):
        """Export alerts to file"""
        try:
            alerts = self.get_recent_alerts(limit=1000)
            
            if format_type == 'json':
                filename = filename or f"alerts_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                with open(filename, 'w') as f:
                    json.dump(alerts, f, indent=2)
            
            elif format_type == 'csv':
                filename = filename or f"alerts_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
                with open(filename, 'w') as f:
                    f.write("timestamp,type,source_ip,severity,message,action_taken\n")
                    for alert in alerts:
                        f.write(f"{alert['timestamp']},{alert['type']},{alert['source_ip']},"
                               f"{alert['severity']},\"{alert['message']}\",{alert['action_taken']}\n")
            
            self.logger.info(f"Exported {len(alerts)} alerts to {filename}")
            return True
            
        except Exception as e:
            self.logger.error(f"Export failed: {e}")
            return False