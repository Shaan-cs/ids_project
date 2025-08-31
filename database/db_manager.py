# ids_project/database/db_manager.py
import sqlite3
import json
import csv
from datetime import datetime, timedelta
from collections import defaultdict

class DatabaseManager:
    def __init__(self, db_file="ids.db"):
        self.db_file = db_file
        self.init_database()
    
    def init_database(self):
        """Initialize database with required tables"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Create alerts table if not exists
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
        
        # Create traffic_stats table if not exists
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
        
        # Create blocked_ips table if not exists
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
        
        # Create settings table if not exists
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key TEXT UNIQUE,
                value TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def log_alert(self, alert_data):
        """Log an alert to the database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO alerts (timestamp, alert_type, source_ip, severity, message, action_taken)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            alert_data.get('timestamp'),
            alert_data.get('type'),
            alert_data.get('source_ip'),
            alert_data.get('severity', 'MEDIUM'),
            alert_data.get('message'),
            alert_data.get('action_taken', 'Logged')
        ))
        
        conn.commit()
        conn.close()
    
    def log_traffic_stats(self, stats_data):
        """Log traffic statistics to the database"""
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
    
    def log_blocked_ip(self, ip_data):
        """Log IP blocking action to the database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO blocked_ips (ip_address, block_time, unblock_time, reason, action)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            ip_data.get('ip_address'),
            ip_data.get('block_time'),
            ip_data.get('unblock_time'),
            ip_data.get('reason'),
            ip_data.get('action', 'blocked')
        ))
        
        conn.commit()
        conn.close()
    
    def get_recent_alerts(self, limit=100):
        """Get recent alerts from the database"""
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
    
    def get_filtered_alerts(self, alert_type=None, severity=None, start_time=None, limit=1000):
        """Get filtered alerts from the database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        query = '''
            SELECT timestamp, alert_type, source_ip, severity, message, action_taken
            FROM alerts 
            WHERE 1=1
        '''
        params = []
        
        if alert_type:
            query += ' AND alert_type = ?'
            params.append(alert_type)
        
        if severity:
            query += ' AND severity = ?'
            params.append(severity)
        
        if start_time:
            query += ' AND timestamp >= ?'
            params.append(start_time.isoformat())
        
        query += ' ORDER BY timestamp DESC LIMIT ?'
        params.append(limit)
        
        cursor.execute(query, params)
        
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
    
    def get_statistics(self, start_time=None):
        """Get statistics from the database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Base query
        query = 'SELECT alert_type, severity, source_ip FROM alerts'
        params = []
        
        if start_time:
            query += ' WHERE timestamp >= ?'
            params.append(start_time.isoformat())
        
        cursor.execute(query, params)
        
        stats = {
            'total_alerts': 0,
            'alert_types': defaultdict(int),
            'severity_dist': defaultdict(int),
            'top_source_ips': defaultdict(int),
            'blocked_ips': 0
        }
        
        for row in cursor.fetchall():
            stats['total_alerts'] += 1
            stats['alert_types'][row[0]] += 1
            stats['severity_dist'][row[1]] += 1
            stats['top_source_ips'][row[2]] += 1
        
        # Get blocked IPs count
        query = 'SELECT COUNT(DISTINCT ip_address) FROM blocked_ips'
        if start_time:
            query += ' WHERE block_time >= ?'
            cursor.execute(query, (start_time.isoformat(),))
        else:
            cursor.execute(query)
        
        stats['blocked_ips'] = cursor.fetchone()[0] or 0
        
        conn.close()
        return stats
    
    def export_alerts_to_csv(self, file_path):
        """Export alerts to CSV file"""
        try:
            alerts = self.get_filtered_alerts(limit=10000)  # Get up to 10,000 alerts
            
            with open(file_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Timestamp', 'Type', 'Source IP', 'Severity', 'Message', 'Action Taken'])
                
                for alert in alerts:
                    writer.writerow([
                        alert['timestamp'],
                        alert['type'],
                        alert['source_ip'],
                        alert['severity'],
                        alert['message'],
                        alert['action_taken']
                    ])
            
            return True
        except Exception as e:
            print(f"Export to CSV failed: {e}")
            return False
    
    def export_alerts_to_json(self, file_path):
        """Export alerts to JSON file"""
        try:
            alerts = self.get_filtered_alerts(limit=10000)  # Get up to 10,000 alerts
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(alerts, f, indent=2)
            
            return True
        except Exception as e:
            print(f"Export to JSON failed: {e}")
            return False
    
    def clear_alerts(self):
        """Clear all alerts from the database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM alerts')
        cursor.execute('DELETE FROM sqlite_sequence WHERE name="alerts"')  # Reset autoincrement
        
        conn.commit()
        conn.close()
    
    def save_setting(self, key, value):
        """Save a setting to the database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO settings (key, value)
            VALUES (?, ?)
        ''', (key, value))
        
        conn.commit()
        conn.close()
    
    def load_setting(self, key, default=None):
        """Load a setting from the database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        cursor.execute('SELECT value FROM settings WHERE key = ?', (key,))
        result = cursor.fetchone()
        
        conn.close()
        return result[0] if result else default