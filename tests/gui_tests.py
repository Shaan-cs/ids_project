# ids_project/tests/gui_tests.py
import unittest
from unittest.mock import Mock, patch
from PyQt5.QtWidgets import QApplication
from gui.dashboard import IDSDashboard

# Initialize QApplication once for all tests
app = QApplication([])

class TestIDSDashboard(unittest.TestCase):
    def setUp(self):
        # Mock the IDS core
        self.mock_core = Mock()
        self.mock_core.status.return_value = {
            'running': True,
            'uptime_seconds': 3600,
            'total_packets': 1000,
            'blocked_ips_count': 2,
            'blocked_ips': {
                '192.168.1.100': {
                    'block_time': '2023-01-01T12:00:00',
                    'unblock_time': '2023-01-01T12:10:00',
                    'reason': 'Test block',
                    'time_remaining': 300
                }
            }
        }
        
        self.mock_core.sniffer.get_stats.return_value = {
            'total_packets': 1000,
            'tcp_packets': 800,
            'udp_packets': 150,
            'icmp_packets': 50,
            'http_packets': 100,
            'bytes_transferred': 1024000,
            'packets_per_second': 50.5,
            'uptime_seconds': 3600
        }
        
        self.dashboard = IDSDashboard(self.mock_core)
    
    def test_dashboard_initialization(self):
        """Test that dashboard initializes correctly"""
        self.assertIsNotNone(self.dashboard)
        self.assertEqual(self.dashboard.windowTitle(), "IDS/IPS Dashboard")
    
    def test_status_update(self):
        """Test status update functionality"""
        self.dashboard.update_dashboard()
        
        # Check that status labels were updated
        self.assertIn("1000", self.dashboard.packet_count_label.text())
        self.assertIn("2", self.dashboard.blocked_ips_label.text())
    
    @patch('database.db_manager.DatabaseManager.get_recent_alerts')
    def test_recent_alerts_update(self, mock_get_alerts):
        """Test recent alerts update"""
        mock_get_alerts.return_value = [{
            'timestamp': '2023-01-01T12:00:00',
            'type': 'TEST',
            'source_ip': '192.168.1.100',
            'severity': 'MEDIUM',
            'message': 'Test alert',
            'action_taken': 'Logged'
        }]
        
        self.dashboard.update_recent_alerts()
        
        # Check that alerts table was updated
        self.assertEqual(self.dashboard.recent_alerts_table.rowCount(), 1)
        self.assertEqual(self.dashboard.recent_alerts_table.item(0, 1).text(), 'TEST')
    
    def test_ip_validation(self):
        """Test IP address validation"""
        self.assertTrue(self.dashboard.is_valid_ip("192.168.1.1"))
        self.assertTrue(self.dashboard.is_valid_ip("8.8.8.8"))
        self.assertFalse(self.dashboard.is_valid_ip("invalid"))
        self.assertFalse(self.dashboard.is_valid_ip("192.168.1.256"))
        self.assertFalse(self.dashboard.is_valid_ip("192.168.1"))

if __name__ == '__main__':
    unittest.main()