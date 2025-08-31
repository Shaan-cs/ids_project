# ids_project/tests/unit_tests.py
import unittest
import tempfile
import os
from unittest.mock import Mock, patch
from core.detector import IntrusionDetector
from core.firewall import FirewallManager
from core.logger import IDSLogger

class TestIntrusionDetector(unittest.TestCase):
    def setUp(self):
        self.detector = IntrusionDetector()
    
    def test_port_scan_detection(self):
        # Test port scan detection
        mock_packet = Mock()
        mock_packet.haslayer.return_value = True
        mock_packet.__getitem__ = lambda self, key: Mock(src='192.168.1.100') if key == 'IP' else Mock(dport=80)
        
        # Simulate multiple port accesses
        for port in range(1, 25):
            mock_packet.__getitem__ = lambda self, key: Mock(src='192.168.1.100') if key == 'IP' else Mock(dport=port)
            self.detector.analyze_packet(mock_packet)
        
        # Should trigger port scan detection
        # (Actual detection would happen in the tracking logic)
        self.assertTrue(len(self.detector.port_scan_tracker['192.168.1.100']['ports']) > 0)

class TestFirewallManager(unittest.TestCase):
    @patch('subprocess.run')
    def test_block_ip_linux(self, mock_subprocess):
        with patch('platform.system', return_value='Linux'):
            firewall = FirewallManager()
            firewall.block_ip('192.168.1.100', 'Test')
            
            # Should call iptables command
            mock_subprocess.assert_called()

class TestIDSLogger(unittest.TestCase):
    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.temp_db.close()
        self.logger = IDSLogger(db_file=self.temp_db.name)
    
    def tearDown(self):
        os.unlink(self.temp_db.name)
    
    def test_log_alert(self):
        alert_data = {
            'timestamp': '2023-01-01T00:00:00',
            'type': 'TEST',
            'source_ip': '192.168.1.100',
            'message': 'Test alert',
            'severity': 'LOW'
        }
        
        self.logger.log_alert(alert_data)
        
        # Verify alert was logged to database
        alerts = self.logger.get_recent_alerts(limit=1)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]['type'], 'TEST')

if __name__ == '__main__':
    unittest.main()