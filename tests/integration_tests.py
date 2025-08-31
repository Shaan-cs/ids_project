# ids_project/tests/integration_tests.py
import subprocess
import time
import threading
from main import IDS

def test_nmap_scan():
    """Test IDS against Nmap scan"""
    print("Testing Nmap scan detection...")
    
    # Start IDS
    ids = IDS({'block_duration': 300})  # 5 minutes for testing
    ids_thread = threading.Thread(target=ids.start)
    ids_thread.daemon = True
    ids_thread.start()
    
    time.sleep(2)  # Give IDS time to start
    
    # Run Nmap scan
    try:
        result = subprocess.run(['nmap', '-p', '1-100', '127.0.0.1'], 
                              capture_output=True, text=True, timeout=30)
        print("Nmap scan completed")
    except subprocess.TimeoutExpired:
        print("Nmap scan timed out")
    
    # Check if detection occurred
    time.sleep(5)
    alerts = ids.logger.get_recent_alerts(limit=10)
    port_scan_alerts = [a for a in alerts if a['type'] == 'PORT_SCAN']
    
    if port_scan_alerts:
        print(f"✓ Port scan detected: {len(port_scan_alerts)} alerts")
        for alert in port_scan_alerts:
            print(f"  - {alert['message']}")
    else:
        print("✗ Port scan not detected")
    
    ids.stop()
    return len(port_scan_alerts) > 0

if __name__ == "__main__":
    print("Running integration tests...")
    test_nmap_scan()