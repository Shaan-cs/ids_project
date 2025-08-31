# ids_project/core/firewall.py
import platform
import subprocess
import threading
import time
from datetime import datetime, timedelta

class FirewallManager:
    def __init__(self, block_duration=600):  # Default: 10 minutes
        self.system = platform.system()
        self.block_duration = block_duration
        self.blocked_ips = {}  # ip: (block_time, unblock_time, reason)
        self.lock = threading.Lock()
        
        # Start cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_expired_blocks)
        self.cleanup_thread.daemon = True
        self.cleanup_thread.start()
    
    def block_ip(self, ip, reason="Suspicious activity"):
        """Block an IP address based on the operating system"""
        if self.is_ip_blocked(ip):
            return False  # Already blocked
        
        block_time = datetime.now()
        unblock_time = block_time + timedelta(seconds=self.block_duration)
        
        with self.lock:
            self.blocked_ips[ip] = (block_time, unblock_time, reason)
        
        try:
            if self.system == "Windows":
                self._block_ip_windows(ip)
            elif self.system == "Linux":
                self._block_ip_linux(ip)
            else:
                print(f"Unsupported OS for automatic blocking: {self.system}")
                return False
            
            print(f"Blocked IP {ip} until {unblock_time}. Reason: {reason}")
            return True
            
        except Exception as e:
            print(f"Failed to block IP {ip}: {e}")
            with self.lock:
                if ip in self.blocked_ips:
                    del self.blocked_ips[ip]
            return False
    
    def _block_ip_windows(self, ip):
        """Block IP on Windows using netsh advfirewall"""
        # Create firewall rule to block the IP
        rule_name = f"IDS_Block_{ip}"
        
        # Check if rule already exists
        check_cmd = ['netsh', 'advfirewall', 'firewall', 'show', 'rule', f'name={rule_name}']
        result = subprocess.run(check_cmd, capture_output=True, text=True)
        
        if "No rules match the specified criteria" not in result.stdout:
            # Rule exists, delete it first
            delete_cmd = ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule_name}']
            subprocess.run(delete_cmd, capture_output=True)
        
        # Add new block rule
        block_cmd = [
            'netsh', 'advfirewall', 'firewall', 'add', 'rule',
            f'name={rule_name}',
            'dir=in',
            'action=block',
            f'remoteip={ip}',
            'protocol=any',
            'enable=yes'
        ]
        
        subprocess.run(block_cmd, check=True, capture_output=True)
    
    def _block_ip_linux(self, ip):
        """Block IP on Linux using iptables"""
        # Check if rule already exists
        check_cmd = ['iptables', '-L', 'INPUT', '-n', '--line-numbers']
        result = subprocess.run(check_cmd, capture_output=True, text=True)
        
        if ip in result.stdout:
            return  # Already blocked
        
        # Add block rule
        block_cmd = ['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP']
        subprocess.run(block_cmd, check=True, capture_output=True)
    
    def unblock_ip(self, ip):
        """Unblock an IP address"""
        if not self.is_ip_blocked(ip):
            return False
        
        try:
            if self.system == "Windows":
                self._unblock_ip_windows(ip)
            elif self.system == "Linux":
                self._unblock_ip_linux(ip)
            
            with self.lock:
                if ip in self.blocked_ips:
                    del self.blocked_ips[ip]
            
            print(f"Unblocked IP {ip}")
            return True
            
        except Exception as e:
            print(f"Failed to unblock IP {ip}: {e}")
            return False
    
    def _unblock_ip_windows(self, ip):
        """Unblock IP on Windows"""
        rule_name = f"IDS_Block_{ip}"
        delete_cmd = ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule_name}']
        subprocess.run(delete_cmd, check=True, capture_output=True)
    
    def _unblock_ip_linux(self, ip):
        """Unblock IP on Linux"""
        # Find rule number
        check_cmd = ['iptables', '-L', 'INPUT', '-n', '--line-numbers']
        result = subprocess.run(check_cmd, capture_output=True, text=True)
        
        for line in result.stdout.split('\n'):
            if ip in line:
                rule_num = line.split()[0]
                delete_cmd = ['iptables', '-D', 'INPUT', rule_num]
                subprocess.run(delete_cmd, check=True, capture_output=True)
                break
    
    def is_ip_blocked(self, ip):
        """Check if an IP is currently blocked"""
        with self.lock:
            return ip in self.blocked_ips
    
    def get_blocked_ips(self):
        """Get all currently blocked IPs with their info"""
        with self.lock:
            return {
                ip: {
                    'block_time': block_time.isoformat(),
                    'unblock_time': unblock_time.isoformat(),
                    'reason': reason,
                    'time_remaining': (unblock_time - datetime.now()).total_seconds()
                }
                for ip, (block_time, unblock_time, reason) in self.blocked_ips.items()
            }
    
    def _cleanup_expired_blocks(self):
        """Periodically clean up expired blocks"""
        while True:
            time.sleep(60)  # Check every minute
            current_time = datetime.now()
            
            with self.lock:
                ips_to_remove = [
                    ip for ip, (_, unblock_time, _) in self.blocked_ips.items()
                    if unblock_time <= current_time
                ]
            
            for ip in ips_to_remove:
                self.unblock_ip(ip)
    
    def set_block_duration(self, duration_seconds):
        """Set the default block duration"""
        self.block_duration = duration_seconds