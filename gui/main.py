# ids_project/gui/main.py
#!/usr/bin/env python3
import sys
import argparse
from PyQt5.QtWidgets import QApplication
from core.ids_core import IDSCore
from gui.dashboard import IDSDashboard, run_gui

def main():
    parser = argparse.ArgumentParser(description="IDS/IPS System with GUI")
    parser.add_argument('--no-gui', action='store_true', help="Run in console mode without GUI")
    parser.add_argument('--interface', '-i', help="Network interface to monitor")
    parser.add_argument('--log-file', '-l', default='ids.log', help="Log file path")
    parser.add_argument('--db-file', '-d', default='ids.db', help="Database file path")
    parser.add_argument('--block-duration', '-b', type=int, default=600, 
                       help="Block duration in seconds (default: 600)")
    
    args = parser.parse_args()
    
    # Create IDS core instance
    ids_core = IDSCore({
        'interface': args.interface,
        'log_file': args.log_file,
        'db_file': args.db_file,
        'block_duration': args.block_duration
    })
    
    if args.no_gui:
        # Run in console mode
        print("Starting IDS/IPS in console mode...")
        print("Press Ctrl+C to stop")
        
        try:
            ids_core.start()
        except KeyboardInterrupt:
            print("\nShutting down IDS...")
            ids_core.stop()
    else:
        # Run with GUI
        run_gui(ids_core)

if __name__ == "__main__":
    main()