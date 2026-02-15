#!/usr/bin/env python3
"""
Entry point for WAFPierce GUI application.
This file is used by PyInstaller to create the executable.
"""
import sys
import os

# When running as a PyInstaller bundle, update paths for bundled resources
if getattr(sys, 'frozen', False):
    # Running as compiled executable
    bundle_dir = sys._MEIPASS
    # Update working directory to bundle location
    os.chdir(bundle_dir)
else:
    # Running as script
    bundle_dir = os.path.dirname(os.path.abspath(__file__))

# Add the bundle directory to path
if bundle_dir not in sys.path:
    sys.path.insert(0, bundle_dir)

def main():
    """Launch the WAFPierce GUI."""
    from wafpierce.gui import main as gui_main
    gui_main()

if __name__ == '__main__':
    main()
