#!/usr/bin/env python3
"""
Build script for creating WAFPierce executable.
Run this script to build the standalone executable.

Usage:
    python build_exe.py
"""
import subprocess
import sys
import os

def main():
    print("=" * 60)
    print("WAFPierce Executable Builder")
    print("=" * 60)
    
    # Check if PyInstaller is installed
    try:
        import PyInstaller
        print(f"✓ PyInstaller found (version {PyInstaller.__version__})")
    except ImportError:
        print("✗ PyInstaller not found. Installing...")
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'pyinstaller'])
        print("✓ PyInstaller installed")
    
    # Install project dependencies
    print("\nInstalling project dependencies...")
    requirements_file = os.path.join(os.path.dirname(__file__), 'requirements.txt')
    if os.path.exists(requirements_file):
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', requirements_file])
        print("✓ Dependencies installed")
    
    # Build the executable
    print("\nBuilding executable...")
    print("-" * 60)
    
    spec_file = os.path.join(os.path.dirname(__file__), 'wafpierce.spec')
    
    result = subprocess.run([
        sys.executable, '-m', 'PyInstaller',
        '--clean',
        '--noconfirm',
        spec_file
    ], cwd=os.path.dirname(__file__))
    
    if result.returncode == 0:
        print("-" * 60)
        print("\n✓ Build successful!")
        print(f"\nExecutable location: {os.path.join(os.path.dirname(__file__), 'dist', 'WAFPierce.exe')}")
        print("\nYou can distribute this single .exe file to users.")
    else:
        print("\n✗ Build failed. Check the output above for errors.")
        sys.exit(1)

if __name__ == '__main__':
    main()
