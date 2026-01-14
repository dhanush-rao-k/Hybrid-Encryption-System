"""
Hybrid Encryption System - Main Launcher
Allows user to choose between CLI and GUI applications
"""

import sys
import os
from pathlib import Path

def main():
    """Main launcher menu."""
    print("\n" + "="*60)
    print("     HYBRID ENCRYPTION SYSTEM - LAUNCHER")
    print("="*60 + "\n")

    print("Choose an interface:")
    print("1. GUI Application (Recommended)")
    print("2. CLI Application (Command Line)")
    print("3. Exit")
    print("-"*60)

    choice = input("Select (1-3): ").strip()

    if choice == "1":
        print("\nLaunching GUI application...")
        try:
            from gui import main as gui_main
            gui_main()
        except ImportError as e:
            print(f"Error: Could not import GUI module: {e}")
            print("Make sure gui.py is in the same directory")
            sys.exit(1)
    elif choice == "2":
        print("\nLaunching CLI application...")
        try:
            from app import main as cli_main
            cli_main()
        except ImportError as e:
            print(f"Error: Could not import CLI module: {e}")
            print("Make sure app.py is in the same directory")
            sys.exit(1)
    elif choice == "3":
        print("Goodbye!")
        sys.exit(0)
    else:
        print("Invalid choice. Please try again.")
        main()

if __name__ == "__main__":
    main()
