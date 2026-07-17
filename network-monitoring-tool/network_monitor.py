#!/usr/bin/env python3
"""
Network Monitoring Tool - Entry Point
"""
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from src.cli import cli

if __name__ == "__main__":
    cli()
