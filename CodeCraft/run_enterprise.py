#!/usr/bin/env python3
"""
SentinelWatch Pro Enterprise Edition Launcher
"""

import os
import sys

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from enterprise_app import SentinelWatchEnterprise
    
    if __name__ == '__main__':
        print("🚀 Starting SentinelWatch Pro Enterprise Edition...")
        print("🔒 Advanced Cybersecurity Platform with AI-Powered Threat Detection")
        print("🌐 Enterprise Integrations | 📊 Compliance Monitoring | 🤖 Machine Learning")
        print("=" * 80)
        
        app = SentinelWatchEnterprise()
        app.run(host='0.0.0.0', port=5000, debug=True)

except ImportError as e:
    print(f"❌ Failed to import enterprise modules: {e}")
    print("🔄 Falling back to original SentinelWatch Pro...")
    
    # Fallback to original app
    try:
        from app import app, socketio
        print("✅ Original SentinelWatch Pro loaded successfully")
        socketio.run(app, host='0.0.0.0', port=5000, debug=True)
    except Exception as fallback_error:
        print(f"❌ Fallback also failed: {fallback_error}")
        sys.exit(1)