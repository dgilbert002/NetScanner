#!/usr/bin/env python3
"""
Clear demo data and prepare for real network monitoring
"""

import os
import sys
import sqlite3

# Get database path
db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'src', 'database', 'enhanced_network_monitor.db')

def clear_demo_data():
    """Clear all demo data from the database using direct SQL"""
    print("🧹 Clearing demo data from database...")
    
    # Check if database exists
    if not os.path.exists(db_path):
        print("📊 No database found - starting fresh")
        return
    
    try:
        # Connect to database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Get all table names
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        
        # Tables to clear (skip system tables)
        tables_to_clear = [
            'devices', 'traffic_sessions', 'website_visits', 
            'enriched_data', 'network_stats', 'user_sessions',
            'content_analysis'
        ]
        
        # Clear each table
        for table in tables_to_clear:
            try:
                cursor.execute(f"DELETE FROM {table}")
                print(f"  ✓ Cleared {table}")
            except sqlite3.OperationalError:
                # Table doesn't exist, skip
                pass
        
        # Commit changes
        conn.commit()
        conn.close()
        
        print("✅ Demo data cleared successfully!")
        print("📊 Database is now ready for real network monitoring data")
        
    except Exception as e:
        print(f"⚠️ Could not clear database: {e}")
        print("  This is okay - the app will create fresh tables if needed")

if __name__ == "__main__":
    clear_demo_data()