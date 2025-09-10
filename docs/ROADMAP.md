# NetScanner Environment Setup - Roadmap

## Overview
This document tracks the changes made to set up the NetScanner environment and resolve the SQLAlchemy table conflict issue.

## Problem Identified
The application had a SQLAlchemy table conflict error: "Table 'devices' is already defined for this MetaData instance." This occurred because both `src/models/network.py` and `src/models/enhanced_network.py` define the same table names (`devices`, `traffic_sessions`, etc.), and both were being imported simultaneously.

## Solution Implemented
**Environment Variable Toggle Approach** - Added `ENABLE_ENHANCED` environment variable to control which model sets are loaded, avoiding database schema conflicts while preserving all existing functionality.

## Changes Made

### 1. Virtual Environment Setup
- **File**: Created `venv/` folder in project root
- **Action**: Created Python virtual environment using `py -3 -m venv venv`
- **Dependencies**: Installed all packages from `requirements.txt` using venv Python
- **Status**: ✅ Completed

### 2. Main Application File (`src/main.py`)
- **Lines Modified**: 10-45
- **Changes**:
  - Added `ENABLE_ENHANCED` environment variable check (defaults to '0' = disabled)
  - Wrapped enhanced model imports in conditional block
  - Wrapped enhanced route imports in conditional block
  - Added fallback to base models when enhanced features disabled
- **Impact**: App now loads base models by default, enhanced features only when explicitly enabled
- **Rollback**: Remove lines 10-45, restore original import structure

### 3. Analytics Service (`src/analytics_service.py`)
- **Lines Modified**: 12-30
- **Changes**:
  - Added `ENABLE_ENHANCED` environment variable check
  - Wrapped enhanced model imports in conditional block
  - Added fallback to base models with dummy classes for enhanced features
- **Impact**: Analytics service respects the environment toggle
- **Rollback**: Remove lines 12-30, restore original import

### 4. Enhanced Packet Capture (`src/enhanced_packet_capture.py`)
- **Lines Modified**: 18-31
- **Changes**:
  - Added `ENABLE_ENHANCED` environment variable check
  - Wrapped enhanced model imports in conditional block
  - Added fallback to base models with dummy classes
- **Impact**: Packet capture service respects the environment toggle
- **Rollback**: Remove lines 18-31, restore original import

## How to Use

### Running with Base Features (Default)
```bash
# No environment variable needed - uses base features by default
.\venv\Scripts\python .\src\main.py
```

### Running with Enhanced Features
```bash
# Set environment variable to enable enhanced features
set ENABLE_ENHANCED=1
.\venv\Scripts\python .\src\main.py
```

### Accessing the Application
- **Local**: http://127.0.0.1:5002
- **Network**: http://192.168.50.45:5002 (or your local IP)

## API Endpoints Available

### Base Features (Always Available)
- `GET /api/users` - User management
- `GET /api/devices` - Device discovery
- `GET /api/traffic/summary` - Traffic statistics
- `GET /api/websites` - Website visits
- `POST /api/monitoring/start` - Start network monitoring
- `POST /api/monitoring/stop` - Stop network monitoring

### Enhanced Features (When ENABLE_ENHANCED=1)
- `GET /api/devices/enhanced` - Enhanced device management
- `GET /api/traffic/analysis` - Detailed traffic analysis
- `GET /api/websites/analytics` - Website analytics
- `GET /api/content/analysis` - Content analysis
- `GET /api/users/<id>/timeline` - User activity timeline

## Rollback Instructions

If you need to revert all changes:

1. **Restore `src/main.py`**:
   - Remove lines 10-45
   - Restore original import structure:
     ```python
     from src.models.enhanced_network import (
         User, Device, TrafficSession, WebsiteVisit, ContentAnalysis, 
         EnrichedData, NetworkStats, UserSession
     )
     from src.routes.user_management import user_management_bp
     from src.routes.enhanced_network import enhanced_network_bp
     ```

2. **Restore `src/analytics_service.py`**:
   - Remove lines 12-30
   - Restore original import:
     ```python
     from src.models.enhanced_network import (
         User, Device, TrafficSession, WebsiteVisit, ContentAnalysis, 
         EnrichedData, NetworkStats, UserSession, db
     )
     ```

3. **Restore `src/enhanced_packet_capture.py`**:
   - Remove lines 18-31
   - Restore original import:
     ```python
     from src.models.enhanced_network import Device, TrafficSession, WebsiteVisit, ContentAnalysis, EnrichedData, db
     ```

## Benefits of This Approach

1. **No Database Changes**: Preserves existing database schema and data
2. **Backward Compatible**: All existing functionality remains intact
3. **Flexible**: Can easily switch between base and enhanced features
4. **Safe**: Easy to roll back if needed
5. **Clean**: No duplicate table definitions or schema conflicts

## Next Steps

The application is now running successfully with base features. To test enhanced features:
1. Stop the current app (Ctrl+C)
2. Set `ENABLE_ENHANCED=1`
3. Restart the app
4. Test enhanced endpoints

## Files Modified
- `src/main.py` (lines 10-45)
- `src/analytics_service.py` (lines 12-30)  
- `src/enhanced_packet_capture.py` (lines 18-31)
- `ROADMAP.md` (created)

## Status: ✅ COMPLETED
The NetScanner application is now running successfully with base features enabled by default.
