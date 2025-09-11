# NetScanner UI Functionality Documentation

## Overview
This document describes the micro-level functionality of the NetScanner family monitoring dashboard. Each component, interaction, and data flow is documented to serve as a blueprint for integrating live data.

## 1. Navigation & Layout System

### 1.1 Sidebar Navigation
- **Toggle**: Hamburger menu (☰) in top-left toggles sidebar visibility
- **Slide Behavior**: Slides out 70% of screen width with backdrop blur
- **Auto-collapse**: Clicking outside sidebar or on any nav link collapses it
- **Sections**: Home, Live, Profiles, Devices, Hostnames

### 1.2 Status Bar
- **Title**: "NetScanner" centered at top
- **Clean Design**: No time display, no status icons
- **Responsive**: Adapts to sidebar state

## 2. Home Dashboard - Profile Management

### 2.1 Profile Cards System
**Default State**: No profiles exist, shows single circular "+" button

**Profile Card Structure**:
```
┌─────────────────────────────┐
│ [Badge] [Profile Picture]   │
│ Name                        │
│ Last seen: [time]           │
│ Last device: [device] [•]   │
│ Last accessed: [app]        │
│ Time online: [total]        │
└─────────────────────────────┘
```

**Card Interactions**:
- **Click Card**: Opens profile detail view
- **Alert Badge**: Red circle with count in top-right
- **Pulsing Dot**: Next to "Last device" indicates active usage
- **Time Online**: Sum of all category times

### 2.2 Add Profile Modal
**Trigger**: Click circular "+" button (only visible on home, when no modal open)

**Modal Structure**:
```
┌─────────────────────────────┐
│                    [X]      │
│ [Profile Picture Preview]   │
│ Click to change             │
│ Name: [input field]         │
│ [Cancel] [Save]             │
└─────────────────────────────┘
```

**Modal Logic**:
- **Visibility Control**: Hidden when on profile detail screen
- **Image Upload**: File input converts to base64, shows preview
- **Form Reset**: Clears on open/close
- **Validation**: Name required

## 3. Profile Detail View

### 3.1 Profile Header
**Layout**: `[←] [Profile Picture] [Name]`
- **Back Button**: Returns to home dashboard
- **Picture**: Same as profile card
- **Name**: Profile name only

### 3.2 Collapsible Sections System

#### 3.2.1 Connected Devices Section
**Header**: `Connected Devices [count] [▼/▶]`

**Device Grid Layout**:
```
┌─────────────────────────────┐
│ Device Name        [•]      │
│ IP: 192.168.1.100           │
│ MAC: aa:bb:cc:dd:ee:ff      │
│ Status: Online              │
│ Last seen: 2 min ago        │
└─────────────────────────────┘
```

**Device States**:
- **Online**: Green pulsing dot, "Online" status
- **Offline**: No dot, "Last seen: [time]" status
- **Sorting**: Online devices first, then offline
- **Count Display**: "3 online" or "Last seen: [time]" if none online

#### 3.2.2 Active Today Section
**Header**: `Active Today [total time] [▼/▶]`

**Category Structure**:
```
┌─────────────────────────────┐
│ [•] Social Media [2h 15m]   │
│   ├─ Instagram [1h 30m]     │
│   │  Device: iPhone 12      │
│   │  Last accessed: 5m ago  │
│   └─ Facebook [45m]         │
│       Device: MacBook Pro   │
│       Last accessed: 1h ago │
└─────────────────────────────┘
```

**Category Logic**:
- **Pulsing Dot**: Green dot pulses when category is active
- **Time Aggregation**: Sum of all apps in category
- **App Details**: Time spent, device name, last accessed
- **Expandable**: Click to show/hide apps
- **Nested Structure**: Categories contain apps

**App Timeline System**:
```
Instagram
  • 2:30 PM - 3:15 PM (45m)
  • 4:20 PM - 4:45 PM (25m)
  • 5:10 PM - 5:30 PM (20m)
```

**Timeline Features**:
- **No Header**: Just bullet points
- **Session Data**: Start time, end time, duration
- **Floating Text**: Same color as background
- **Nested Indentation**: Appears under app heading
- **Click to Expand**: Toggle visibility

#### 3.2.3 Alerts Section
**Header**: `Alerts [badge count] [▼/▶] [🗑️]`

**Alert Item Structure**:
```
┌─────────────────────────────┐
│ ⚠️  [Alert Title]           │
│    [Description]            │
│                    [Time]   │
└─────────────────────────────┘
```

**Alert States**:
- **Unseen**: Normal appearance, counted in badge
- **Seen**: Strikethrough text, dimmed, not counted
- **Click to Toggle**: Click alert to mark seen/unseen
- **Clear All**: Trash icon clears all alerts
- **Badge Updates**: Real-time count updates

## 4. Data Aggregation & Calculations

### 4.1 Time Online Calculation
**Formula**: Sum of all category times
```
Time Online = Σ(Category1 + Category2 + ... + CategoryN)
```

**Implementation**:
- **Category Level**: Sum of all apps in category
- **Profile Level**: Sum of all categories
- **Real-time**: Updates as categories change

### 4.2 Device Status Logic
**Online Detection**:
- **Pulsing Dot**: Indicates active usage
- **Status Text**: "Online" vs "Last seen: [time]"
- **Sorting Priority**: Online devices first

**Last Device Logic**:
- **Most Recent**: Device with latest activity
- **Pulsing Indicator**: Shows when actively in use
- **Fallback**: Shows last seen time if offline

### 4.3 Alert Badge System
**Badge Count**: Number of unseen alerts
**Updates Triggered By**:
- **Alert Toggle**: Clicking alert toggles seen/unseen
- **Clear All**: Removes all alerts, badge disappears
- **New Alerts**: Badge count increases

**Badge Display**:
- **Home Cards**: Top-right corner of each profile card
- **Profile Detail**: In alerts section header
- **Real-time**: Updates immediately on interaction

## 5. UI State Management

### 5.1 Modal State Control
**Add Profile Button Visibility**:
- **Hidden When**: Modal is open, on profile detail screen
- **Visible When**: On home screen, no modal open, no profiles exist

**State Variables**:
- `currentSection`: Tracks current view (home, profile-detail, etc.)
- `modalOpen`: Boolean for add profile modal state

### 5.2 Collapsible Section Logic
**Toggle Behavior**:
- **Click Header**: Expands/collapses section
- **Icon Rotation**: ▼ (expanded) / ▶ (collapsed)
- **Smooth Animation**: CSS transitions

**Section Dependencies**:
- **Devices**: Loads device data when expanded
- **Activity**: Loads app data when expanded
- **Alerts**: Loads alert data when expanded

## 6. Data Flow Architecture

### 6.1 Profile Data Structure
```javascript
Profile = {
  id: "profile_1",
  name: "John Doe",
  picture: "base64_image_data",
  devices: [
    {
      id: "device_1",
      name: "iPhone 12",
      ip: "192.168.1.100",
      mac: "aa:bb:cc:dd:ee:ff",
      status: "online",
      lastSeen: "2024-01-15T14:30:00Z"
    }
  ],
  activity: {
    categories: [
      {
        id: "social",
        name: "Social Media",
        totalTime: 135, // minutes
        apps: [
          {
            id: "instagram",
            name: "Instagram",
            time: 90,
            device: "iPhone 12",
            lastAccessed: "2024-01-15T14:25:00Z",
            timeline: [
              {
                start: "2024-01-15T14:00:00Z",
                end: "2024-01-15T14:45:00Z",
                duration: 45
              }
            ]
          }
        ]
      }
    ]
  },
  alerts: [
    {
      id: "alert_1",
      title: "Restricted App Usage",
      description: "Instagram used during study hours",
      time: "2024-01-15T14:30:00Z",
      seen: false
    }
  ]
}
```

### 6.2 Real-time Updates
**Data Refresh Triggers**:
- **Section Expansion**: Load data when section opens
- **User Interaction**: Update counts, badges, status
- **Time Intervals**: Periodic updates for live data

**Update Functions**:
- `loadProfiles()`: Loads all profile cards
- `loadProfileDevices()`: Loads device data for profile
- `loadProfileActivity()`: Loads app/category data
- `loadProfileAlerts()`: Loads alert data
- `updateAlertBadge()`: Updates badge counts

## 7. Live Tab - Real-time Network Monitoring

### 7.1 Live Profile Cards
**Profile Display**:
- **Small Cards**: Quarter size of home profile cards
- **Always Visible**: Shown whenever on Live tab
- **Profile Info**: Name, time online, online/offline status
- **Interactive**: Click to filter sessions by profile
- **Real-time Status**: Pulsing dot for online, gray for offline
- **Time Calculation**: Shows total session duration for each profile

**Card Layout**:
```
┌─────────────────┐
│       [J]       │  <- Avatar with first letter
│   John Doe      │  <- Name
│  ● Online       │  <- Status with dot
│    2h 30m       │  <- Time online
└─────────────────┘
```

### 7.2 Time Range Filtering
**Time Range Options**:
- **Last 15 min**: Show only recent sessions
- **Last 1 hour**: Show sessions from past hour
- **Last 2 hours**: Show sessions from past 2 hours
- **Today**: Show all sessions from today
- **24 Hour Limit**: Live tab never shows sessions older than 24 hours

**Implementation**:
- **Default**: 15 minutes selected
- **Real-time Updates**: Sessions refresh every 5 minutes
- **Session Aggregation**: Data aggregated every 5 minutes to reduce noise
- **Position**: Above the traffic table, below profile cards

### 7.3 Multi-Select Filter System
**Category and App Filters**:
- **Side-by-side Layout**: Categories and apps in separate containers using flexbox
- **Responsive Design**: Stacks vertically on mobile, side-by-side on desktop
- **Synchronized Filtering**: Selecting categories filters available apps
- **Count Badges**: Shows number of sessions per category
- **Multi-select**: Can select multiple categories and apps simultaneously
- **CSS Implementation**: Uses `display: flex` with `flex: 1` for equal width distribution

**Alert Filter**:
- **Toggle Badge**: Click alert badge to filter sessions with alerts
- **Visual State**: Badge changes color when active filter
- **Count Display**: Shows total alert count
- **Hidden from Active Filters**: Alerts are applied but not shown in filter list
- **Position**: Next to "Live Network Traffic" title

### 7.4 Active Filters Display
**Filter Management**:
- **Active Filter Chips**: Shows all currently active filters (except alerts)
- **Remove Filters**: Click "X" on any filter chip to remove it
- **Auto-hide**: Section hidden when no filters active
- **Real-time Updates**: Updates immediately when filters change
- **Position**: Below time range, above traffic table

### 7.4 Live Sessions Table
**Table Columns**:
- **Device**: Friendly name (top) + IP address (bottom)
- **Category**: Color-coded category badges
- **Accessing**: App name + start time
- **Duration**: Session duration in minutes/hours
- **Data**: Total data transferred (KB/MB/GB)
- **Status**: Active/Inactive with pulsing dot indicator

**Session Data Structure**:
```javascript
Session = {
    id: "session_123",
    device: "iPhone 12",
    deviceIp: "192.168.1.100",
    profile: "profile_1",
    category: "Social Media",
    categoryId: "social",
    app: "Instagram",
    appId: "instagram",
    url: "instagram.com",
    startTime: "2024-01-15T14:00:00Z",
    duration: 25, // minutes
    isActive: true,
    dataBytes: 15728640, // bytes
    lastSeen: "2024-01-15T14:25:00Z",
    // Enrichment fields
    hostname: "google.com",
    organization: "Google LLC",
    asn: 15169,
    hasAlert: false
}
```

### 7.4.1 Session Aggregation Logic
**5-Minute Aggregation Window**:
- **Time Buckets**: Sessions grouped into 5-minute intervals
- **Noise Reduction**: Prevents table from being overwhelmed with micro-sessions
- **Real-time Updates**: New sessions appear immediately, old ones aggregate
- **Window Size**: 5 minutes provides balance between detail and performance

**Session Start/End Detection**:
- **Start Trigger**: First packet detected for app/device combination
- **End Trigger**: No packets for 5+ minutes OR explicit session termination
- **Duration Calculation**: `endTime - startTime` in minutes
- **Active Status**: Session considered active if last packet within 5 minutes

**Data Size Aggregation**:
- **Cumulative Bytes**: Sum of all packets in session window
- **Formatting Thresholds**: 
  - 0.1 KB = "0.1 KB"
  - 1 MB = "1.0 MB" 
  - 1024 MB = "1.0 GB"
- **Real-time Updates**: Data size increases as session continues

### 7.4.2 Session Lifecycle Management
**Session States**:
- **Active**: Currently receiving packets (pulsing green dot)
- **Inactive**: No packets for 5+ minutes (gray dot)
- **Completed**: Session ended, moved to history

**Session Persistence**:
- **24-Hour Window**: Live tab only shows sessions from last 24 hours
- **Auto-Archive**: Older sessions moved to historical data
- **Memory Management**: Prevents unlimited session accumulation

**Session Merging**:
- **Same App/Device**: Multiple short sessions merged if within 5-minute window
- **Gap Detection**: Sessions separated by >5 minutes remain separate
- **Duration Recalculation**: Merged sessions get combined duration

### 7.4.3 Data Flow Architecture
**Packet Processing Pipeline**:
```
Raw Packets → App Detection → Device Mapping → Session Creation → Aggregation → Table Display
```

**Real-time Updates**:
- **Packet Arrival**: Triggers session update or creation
- **Table Refresh**: Updates every 2 seconds for active sessions
- **Sorting Priority**: Active sessions always appear first
- **Visual Indicators**: Pulsing dots for active, static for inactive

**Performance Optimization**:
- **Lazy Loading**: Only visible sessions fully processed
- **Batch Updates**: Multiple changes grouped together
- **Memory Cleanup**: Old sessions removed from memory
- **Efficient Sorting**: Pre-sorted data structures for fast table updates

### 7.4.4 Technical Implementation Details
**Session Data Generation**:
- **Sample Data**: 100 sessions generated with random dates over 7 days
- **Device Distribution**: 8 different device types (iPhone, MacBook, etc.)
- **App Variety**: Multiple apps per category for realistic testing
- **Time Distribution**: Random start times within 7-day window
- **Duration Range**: 1-120 minutes per session for variety

**Data Formatting Functions**:
```javascript
formatDataBytes(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

formatDuration(minutes) {
    if (minutes < 60) return `${minutes}m`;
    const hours = Math.floor(minutes / 60);
    const mins = minutes % 60;
    return mins > 0 ? `${hours}h ${mins}m` : `${hours}h`;
}
```

**Session Filtering Logic**:
- **Time Range**: Filter by last 15min, 1hour, 2hours, or today
- **Profile Filter**: Show sessions for selected profiles only
- **Category Filter**: Filter by app categories (social, gaming, work, etc.)
- **App Filter**: Filter by specific applications
- **Alert Filter**: Show only sessions with alerts

**Real-time Session Updates**:
- **Active Detection**: Sessions marked active if last packet within 5 minutes
- **Status Changes**: Visual indicators update when sessions become active/inactive
- **Data Accumulation**: Byte counts increase as sessions continue
- **Auto-refresh**: Table updates every 2 seconds for live data

### 7.5 Table Sorting System
**Three-State Sorting**:
- **Unsorted**: Default state, active sessions first, then by recency
- **Ascending**: Click once for ascending sort
- **Descending**: Click twice for descending sort
- **Unsorted**: Click third time returns to default (unsorted)

**Sortable Columns**:
- **Device**: Sort by device name
- **Category**: Sort by category name
- **Accessing**: Sort by app name
- **Duration**: Sort by session duration
- **Data**: Sort by data transferred
- **Status**: Sort by active/inactive status

**Sample Data**:
- **100 Rows**: Generated with random dates over last 7 days
- **Random Distribution**: Sessions spread across different times
- **Time Filter Testing**: Allows testing of all time range filters
- **Realistic Data**: Mix of active/inactive sessions with varying durations

### 7.6 Cell-Based Filtering
**Click to Filter**:
- **Device Cell**: Adds profile filter for that device's owner
- **Category Cell**: Adds category filter
- **App Cell**: Adds application filter
- **Status Cell**: Toggles alert filter if session has alerts

**Implementation**:
- **Smart Filtering**: Automatically determines appropriate filter type
- **Duplicate Prevention**: Won't add duplicate filters
- **Visual Feedback**: Clicked cells highlighted temporarily

### 7.7 Data Formatting
**Data Size Formatting**:
- **Bytes**: Shows as "B" for very small amounts
- **Kilobytes**: Shows as "KB" starting at 0.1 KB
- **Megabytes**: Shows as "MB" starting at 1 MB
- **Gigabytes**: Shows as "GB" starting at 1024 MB

**Duration Formatting**:
- **Minutes**: Shows as "25m" for under 1 hour
- **Hours**: Shows as "2h" for exact hours
- **Mixed**: Shows as "2h 30m" for hours + minutes

**Time Formatting**:
- **Recent**: "Just now", "5m ago", "2h ago"
- **Older**: Shows date for sessions over 24 hours old

### 7.8 Session Status Indicators
**Active Sessions**:
- **Pulsing Green Dot**: Indicates session is currently active
- **Real-time Updates**: Status updates as sessions become active/inactive
- **Priority Sorting**: Active sessions always appear first

**Inactive Sessions**:
- **Gray Dot**: No animation, indicates session ended
- **Last Seen Time**: Shows when session was last active
- **Floating Behavior**: Inactive sessions move down as new ones appear

### 7.9 Refresh Handling
**F5 Refresh Behavior**:
- **Section Persistence**: Maintains current section after refresh
- **Data Reload**: Reloads appropriate data for current section
- **State Restoration**: Restores filter states and sorting

**Implementation**:
- **localStorage**: Saves current section before page unload
- **Load Handler**: Restores section and data on page load
- **No Default Reset**: Never goes back to dashboard on refresh

## 8. Error Handling & Debugging

### 8.1 JavaScript Error Prevention
**DOM Element Safety**:
- **Null Checks**: All DOM element access includes null checks
- **Safe Property Access**: Uses conditional checks before accessing properties
- **Graceful Degradation**: Functions continue to work even if elements are missing
- **Error Logging**: Console logging for debugging and error tracking

**Implementation Example**:
```javascript
function updateAddButtonVisibility() {
    const addContainer = document.getElementById('add-profile-container');
    const bottomButton = document.getElementById('bottom-add-button');
    
    // Safe access with null checks
    if (addContainer) addContainer.style.display = 'none';
    if (bottomButton) bottomButton.style.display = 'none';
}
```

### 8.2 Debugging System
**Console Logging**:
- **Function Entry**: Logs when functions are called with parameters
- **Data Validation**: Logs data structures and element availability
- **Error Tracking**: Captures and logs JavaScript errors
- **Performance Monitoring**: Tracks function execution times

**Debug Functions**:
- `loadLiveProfiles()`: Logs profile data and container availability
- `loadTimeFilters()`: Logs tab count and click events
- `loadSessionsTable()`: Logs filtered session count
- `showProfileDetail()`: Logs profile object being displayed

### 8.3 Sample Data Fallbacks
**API Error Handling**:
- **Network Failures**: Falls back to sample data when API calls fail
- **Empty Responses**: Shows sample data when API returns empty results
- **Data Validation**: Ensures data structure integrity before processing

**Sample Data Structure**:
- **Home Profiles**: 3 sample profiles (John Doe, Jane Smith, Kids)
- **Live Sessions**: 100 sessions with random dates over 7 days
- **Profile Details**: Complete device, activity, and alert data
- **Realistic Distribution**: Mix of active/inactive sessions with varying durations

### 8.4 Layout & CSS Improvements
**Flexbox Implementation**:
- **Filter Layout**: Categories and apps side-by-side using `display: flex`
- **Responsive Design**: Stacks vertically on mobile, side-by-side on desktop
- **Equal Distribution**: Uses `flex: 1` for equal width distribution
- **Gap Spacing**: Consistent 20px gap between filter groups

**Mobile Responsive Updates**:
- **Breakpoint**: 768px for mobile/desktop transition
- **Filter Behavior**: `flex-direction: column` on mobile
- **Profile Cards**: Responsive grid with `minmax(150px, 1fr)` on mobile
- **Touch-Friendly**: Larger touch targets for mobile interaction

**CSS Class Fixes**:
- **Profile Detail**: Added `tab-content` class for proper visibility control
- **Element Safety**: Null checks prevent CSS property access errors
- **State Management**: Proper active/inactive class handling

## 9. Integration Points for Live Data

### 9.1 Network Monitoring Integration
**Device Discovery**:
- **New Device Detection**: Show badge on home
- **Device Status**: Online/offline based on network activity
- **Last Seen**: Update when device goes offline

**Traffic Analysis**:
- **App Detection**: Identify applications from network traffic
- **Time Tracking**: Measure session durations
- **Category Classification**: Group apps into categories

### 9.1.1 Enrichment Pipeline (Immediate Lookups, Cached)
- **Goal**: Resolve destination IP to hostname and ownership for classification and readability.
- **Sources**:
  - DNS/SNI observed during capture (preferred)
  - Reverse DNS (PTR) fallback
  - RDAP whois via `ipwhois` for `organization` and `asn`
- **Storage**: `enriched_data` table with fields `ip_address`, `hostname`, `organization`, `asn`, `isp`, `updated_at`.
- **Behavior**:
  - On first sight of an unknown IP, enqueue immediate enrichment (no waiting 24h).
  - On success, cache and set `updated_at`. Next refresh allowed after TTL (24h default).
  - On failure, retry with backoff: 60s → 5m → 30m (cap). Backoff is per‑IP.
  - User Rules always override enrichment for `category/app`.
- **Optional nDPI** (Settings: Off / Fallback / On): If enabled, use nDPI labels when DNS/SNI is missing to suggest `app/category` (rules still override).

### 9.1.2 3‑Second Server Logger
- Runs every 3 seconds; prints recent sessions with:
  - timestamp, `src_ip` → `dst_ip`, protocol:port, total bytes, active flag
  - plus `org`, `asn`, `host` from `enriched_data` when available
- Example: `[SESSION_LOG] … -> 142.250.72.14 HTTPS:443 bytes=12345 active=False org=Google LLC asn=AS15169 host=google.com`
- Unknowns are enqueued once for immediate enrichment; subsequent cycles will show enriched data.

### 9.2 Behavioral Analysis
**Usage Patterns**:
- **Session Detection**: Start/end times for app usage
- **Device Correlation**: Link apps to specific devices
- **Time Aggregation**: Calculate total time per category

**Alert Generation**:
- **Rule Violations**: Detect restricted app usage
- **Time-based Alerts**: Usage during restricted hours
- **Threshold Alerts**: Excessive usage warnings

### 9.3 Data Persistence
**Database Tables**:
- `user_profiles`: Profile information and pictures
- `profile_device_assignments`: Device-to-profile mapping
- `device_activity`: Real-time device status
- `app_sessions`: App usage sessions with timestamps
- `alerts`: Alert messages and seen status

## 10. Performance Considerations

### 10.1 Lazy Loading
**Section Data**: Load only when section is expanded
**Image Optimization**: Base64 encoding for profile pictures
**Efficient Updates**: Update only changed elements

### 10.2 Real-time Updates
**Polling Intervals**: Configurable refresh rates
**Event-driven**: Update on user interactions
**Batch Updates**: Group multiple changes together

## 11. Future Enhancements

### 11.1 Advanced Features
**Timeline Visualization**: Graphical timeline for app usage
**Predictive Analytics**: Usage pattern predictions
**Advanced Filtering**: Date ranges, app categories, devices

### 11.2 Mobile Optimization
**Touch Gestures**: Swipe to navigate
**Responsive Design**: Adapt to different screen sizes
**Offline Support**: Cache data for offline viewing

---

## 12. DEVICES SCREEN FUNCTIONALITY

### 12.1 Device Discovery & Management
**Purpose**: Comprehensive network device management with detailed information gathering
**Location**: Devices tab in main navigation

#### 12.1.1 Device Table Structure
**Columns**:
- **Device Name**: Friendly name or hostname
- **IP Address**: Current IP address (monospace font)
- **MAC Address**: Hardware MAC address (monospace font)
- **Manufacturer**: Device manufacturer (Apple, Samsung, etc.)
- **Model**: Specific device model
- **Status**: Online/Offline with visual indicator
- **Last Seen**: Time since last activity
- **Actions**: Details button for each device

#### 12.1.2 Device Information Gathering
**Data Sources**:
- **Network Scanning**: ARP table, ping sweeps
- **MAC Address Lookup**: OUI database for manufacturer identification
- **Device Fingerprinting**: Port scanning, service detection
- **DNS Resolution**: Hostname resolution for IP addresses
- **SNMP Queries**: For managed network devices

**Sample Device Data**:
```javascript
{
    id: 1,
    name: 'iPhone 12 Pro',
    ip: '192.168.1.100',
    mac: '00:1B:44:11:3A:B7',
    manufacturer: 'Apple',
    model: 'iPhone 12 Pro',
    status: 'online',
    lastSeen: new Date(Date.now() - 5 * 60 * 1000),
    profile: 'John Doe'
}
```

### 12.2 Device Table Functionality

#### 12.2.1 Sorting System
**Implementation**: 3-state sorting (unsorted → asc → desc → unsorted)
**Sortable Columns**: All columns except Actions
**Visual Indicators**: ↑ for ascending, ↓ for descending

**Sort Logic**:
```javascript
function sortDevicesTable(column) {
    if (devicesData.sortColumn === column) {
        devicesData.sortDirection = devicesData.sortDirection === 'asc' ? 'desc' : 'asc';
    } else {
        devicesData.sortColumn = column;
        devicesData.sortDirection = 'asc';
    }
    // Sort and update indicators
}
```

#### 12.2.2 Device Status Indicators
**Online Status**: Green dot with "Online" text
**Offline Status**: Gray dot with "Offline" text
**Last Seen Formatting**: "Just now", "5m ago", "2h ago", "1d ago"

### 12.3 Device Details Modal

#### 12.3.1 Device Information Section
**Layout**: Grid of information cards
**Information Displayed**:
- Device Name
- IP Address
- MAC Address
- Manufacturer
- Model
- Status
- Last Seen
- Assigned Profile

#### 12.3.2 Device Traffic Sessions Table
**Purpose**: Show traffic sessions for the selected device
**Table Structure**: Same as Live tab traffic table
**Columns**: Device, Category, Accessing, Duration, Data, Status
**Sorting**: Same 3-state sorting as Live tab
**Cell Clicking**: Filter by clicked value (same behavior as Live tab)

### 12.4 Cell Clicking Behavior (Fixed)

#### 12.4.1 Live Tab Cell Clicking
**Previous Behavior**: Clicking device cell filtered by profile owner
**New Behavior**: Clicking device cell filters by device name directly
**Implementation**:
```javascript
case 'device':
    // Filter by device name directly, not by profile
    if (!liveData.filters.devices.includes(value)) {
        liveData.filters.devices.push(value);
        updateActiveFilters();
        loadSessionsTable();
    }
    break;
```

#### 12.4.2 Devices Tab Cell Clicking
**Behavior**: Clicking any cell adds that value as a filter
**Filter Types**:
- **Device**: Filter by device name
- **Category**: Filter by category ID
- **App**: Filter by app ID
- **Duration**: Filter by duration value
- **Data**: Filter by data size
- **Status**: Filter by active/inactive status

### 12.5 Filter Management System

#### 12.5.1 Active Filters Display
**Location**: Below time range filters in Live tab
**Filter Types Supported**:
- Profile filters
- Category filters
- App filters
- Device filters (new)
- Duration filters (new)
- Data range filters (new)
- Status filters (new)

#### 12.5.2 Filter Removal
**Method**: Click "X" button on active filter
**Functions**:
- `removeDeviceFilter(deviceName)`
- `removeDurationFilter(duration)`
- `removeDataRangeFilter(dataRange)`
- `removeStatusFilter(status)`

### 12.6 Network Scanning Integration

#### 12.6.1 Refresh Devices
**Function**: `refreshDevices()`
**Action**: Reload device list from current data
**UI**: Refresh button with icon

#### 12.6.2 Scan Network
**Function**: `scanNetwork()`
**Action**: Trigger new network scan for devices
**UI**: Scan button with icon
**Future Integration**: Connect to backend scanning service

### 12.7 Data Flow Architecture

#### 12.7.1 Device Data Loading
1. **Initialize**: `initializeDevices()` called when Devices tab is shown
2. **Load Data**: `loadDevices()` generates sample data
3. **Render Table**: `renderDevicesTable()` populates table
4. **Setup Sorting**: Event listeners attached to column headers

#### 12.7.2 Device Details Flow
1. **Click Details**: `showDeviceDetails(deviceId)` called
2. **Load Info**: `loadDeviceInfo(device)` populates device information
3. **Load Traffic**: `loadDeviceTrafficSessions(deviceId)` gets traffic data
4. **Render Tables**: Both info grid and traffic table rendered
5. **Show Modal**: Modal displayed with all information

### 12.8 Error Handling & Debugging

#### 12.8.1 Console Logging
**Functions Logged**:
- `initializeDevices()`: "Initializing devices section..."
- `loadDevices()`: "Loading devices..."
- `renderDevicesTable()`: "Rendering devices table..."
- `showDeviceDetails()`: "Showing device details for device ID: X"
- `sortDevicesTable()`: "Sorting devices by: X"

#### 12.8.2 Error Prevention
**Null Checks**: All DOM element access protected
**Fallback Data**: Sample data provided for testing
**Graceful Degradation**: Functions continue if elements missing

### 12.9 Future Enhancements

#### 12.9.1 Real Network Integration
**ARP Table Scanning**: Read system ARP table
**Ping Sweeps**: Scan IP ranges for active devices
**MAC Address Lookup**: OUI database integration
**Device Fingerprinting**: Port scanning, service detection

#### 12.9.2 Advanced Device Management
**Device Renaming**: Edit friendly names
**Profile Assignment**: Assign devices to profiles
**Device Grouping**: Group devices by type/location
**Historical Data**: Track device connection history

---

This documentation serves as the foundation for integrating live network monitoring data into the existing UI framework. Each function and interaction is designed to work seamlessly with real-time data while maintaining the current user experience.

## 13. Hostnames, Categories, Apps, and Rules

### 13.1 Data Model (SQLite)
- Categories (`hn_categories`): id, name, description, is_system, created_at, updated_at
- Apps/Sites (`hn_apps`): id, category_id, name, slug, is_system, created_at, updated_at
- Match Rules (`hn_rules`): id, app_id, type (domain|ip|cidr|sni|regex), value, source (manual|auto|ndpi), confidence (0–1), created_at, updated_at
- Defaults: `Uncategorized` category and `Unknown` app are created automatically.

### 13.2 REST Endpoints
- `POST /api/hostnames/bootstrap` → ensure defaults
- `GET/POST/PUT/DELETE /api/hostnames/categories`
- `GET/POST/PUT/DELETE /api/hostnames/apps`
- `GET/POST/PUT/DELETE /api/hostnames/rules`
- Classifier: `POST /api/network/classify` with `{ hostname, sni, ip }` → returns `{ category, app, rule_source, confidence }`

### 13.3 Classification Precedence
1. Local rules (exact domain → root domain → ip)
2. Cache (future)
3. DPI (optional nDPI) if enabled (future)
4. Fallback → `Uncategorized` / `Unknown` with low confidence

### 13.4 UI Workflow (Hostnames Tab)
- Three panels:
  - Categories: list, add, edit, delete; selecting filters apps
  - Apps & Sites: list, add, edit, delete tied to selected category; selecting filters rules
  - Match Rules: list, add (domain/IP), edit, delete tied to selected app
- Quick-add flow (from Live/Devices row) planned: create domain rule and pick category/app.

### 13.5 Raspberry Pi Notes
- No API keys required. Uses DNS/SNI and local rules; optionally integrates nDPI if installed.
- Packages: tshark, libpcap, pyshark, scapy, tldextract, publicsuffix2, dnspython.

### 13.6 Logging
- Each endpoint logs the function name, parameters, and return status to aid troubleshooting.

## 14. Devices Tab – Finalized Layout & Behavior

### 14.1 Columns and Semantics
- **Device**: friendly name (may be blank), then IP and MAC underneath in smaller monospace.
- **Manufacturer**: vendor/manufacturer string if known.
- **Status**: Active (pulsing green) or Offline · Last seen X ago.
- Clicking a row toggles an inline expander with time range filters, alert badge, and a traffic table (same sort rules as Live).

### 14.2 Sorting
- Three-state sort per column (↕/↑/↓). Third click clears sort to unsorted.
- Indicators mirror Live table visuals.

### 14.3 Expander (Details)
- Friendly name input with clear (×); blur or Enter saves and updates the row.
- Time ranges: 15 min, 1 hour, 2 hours, Today.
- Alert toggle filters expander’s sessions.
- Traffic sessions table copies Live columns; sortable; includes quick “Add rule”.

### 14.4 Dummy Data and Resilience
- If backend data isn’t ready, the Devices tab renders sample devices.
- Rendering waits for containers to be present; if not ready (e.g., on refresh), it retries on the next animation frame to avoid empty tables.

## 15. Live Tab – Classification & Quick Rules

### 15.1 Auto Classification
- While rendering rows, if category/app are unknown, UI POSTs to `/api/network/classify` with `{ hostname|sni|ip }` and displays `{ category, app }`.
- Manual rules always override.

### 15.2 Quick Add Rule
- Each row exposes “Add rule”, which:
  1) Ensures defaults exist
  2) Finds/creates the Category and App/Site
  3) Adds a domain rule (if hostname) or IP rule
  4) Navigates to Rules tab and focuses the affected Category/App

## 16. Rules Tab – Unified Rules Manager

### 16.1 Structure
- Three panels:
  - Categories: add/edit/delete; selecting filters Apps
  - Apps & Sites: add/edit/delete; selecting filters Rules
  - Match Rules: add/edit/delete domain or IP rules tied to the selected App/Site

### 16.2 Badge
- Rules menu badge shows count of rules tied to `Unknown` app or to apps under `Uncategorized` to prioritize clean-up.

### 16.3 API (no keys required)
- `POST /api/hostnames/bootstrap` – ensure defaults exist
- `GET/POST/PUT/DELETE /api/hostnames/categories`
- `GET/POST/PUT/DELETE /api/hostnames/apps`
- `GET/POST/PUT/DELETE /api/hostnames/rules`
- `POST /api/network/classify` – rule-first DNS/SNI/IP classification

### 16.4 Data Model
- `hn_categories(id, name, description, is_system, created_at, updated_at)`
- `hn_apps(id, category_id, name, slug, is_system, created_at, updated_at)`
- `hn_rules(id, app_id, type[domain|ip|cidr|sni|regex], value, source[manual|auto|ndpi], confidence, created_at, updated_at)`
- Defaults auto-created: `Uncategorized` and `Unknown`.

## 17. Navigation & State Persistence

### 17.1 Hash + Local Storage
- Active tab is stored in URL hash (e.g., `#live`, `#devices`, `#rules`) and in localStorage as `currentSection`.
- On load/refresh, app prefers hash; else uses `currentSection`; else falls back to `home`.
- Back/forward navigation updates the UI (hashchange listener). Programmatic `showSection()` updates hash for deep links.

### 17.2 Robust Activation
- `showSection()` safely resolves nav links and section elements; normalizes legacy names (`hostnames` → `rules`) and falls back to `home` if needed.
- Section data loaders run on each switch; basic guards prevent duplicate handler attachment.

---

## 18. Developer Notes – API Examples (no keys required)

Replace `127.0.0.1:5002` with your server’s host/IP (e.g., the Raspberry Pi).

### 18.1 Bootstrap defaults
```bash
curl -s -X POST http://127.0.0.1:5002/api/hostnames/bootstrap
```

### 18.2 Categories
Create:
```bash
curl -s -X POST http://127.0.0.1:5002/api/hostnames/categories \
  -H "Content-Type: application/json" \
  -d '{"name":"Social Media"}'
```
List:
```bash
curl -s http://127.0.0.1:5002/api/hostnames/categories
```
Update:
```bash
curl -s -X PUT http://127.0.0.1:5002/api/hostnames/categories/1 \
  -H "Content-Type: application/json" \
  -d '{"name":"Entertainment"}'
```
Delete:
```bash
curl -s -X DELETE http://127.0.0.1:5002/api/hostnames/categories/1
```

### 18.3 Apps & Sites
Create (under category_id=1):
```bash
curl -s -X POST http://127.0.0.1:5002/api/hostnames/apps \
  -H "Content-Type: application/json" \
  -d '{"category_id":1, "name":"Instagram"}'
```
List (optionally filter by category_id):
```bash
curl -s http://127.0.0.1:5002/api/hostnames/apps?category_id=1
```
Update:
```bash
curl -s -X PUT http://127.0.0.1:5002/api/hostnames/apps/1 \
  -H "Content-Type: application/json" \
  -d '{"name":"Instagram Mobile"}'
```
Delete:
```bash
curl -s -X DELETE http://127.0.0.1:5002/api/hostnames/apps/1
```

### 18.4 Match Rules
Create domain rule (app_id=1):
```bash
curl -s -X POST http://127.0.0.1:5002/api/hostnames/rules \
  -H "Content-Type: application/json" \
  -d '{"app_id":1, "type":"domain", "value":"instagram.com"}'
```
Create IP rule:
```bash
curl -s -X POST http://127.0.0.1:5002/api/hostnames/rules \
  -H "Content-Type: application/json" \
  -d '{"app_id":1, "type":"ip", "value":"151.101.1.140"}'
```
List (optionally filter by app_id):
```bash
curl -s http://127.0.0.1:5002/api/hostnames/rules?app_id=1
```
Update:
```bash
curl -s -X PUT http://127.0.0.1:5002/api/hostnames/rules/1 \
  -H "Content-Type: application/json" \
  -d '{"value":"instagram-cdn.com"}'
```
Delete:
```bash
curl -s -X DELETE http://127.0.0.1:5002/api/hostnames/rules/1
```

### 18.5 Classifier
DNS/SNI/IP classification (rule-first):
```bash
curl -s -X POST http://127.0.0.1:5002/api/network/classify \
  -H "Content-Type: application/json" \
  -d '{"hostname":"instagram.com"}'
```
Response:
```json
{ "category":"Social Media", "app":"Instagram", "rule_source":"manual", "confidence":1.0 }
```
