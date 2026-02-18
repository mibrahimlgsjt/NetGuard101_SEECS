import platform
from datetime import datetime

# Check if we are running on Android
IS_ANDROID = "android" in platform.uname().release.lower() or "android" in platform.system().lower()

class AndroidUtils:
    """
    Utility class to handle Android-specific APIs via Pyjnius.
    Falls back to mock data on non-Android systems.
    """
    
    def __init__(self):
        global IS_ANDROID
        self.TrafficStats = None
        self.Activity = None
        self.Context = None
        self.UsageStatsManager = None
        self.Settings = None
        self.Intent = None
        self.Uri = None
        
        self.demo_manager = None
        
        if IS_ANDROID:
            try:
                from jnius import autoclass, cast
                self.TrafficStats = autoclass('android.net.TrafficStats')
                PythonActivity = autoclass('org.kivy.android.PythonActivity')
                self.Activity = PythonActivity.mActivity
                self.Context = autoclass('android.content.Context')
                self.UsageStatsManager = cast('android.app.usage.UsageStatsManager', 
                                              self.Activity.getSystemService(self.Context.USAGE_STATS_SERVICE))
                self.Settings = autoclass('android.provider.Settings')
                self.Intent = autoclass('android.content.Intent')
                self.Uri = autoclass('android.net.Uri')
            except Exception as e:
                print(f"AndroidUtils Init Error: {e}")
                IS_ANDROID = False # Fallback
        
        if not IS_ANDROID:
            # Silencing mock initialization logs
            # print("INFO: Android API not found. Using MOCK data (Demo Mode).")
            from demo_mode import DemoModeManager
            self.demo_manager = DemoModeManager()

    def get_data_usage(self):
        """
        Returns a dictionary with 'mobile_rx', 'mobile_tx', 'total_rx', 'total_tx' in bytes.
        """
        if IS_ANDROID and self.TrafficStats:
            try:
                return {
                    "mobile_rx": self.TrafficStats.getMobileRxBytes(),
                    "mobile_tx": self.TrafficStats.getMobileTxBytes(),
                    "total_rx": self.TrafficStats.getTotalRxBytes(),
                    "total_tx": self.TrafficStats.getTotalTxBytes()
                }
            except Exception as e:
                print(f"Error fetching traffic stats: {e}")
                return {"mobile_rx": 0, "mobile_tx": 0, "total_rx": 0, "total_tx": 0}
        
        # Mock Data
        if self.demo_manager:
            return self.demo_manager.get_mock_data_usage()
        
        return {"mobile_rx": 0, "mobile_tx": 0, "total_rx": 0, "total_tx": 0}

    def has_usage_stats_permission(self):
        """Check if the app has permission to access usage stats."""
        if IS_ANDROID:
            try:
                from jnius import autoclass
                AndroidProcess = autoclass('android.os.Process')
                app_ops = self.Activity.getSystemService(self.Context.APP_OPS_SERVICE)
                mode = app_ops.checkOpNoThrow(
                    "android:get_usage_stats",
                    AndroidProcess.myUid(), 
                    self.Activity.getPackageName()
                )
                return mode == app_ops.MODE_ALLOWED
            except Exception:
                return False
        return True # Mock always has permission

    def request_usage_stats_permission(self):
        """Redirect user to settings to grant usage stats permission."""
        if IS_ANDROID:
            try:
                intent = self.Intent(self.Settings.ACTION_USAGE_ACCESS_SETTINGS)
                self.Activity.startActivity(intent)
            except Exception as e:
                print(f"Failed to open settings: {e}")
        else:
            print("MOCK: Requesting Usage Stats Permission (Always Granted)")
            return True

    def get_running_apps(self):
        """
        Returns a list of recently active package names.
        Requires PACKAGE_USAGE_STATS permission.
        """
        if IS_ANDROID and self.UsageStatsManager:
            try:
                # Query for last 10 seconds
                from jnius import autoclass
                System = autoclass('java.lang.System')
                end_time = System.currentTimeMillis()
                start_time = end_time - 1000 * 10
                
                stats = self.UsageStatsManager.queryUsageStats(
                    self.UsageStatsManager.INTERVAL_DAILY, start_time, end_time
                )
                
                apps = []
                if stats:
                    iterator = stats.iterator()
                    while iterator.hasNext():
                        stat = iterator.next()
                        if stat.getTotalTimeInForeground() > 0:
                            apps.append(stat.getPackageName())
                return list(set(apps))
            except Exception as e:
                print(f"Error getting running apps: {e}")
                return []
        
        # Mock Data
        if self.demo_manager:
            return self.demo_manager.get_mock_running_apps()
        return []

    def block_app_action(self, package_name):
        """
        Simulate blocking by bringing this app to front or showing a toast.
        """
        if IS_ANDROID:
            try:
                # Simple "Block" by bringing our app to front
                intent = self.Intent(self.Context, self.Activity.getClass())
                intent.setFlags(self.Intent.FLAG_ACTIVITY_NEW_TASK)
                self.Activity.startActivity(intent)
                
                # Toast
                from jnius import autoclass
                Toast = autoclass('android.widget.Toast')
                msg = f"Access to {package_name} is BLOCKED by IDPS!"
                Toast.makeText(self.Activity, msg, Toast.LENGTH_LONG).show()
                return True
            except Exception as e:
                print(f"Error in block action: {e}")
                return False
        else:
            # Mock Action (Silenced)
            # print(f"[MOCK] Blocked app: {package_name}")
            return True

android_utils = AndroidUtils()
