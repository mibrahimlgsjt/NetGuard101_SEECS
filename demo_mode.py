import random
import time

class DemoModeManager:
    """
    Provides mock data for the application when running in Demo Mode
    or on non-Android platforms.
    """
    
    def __init__(self):
        self._last_data_check = time.time()
        self._mock_data = {
            'mobile_rx': 1024 * 1024 * 5,  # 5 MB
            'mobile_tx': 1024 * 1024 * 2,  # 2 MB
            'total_rx': 1024 * 1024 * 150, # 150 MB
            'total_tx': 1024 * 1024 * 50   # 50 MB
        }
        self.blocked_apps = ["com.facebook.katana", "com.instagram.android"]

    def get_mock_data_usage(self):
        """Simulate increasing data usage."""
        current_time = time.time()
        elapsed = current_time - self._last_data_check
        self._last_data_check = current_time
        
        # Add random increment based on elapsed time
        inc = int(elapsed * 1024 * 50) # 50KB per second
        
        self._mock_data['mobile_rx'] += int(inc * random.uniform(0.5, 1.5))
        self._mock_data['mobile_tx'] += int(inc * 0.2 * random.uniform(0.5, 1.5))
        self._mock_data['total_rx'] += int(inc * 1.2)
        self._mock_data['total_tx'] += int(inc * 0.3)
        
        return self._mock_data

    def get_mock_running_apps(self):
        """Return a list of simulated running apps."""
        apps = ["com.android.chrome", "com.google.android.youtube", "com.whatsapp"]
        if random.random() < 0.3:
            apps.append(random.choice(self.blocked_apps))
        return apps
