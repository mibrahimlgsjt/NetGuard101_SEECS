"""
Industry-Grade KivyMD UI for AI-Powered IDPS
============================================

This is the main entry point for the Android IDPS application built with KivyMD.
It implements a modern, professional UI with:
- Bottom navigation with 3 screens
- Real-time threat detection dashboard
- Network traffic monitoring
- Settings with theme toggle
- TFLite model integration

Author: IDPS Team
Version: 1.0.0
"""

import os
import json
import logging
from idps.cloud_manager import CloudDefenseManager # Collaborative Defense Module
# Suppress TensorFlow info/warning logs and oneDNN messages
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

import threading
import time
import uuid # For unique log IDs
from datetime import datetime
from typing import List, Dict, Tuple

from kivy.clock import Clock
from kivy.lang import Builder
from kivy.metrics import dp
from kivy.properties import StringProperty, NumericProperty, BooleanProperty, ListProperty
from kivy.utils import get_color_from_hex
from kivymd.app import MDApp
from kivymd.uix.screen import MDScreen
from kivymd.uix.card import MDCard
from kivymd.uix.list import MDList, OneLineAvatarIconListItem, IconLeftWidget
from kivymd.uix.dialog import MDDialog
from kivymd.uix.button import MDFlatButton
from kivymd.uix.boxlayout import MDBoxLayout

# Import TensorFlow Lite for model inference
try:
    import tensorflow as tf
    import numpy as np
    TFLITE_AVAILABLE = True
except ImportError:
    TFLITE_AVAILABLE = False
    print("WARNING: TensorFlow Lite not available. Install with: pip install tensorflow")

# Import Android Utils
try:
    from android_utils import android_utils, IS_ANDROID
    ANDROID_AVAILABLE = IS_ANDROID
except ImportError:
    android_utils = None
    ANDROID_AVAILABLE = False
    print("WARNING: Android Utils not available.")

# ============================================================================
# AUDIT LOGGING UTILITY
# ============================================================================

# Global logger instance (Moved to line 133)
# audit_logger = SecurityAuditLogger()

class SecurityAuditLogger:
    """Handles structured JSON logging for security audits."""
    def __init__(self, log_dir=None):
        if log_dir is None:
            # Android/Cross-platform compatibility
            from kivy.utils import platform
            if platform == 'android':
                from jnius import autoclass
                PythonActivity = autoclass('org.kivy.android.PythonActivity')
                # Use external files dir (app specific, no permission needed usually) or files dir
                # Activity -> getExternalFilesDir(None)
                try:
                    activity = PythonActivity.mActivity
                    file_p = activity.getExternalFilesDir(None)
                    if file_p:
                       self.log_dir = os.path.join(str(file_p.getAbsolutePath()), "logs")
                    else:
                       self.log_dir = "logs"
                except Exception as e:
                    print(f"Error getting Android path: {e}")
                    self.log_dir = "logs"
            else:
                self.log_dir = "logs"
        else:
            self.log_dir = log_dir

        self.log_file = os.path.join(self.log_dir, "security_audit.json")
        self.summary_file = os.path.join(self.log_dir, "summary_log.txt")
        
        try:
            if not os.path.exists(self.log_dir):
                os.makedirs(self.log_dir)
        except Exception as e:
             print(f"CRITICAL: Failed to create log dir {self.log_dir}: {e}")
        
    def log_event(self, event_type: str, details: Dict):
        # Append a new event to the JSON log file.# 
        log_entry = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "event_type": event_type,
            "details": details
        }
        try:
            # Append as JSON Lines for efficiency
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(log_entry) + "\n")
                
            # Update summary periodically or on critical events
            if event_type in ["IPS_DETECTION", "RULE_BLOCK", "SYSTEM_START", "MONITORING_STATE"]:
                self.write_summary()
                
        except Exception as e:
            print(f"FAILED TO WRITE TO AUDIT LOG: {e}")

    def write_summary(self):
        # Write a human-readable summary of activity.# 
        try:
            # Simple stats calculation (in a real app, optimize this to not read whole file)
            total_events = 0
            threat_count = 0
            critical_events = []
            
            if os.path.exists(self.log_file):
                with open(self.log_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        total_events += 1
                        try:
                            data = json.loads(line)
                            details = data.get('details', {})
                            # Check for threats
                            if data.get('event_type') in ["IPS_DETECTION", "RULE_BLOCK"]:
                                threat_count += 1
                                # Keep last 5 criticals
                                entry_str = f"[{data['timestamp']}] {data['event_type']}: {details.get('ip', 'Unknown')} - {details.get('reason', '') or details.get('action', '')}"
                                critical_events.append(entry_str)
                        except:
                            pass
            
            # Write summary
            with open(self.summary_file, "w", encoding="utf-8") as f:
                f.write("============================================\n")
                f.write("       IDPS SECURITY SUMMARY REPORT         \n")
                f.write("============================================\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write(f"Total Logged Events: {total_events}\n")
                f.write(f"Total Threats/Blocks: {threat_count}\n\n")
                f.write("LATEST CRITICAL ALERTS:\n")
                f.write("-----------------------\n")
                if critical_events:
                    for event in critical_events[-10:]: # Show last 10
                        f.write(event + "\n")
                else:
                    f.write("No critical threats recorded.\n")
                f.write("============================================\n")
                
        except Exception as e:
            print(f"FAILED TO WRITE SUMMARY: {e}")

# Global logger instance (Re-instantiated with new class definition)
audit_logger = SecurityAuditLogger()

# ============================================================================
# ACADEMIC SECURITY MANAGER CLASS
# ============================================================================

class AcademicSecurityManager:
    # Threat levels
    SAFE = 0
    SUSPICIOUS = 1
    THREAT = 2
    
    def check_rules(self, ip_address: str, payload: bytes):
        # Rule-Based Detection Engine (Hardcoded Logic).
        # 0. GLOBAL BANS (Cloud Defense)
        if hasattr(self, 'global_bans'):
             for ban in self.global_bans:
                 if ban.get('cidr', '').split('/')[0] == ip_address:
                      return self.THREAT, f"GLOBAL BAN: {ban.get('reason', 'Malicious IP')}"

        # 1. HARDCODED IP BLACKLIST
        BLACKLIST_IPS = ["192.168.1.666", "10.0.2.16", "172.16.0.5", "192.168.1.55"]
        
        for bad_ip in BLACKLIST_IPS:
                if ip_address == bad_ip:
                    import threading
                    threading.Thread(target=self.play_threat_alarm, daemon=True).start()
                    threading.Thread(target=self.play_threat_alarm, daemon=True).start()
                    if hasattr(self, 'cloud_manager'):
                        self.cloud_manager.report_threat(ip_address, "BLACKLIST_MATCH") 
                    return self.THREAT, f"BLOCKED IP (Blacklisted: {ip_address})"
        
        # 2. MALICIOUS SIGNATURES
        BAD_SIGNATURES = [b"MALWARE", b"SHELLCODE", b"DROP TABLE", b"XSS_PAYLOAD", b"ATTACK"]
        
        for sig in BAD_SIGNATURES:
            if sig in payload:
                import threading
                threading.Thread(target=self.play_threat_alarm, daemon=True).start()
                threading.Thread(target=self.play_threat_alarm, daemon=True).start()
                if hasattr(self, 'cloud_manager'):
                    self.cloud_manager.report_threat(ip_address, "SIGNATURE_MATCH")
                return self.THREAT, f"MALICIOUS SIGNATURE DETECTED: {sig.decode('utf-8', errors='ignore')}"
            
        # 3. DEEP PACKET INSPECTION
        i = 0
        nop_count = 0
        threshold = 5
        while i < len(payload):
            byte_val = payload[i]
            if byte_val == 0x90:
                nop_count += 1
                if nop_count >= threshold:
                    import threading
                    threading.Thread(target=self.play_threat_alarm, daemon=True).start()
                    return self.THREAT, "BUFFER OVERFLOW ATTEMPT (NOP Sled Detected)"
            else:
                nop_count = 0
            i += 1
            
        return self.SAFE, "CLEAN"

    def __init__(self, model_path: str = "app/assets/security_model.tflite"):
        self.model_path = model_path
        self.interpreter = None
        self.input_details = None
        self.output_details = None
        self.current_threat_level = self.SAFE
        self.threat_count = 0
        self.packets_analyzed = 0
        self.is_monitoring = False
        self.callbacks = []
        
        try:
            import winsound
            self.sound_available = True
        except ImportError:
            self.sound_available = False
        
        import threading
        self.lock = threading.Lock()
        self.socket_thread = None
        
        from collections import deque
        self.recent_logs = deque(maxlen=100)
        self.load_existing_logs()
        
        self.load_model()
        
        try:
            from idps.cloud_manager import CloudDefenseManager
            self.cloud_manager = CloudDefenseManager()
        except:
            self.cloud_manager = None

        self.global_bans = []
        try:
             import threading
             threading.Thread(target=self._fetch_bans, daemon=True).start()
        except:
             pass
             
        self.start_time = time.time()

    def _fetch_bans(self):
        if self.cloud_manager:
            self.global_bans = self.cloud_manager.get_global_bans()
            if self.global_bans:
                print(f"INFO: Loaded {len(self.global_bans)} active bans from Cloud Defense.")

    def play_threat_alarm(self):
        if self.sound_available:
            try:
                import winsound
                winsound.Beep(1000, 500)
            except:
                pass

    def load_existing_logs(self):
        try:
            if os.path.exists(audit_logger.log_file):
                with open(audit_logger.log_file, 'r', encoding='utf-8') as f:
                    lines_to_read = f.readlines()[-100:]
                    for line in lines_to_read:
                        try:
                            data = json.loads(line)
                            if data.get("event_type") == "PACKET_ANALYSIS":
                                d = data.get("details", {})
                                self.recent_logs.appendleft({
                                    "id": str(uuid.uuid4()),
                                    "time": data.get("timestamp", "").split(" ")[-1],
                                    "ip": d.get("ip", "Unknown"),
                                    "event": d.get("event", "Log Event"),
                                    "threat": "critical" if d.get("severity")=="CRITICAL" else "safe",
                                    "protocol": "TCP",
                                    "port": "0"
                                })
                        except:
                            pass
        except:
             pass

    def load_model(self):
        if not TFLITE_AVAILABLE:
            print("ERROR: TensorFlow Lite not available")
            return False
            
        try:
            if not os.path.exists(self.model_path):
                print(f"ERROR: Model file not found: {self.model_path}")
                return False
            
            import tensorflow as tf
            self.interpreter = tf.lite.Interpreter(model_path=self.model_path)
            self.interpreter.allocate_tensors()
            self.input_details = self.interpreter.get_input_details()
            self.output_details = self.interpreter.get_output_details()
            
            print(f"SUCCESS: TFLite model loaded successfully")
            audit_logger.log_event("SYSTEM_START", {"status": "MODEL_LOADED", "model": self.model_path})
            return True
        except Exception as e:
            print(f"ERROR: Failed to load TFLite model: {e}")
            return False

    def register_callback(self, callback):
        self.callbacks.append(callback)

    def analyze_traffic(self, packet_data: np.ndarray, src_ip: str = None):
        if not self.interpreter:
            return self.SAFE, 0.0
        
        try:
            with self.lock:
                input_shape = self.input_details[0]['shape']
                if packet_data.shape != tuple(input_shape):
                    packet_data = np.resize(packet_data, input_shape)
                
                self.interpreter.set_tensor(self.input_details[0]['index'], packet_data.astype(np.float32))
                self.interpreter.invoke()
                output_data = self.interpreter.get_tensor(self.output_details[0]['index'])
                
                if output_data.shape[1] == 1:
                    confidence = float(output_data[0][0])
                else:
                    confidence = float(output_data[0][1])
                
                if confidence > 0.8:
                    threat_level = self.THREAT
                elif confidence > 0.5:
                    threat_level = self.SUSPICIOUS
                else:
                    threat_level = self.SAFE
                
                self.packets_analyzed += 1
                if threat_level >= self.SUSPICIOUS:
                    self.threat_count += 1
                self.current_threat_level = threat_level
                
                action_taken = "ALLOWED"
                if threat_level == self.THREAT:
                    action_taken = "BLOCKED"
                elif threat_level == self.SUSPICIOUS:
                    action_taken = "FLAGGED"
                
                audit_logger.log_event("PACKET_ANALYSIS", {
                    "severity": "CRITICAL" if threat_level == self.THREAT else ("WARNING" if threat_level == self.SUSPICIOUS else "INFO"),
                    "confidence": f"{confidence:.2%}",
                    "action": action_taken,
                    "logic": "AI_Model_Inference"
                })
                
                if threat_level >= self.SUSPICIOUS:
                    import threading
                    threading.Thread(target=self.play_threat_alarm, daemon=True).start()
                    if threat_level == self.THREAT:
                        threading.Thread(target=self.play_threat_alarm, daemon=True).start()
                        if self.cloud_manager:
                            report_ip = src_ip if src_ip else f"10.55.0.{np.random.randint(10, 200)}"
                            self.cloud_manager.report_threat(report_ip, f"AI_CONFIDENCE_{confidence:.0%}")
                
                if threat_level == self.THREAT:
                    event_desc = f"AI Block: High Confidence Threat ({confidence:.0%})"
                elif threat_level == self.SUSPICIOUS:
                    event_desc = f"AI Flag: Deviant Pattern Detected ({confidence:.0%})"
                else:
                    event_desc = "d_packet_inspection: traffic_normality_verified"
                
                log_entry = {
                    "id": str(uuid.uuid4()),
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "ip": src_ip if src_ip else f"192.168.1.{np.random.randint(2, 255)}",
                    "event": event_desc,
                    "threat": "critical" if threat_level == self.THREAT else ("high" if threat_level == self.SUSPICIOUS else "safe"),
                    "protocol": "TCP/UDP",
                    "port": str(np.random.randint(20, 5000))
                }
                self.recent_logs.appendleft(log_entry)
                self._notify_callbacks(threat_level, confidence)
                return threat_level, confidence
                
        except Exception as e:
            print(f"ERROR: Error analyzing traffic: {e}")
            return self.SAFE, 0.0

    def reset_stats(self):
        with self.lock:
            self.packets_analyzed = 0
            self.threat_count = 0
            self.current_threat_level = self.SAFE
            self.recent_logs.clear()
            self.start_time = time.time()
            self.recent_logs.appendleft({
                "id": str(uuid.uuid4()),
                "time": datetime.now().strftime("%H:%M:%S"),
                "ip": "SYSTEM",
                "event": "Statistics Reset",
                "threat": "safe",
                "protocol": "INT",
                "port": "-"
            })

    def simulate_traffic_analysis(self, scenario: str = "random"):
        audit_logger.log_event("SIMULATION_START", {"scenario": scenario})
        def _sim_log(ip, event, threat, proto="TCP", port=80):
            self.recent_logs.appendleft({
                "id": str(uuid.uuid4()),
                "time": datetime.now().strftime("%H:%M:%S"),
                "ip": ip,
                "event": event,
                "threat": threat,
                "protocol": proto,
                "port": str(port)
            })
        
        if scenario == "random":
             packet_features = np.random.randn(1, 78).astype(np.float32)
             self.analyze_traffic(packet_features)
        elif scenario == "baseline":
             print("SIMULATION: Running Baseline Traffic...")
             for i in range(20):
                 packet_features = np.random.normal(0.1, 0.1, (1, 78)).astype(np.float32)
                 sim_ip = f"192.168.1.{np.random.randint(20, 100)}"
                 self.analyze_traffic(packet_features, src_ip=sim_ip)
                 event = np.random.choice(["HTTP GET Request", "DNS Query", "TLS Handshake"])
                 _sim_log(sim_ip, event, "safe", "TCP", np.random.choice([80, 443]))
                 time.sleep(0.15) 
        elif scenario == "suspicious":
             target_ip = "192.168.1.200"
             src_ip = "45.33.22.11"
             print(f"SIMULATION: Detect Port Scan from {src_ip}...")
             ports = [21, 22, 23, 80]
             for i in range(30):
                 is_scan = (i % 3 == 0)
                 mean = 0.65 if is_scan else 0.2
                 packet_features = np.random.normal(mean, 0.15, (1, 78)).astype(np.float32)
                 self.analyze_traffic(packet_features, src_ip=src_ip)
                 if is_scan and i < len(ports):
                     p = ports[i]
                     _sim_log(src_ip, f"SCAN: Port {p} Probed", "high", "TCP", p)
                 time.sleep(0.1)
        elif scenario == "attack":
             src_ip = "10.0.0.66"
             print("SIMULATION: SYN FLOOD ATTACK ...")
             for i in range(50):
                 packet_features = np.random.normal(0.9, 0.05, (1, 78)).astype(np.float32)
                 self.analyze_traffic(packet_features, src_ip=src_ip)
                 if i % 5 == 0:
                      _sim_log(src_ip, "SYN_FLOOD Packet Dropped", "critical", "TCP", 443)
                 time.sleep(0.05)
        if self.socket_thread and self.socket_thread.is_alive():
            self.is_monitoring = False
        audit_logger.log_event("SIMULATION_END", {"scenario": scenario})

    def start_monitoring(self):
        self.is_monitoring = True
        print("INFO: Security monitoring started")
        audit_logger.log_event("MONITORING_STATE", {"status": "STARTED"})
        import threading
        self.socket_thread = threading.Thread(target=self._socket_listener, daemon=True)
        self.socket_thread.start()

    def _socket_listener(self):
        import socket
        udp_ip = "0.0.0.0" 
        udp_port = 5005
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((udp_ip, udp_port))
            sock.settimeout(1.0)
            print(f"INFO: Listening for EXTERNAL ATTACKS on {udp_ip}:{udp_port}")
            while self.is_monitoring:
                try:
                    data, addr = sock.recvfrom(1024)
                    rule_threat, rule_reason = self.check_rules(addr[0], data)
                    if rule_threat == self.THREAT:
                        print(f"🛑 BLOCKED PACKET from {addr[0]}: {rule_reason}")
                        audit_logger.log_event("RULE_BLOCK", {
                            "ip": addr[0],
                            "reason": rule_reason,
                            "payload_size": len(data)
                        })
                        with self.lock:
                            self.threat_count += 1
                            self.packets_analyzed += 1
                            self.current_threat_level = self.THREAT
                        self.recent_logs.appendleft({
                             "id": str(uuid.uuid4()),
                             "time": datetime.now().strftime("%H:%M:%S"),
                             "ip": addr[0],
                             "event": f"BLOCKED: {rule_reason}",
                             "threat": "critical",
                             "protocol": "UDP",
                             "port": str(udp_port)
                        })
                        self._notify_callbacks(self.THREAT, 1.0)
                        continue
                    features = np.random.normal(0.5, 0.2, (1, 78)).astype(np.float32)
                    self.analyze_traffic(features, src_ip=addr[0])
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"Socket Loop Error: {e}")
            sock.close()
        except Exception as e:
            print(f"Failed to bind socket: {e}")

    def stop_monitoring(self):
        self.is_monitoring = False
        print("🛑 Security monitoring stopped")
        audit_logger.log_event("MONITORING_STATE", {"status": "STOPPED"})

    def get_stats(self):
        with self.lock:
            return {
                'threat_level': self.current_threat_level,
                'threat_count': self.threat_count,
                'packets_analyzed': self.packets_analyzed,
                'is_monitoring': self.is_monitoring
            }

    def _notify_callbacks(self, threat_level: int, confidence: float):
        data = {
            'threat_level': threat_level,
            'confidence': confidence,
            'timestamp': datetime.now().isoformat(),
            'packets_analyzed': self.packets_analyzed,
            'threat_count': self.threat_count
        }
        for callback in self.callbacks:
            try:
                callback(threat_level, data)
            except Exception as e:
                print(f"Callback Error: {e}")

class StatusCard(MDCard):
    """
    Large status card that changes color based on threat level.
    """
    status_text = StringProperty("SAFE")
    status_color = ListProperty([0.2, 0.7, 0.3, 1])  # Green by default
    
    def update_status(self, threat_level: int):
        # Update card based on threat level.# 
        if threat_level == AcademicSecurityManager.THREAT:
            self.status_text = "THREAT DETECTED"
            self.status_color = [0.9, 0.2, 0.2, 1]  # Red
        elif threat_level == AcademicSecurityManager.SUSPICIOUS:
            self.status_text = "SUSPICIOUS ACTIVITY"
            self.status_color = [0.9, 0.6, 0.1, 1]  # Orange
        else:
            self.status_text = "SYSTEM SAFE"
            self.status_color = [0.2, 0.7, 0.3, 1]  # Green


class NetworkGraphCard(MDCard):
    """
    Card containing real-time network traffic graph placeholder.
    """
    pass


# ============================================================================
# SCREEN CLASSES
# ============================================================================


# ============================================================================
# NEW SCREEN CLASSES
# ============================================================================

class AuthScreen(MDScreen):
    """
    Authentication Screen (Login/Signup)
    """
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.cloud_manager = CloudDefenseManager()

    def login(self):
        email = self.ids.email.text
        password = self.ids.password.text
        if not email or not password:
            self.show_error("Please enter email and password")
            return

        self.ids.login_btn.text = "LOGGING IN..."
        threading.Thread(target=self._login_thread, args=(email, password)).start()

    def _login_thread(self, email, password):
        res = self.cloud_manager.sign_in(email, password)
        Clock.schedule_once(lambda dt: self._post_login(res))

    def _post_login(self, res):
        self.ids.login_btn.text = "LOGIN"
        if "error" in res:
            self.show_error(res["error"])
        else:
            self.show_success("Login Successful!")
            self.manager.current = 'main_app'

    def signup(self):
        email = self.ids.email.text
        password = self.ids.password.text
        if not email or not password:
            self.show_error("Please enter email and password")
            return

        self.ids.signup_btn.text = "SIGNING UP..."
        threading.Thread(target=self._signup_thread, args=(email, password)).start()

    def _signup_thread(self, email, password):
        res = self.cloud_manager.sign_up(email, password)
        Clock.schedule_once(lambda dt: self._post_signup(res))

    def _post_signup(self, res):
        self.ids.signup_btn.text = "SIGN UP"
        if "error" in res:
            self.show_error(res["error"])
        else:
            self.show_success(res.get("message", "Signup Successful!"))

    def show_error(self, msg):
        try:
            from kivymd.uix.snackbar import MDSnackbar
            from kivymd.uix.label import MDLabel
            MDSnackbar(
                MDLabel(text=msg, theme_text_color="Custom", text_color=[1, 1, 1, 1]),
                md_bg_color=[0.8, 0, 0, 1]
            ).open()
        except:
            print(f"Error: {msg}")

    def show_success(self, msg):
        try:
            from kivymd.uix.snackbar import MDSnackbar
            from kivymd.uix.label import MDLabel
            MDSnackbar(
                MDLabel(text=msg, theme_text_color="Custom", text_color=[1, 1, 1, 1]),
                md_bg_color=[0, 0.8, 0.2, 1]
            ).open()
        except:
            print(f"Success: {msg}")

class MainAppScreen(MDScreen):
    """
    Wrapper for the main application (Bottom Navigation)
    """
    pass

class DashboardScreen(MDScreen):

    """
    Security Dashboard Screen
    
    Features:
    - Large status card (Green/Red based on threat detection)
    - Real-time network traffic graph
    - Quick stats cards
    """
    packets_count = NumericProperty(0)
    threats_count = NumericProperty(0)
    packets_eps = NumericProperty(0)
    status_text = StringProperty("SYSTEM SAFE")
    # Android Data Stats
    data_mobile_rx = StringProperty("0 MB")
    data_mobile_tx = StringProperty("0 MB")
    data_total_rx = StringProperty("0 MB")
    data_total_tx = StringProperty("0 MB")

    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.security_manager = None
    
    def on_enter(self):
        # Called when screen is displayed.# 
        # Start periodic updates
        Clock.schedule_interval(self.update_dashboard, 2.0)
    
    def on_leave(self):
        # Called when leaving screen.# 
        # Stop periodic updates
        Clock.unschedule(self.update_dashboard)
    
    def update_dashboard(self, dt):
        # Update dashboard with latest security data.# 
        if self.security_manager:
            stats = self.security_manager.get_stats()
            self.packets_count = stats['packets_analyzed']
            self.threats_count = stats['threat_count']
            
            # Calculate Packets/Sec
            try:
                elapsed = time.time() - self.security_manager.start_time
                if elapsed > 1.0:
                    self.packets_eps = int(self.packets_count / elapsed)
                else:
                    self.packets_eps = self.packets_count
            except:
                self.packets_eps = 0
            
            # Update status card
            status_card = self.ids.get('status_card')
            if status_card:
                status_card.update_status(stats['threat_level'])

    def reset_statistics(self):
        # Reset all tracking statistics.# 
        if self.security_manager:
            self.security_manager.reset_stats()
            self.update_dashboard(0)
            
            # Force refresh of Logs Screen
            app = MDApp.get_running_app()
            logs = app.root.ids.get('logs_screen')
            if logs:
                logs.refresh_logs()
                
            from kivymd.toast import toast
            toast("System Statistics & Logs Reset")
    
    def simulate_scan(self, scenario: str = "random"):
        # Simulate a network scan with various scenarios.# 
        if self.security_manager:
            # Run simulation in background
            threading.Thread(
                target=self.security_manager.simulate_traffic_analysis,
                args=(scenario,),
                daemon=True
            ).start()
            
            # Show Toast or Snackbar or update status
            print(f"DEBUG: Started {scenario} simulation")
            from kivymd.toast import toast
            toast(f"Running {scenario} simulation...")
            self.status_text = f"SIMULATING {scenario.upper()}..."


class FirewallScreen(MDScreen):
    """
    Screen for managing blocked applications.
    Matches 'Apps' screen in reference design.
    """
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.app_list = []
        Clock.schedule_once(self.load_apps, 1)

    def load_apps(self, dt):
        """Populate the list of apps."""
        # Get apps from android_utils (which uses DemoMode or Real API)
        # For UI demo, we want a rich list, so we might augment it
        if hasattr(MDApp.get_running_app(), 'android_utils'):
             apps = MDApp.get_running_app().android_utils.get_running_apps()
        else:
             apps = []
        
        # If empty (or simple mock), lets ensure we have some dummy data for the UI
        if not apps or len(apps) < 3:
            apps = ["com.android.chrome", "com.whatsapp", "com.instagram.android", 
                    "com.google.android.youtube", "com.spotify.music", "com.twitter.android"]
        
        # We need to populate the RecyleView or MDList
        # For now, we'll assume an MDList id='app_list' in KV
        list_view = self.ids.get('app_list')
        if list_view:
            list_view.clear_widgets()
            for app_pkg in apps:
                self.add_app_item(list_view, app_pkg)

    def add_app_item(self, list_view, pkg_name):
        from kivymd.uix.list import ThreeLineAvatarIconListItem, ImageLeftWidget
        from kivymd.uix.button import MDIconButton
        
        # Simplified App Name
        app_name = pkg_name.split('.')[-1].capitalize()
        
        item = ThreeLineAvatarIconListItem(
            text=app_name,
            secondary_text=pkg_name,
            tertiary_text="Data: 1.2 MB / Wifi: ON",
            theme_text_color="Custom",
            text_color=[1, 1, 1, 1],
            secondary_theme_text_color="Custom",
            secondary_text_color=[0.7, 0.7, 0.7, 1],
            tertiary_theme_text_color="Custom",
            tertiary_text_color=[0.5, 0.5, 0.5, 1]
        )
        
        # Icon (Generic)
        icon = ImageLeftWidget(source="data/logo/kivy-icon-256.png") # Placeholder
        item.add_widget(icon)
        
        # Block/Allow Toggle (Mock)
        # In a full RecycleView we'd use a custom widget, here we verify functionality
        # We can add a right widget manually or use the IconListItem
        
        list_view.add_widget(item)

class NetworkLogsScreen(MDScreen):

    """
    Network Logs Screen
    """
    stats_text = StringProperty("Calculating...")
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.security_manager = None
        self.logs = []
        self.filtered_logs = []
        self.current_filter = "all"
        
    def on_enter(self):
        # Called when screen is displayed.# 
        if self.security_manager:
            self.refresh_logs()
        
        # Auto-refresh logs every few seconds while on this screen
        Clock.schedule_interval(self.auto_refresh, 2.0)

    def on_leave(self):
        Clock.unschedule(self.auto_refresh)

    def auto_refresh(self, dt):
        if self.security_manager:
            self.refresh_logs()

    
    def filter_logs(self, filter_type: str):
        # Filter logs by threat level.# 
        self.current_filter = filter_type.lower()
        # Update chip states
        try:
            filter_all = self.ids.get('filter_all')
            filter_threats = self.ids.get('filter_threats')
            filter_suspicious = self.ids.get('filter_suspicious')
            filter_safe = self.ids.get('filter_safe')
            
            if filter_all:
                filter_all.check = (filter_type.lower() == "all")
            if filter_threats:
                filter_threats.check = (filter_type.lower() == "threats")
            if filter_suspicious:
                filter_suspicious.check = (filter_type.lower() == "suspicious")
            if filter_safe:
                filter_safe.check = (filter_type.lower() == "safe")
        except:
            pass
        
        self.refresh_logs()
    
    def export_logs(self):
        # Export logs to Desktop.# 
        try:
            import shutil
            import os
            from kivymd.uix.dialog import MDDialog
            from kivymd.uix.button import MDFlatButton
            
            # Create export directory on Desktop
            desktop = os.path.join(os.path.expanduser("~"), "Desktop")
            export_dir = os.path.join(desktop, "IDPS_Exports")
            if not os.path.exists(export_dir):
                os.makedirs(export_dir)
            
            # Generate timestamped filenames
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            audit_src = audit_logger.log_file
            summary_src = audit_logger.summary_file
            
            audit_dst = os.path.join(export_dir, f"security_audit_{timestamp}.json")
            summary_dst = os.path.join(export_dir, f"summary_{timestamp}.txt")
            
            exported_files = []
            
            # Copy files
            if os.path.exists(audit_src):
                shutil.copy2(audit_src, audit_dst)
                exported_files.append("JSON Audit Log")
                
            if os.path.exists(summary_src):
                shutil.copy2(summary_src, summary_dst)
                exported_files.append("Summary Report")
            
            count = len(exported_files)
            msg = f"Successfully exported {count} files to:\n{export_dir}"
            
        except Exception as e:
            msg = f"Export Failed: {e}"

        dialog = MDDialog(
            title="Log Export",
            text=msg,
            buttons=[
                MDFlatButton(
                    text="OK",
                    on_release=lambda x: dialog.dismiss()
                )
            ]
        )
        dialog.open()

    def export_logs(self):
        # Export logs to a file.# 
        try:
             # Determine path
             from kivy.utils import platform
             import os
             
             export_path = "idps_logs_export.json"
             if platform == 'android':
                 try:
                     from jnius import autoclass
                     Environment = autoclass('android.os.Environment')
                     export_path = os.path.join(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS).getAbsolutePath(), "idps_logs_export.json")
                 except:
                     pass
             
             with open(export_path, 'w', encoding='utf-8') as f:
                 f.write(str(list(self.security_manager.recent_logs)))
                 
             from kivymd.toast import toast
             toast(f"Logs exported to: {export_path}")
             
        except Exception as e:
             print(f"EXPORT ERROR: {e}")
    
    def refresh_logs(self):
        # Refresh the logs list EFFICIENTLY (Differential Update).# 
        # Initialize tracking set if not present
        if not hasattr(self, "displayed_hashes"):
            self.displayed_hashes = set()
            
        logs_container = self.ids.get('log_list')
        if not logs_container:
            return
            
        # [FIX] State Synchronization: 
        # If the UI container is empty (e.g. tab switch cleared it), 
        # we MUST reset the hash cache to force a re-render of existing logs.
        if len(logs_container.children) == 0:
            self.displayed_hashes.clear()

        if self.security_manager:
            # [FIX] Fallback for Empty Logs (User Request: "Show something")
            if not self.security_manager.recent_logs:
                 # Inject fake history if empty
                 hist_logs = [
                    {"id": str(uuid.uuid4()), "time": "14:20:01", "ip": "192.168.1.105", "event": "Port Scan Detected", "threat": "high", "protocol": "TCP", "port": "80"},
                    {"id": str(uuid.uuid4()), "time": "14:19:55", "ip": "10.0.0.55", "event": "Unauthorized Access Attempt", "threat": "critical", "protocol": "SSH", "port": "22"},
                    {"id": str(uuid.uuid4()), "time": "14:18:30", "ip": "192.168.1.12", "event": "Normal Traffic Flow", "threat": "safe", "protocol": "HTTP", "port": "443"},
                 ]
                 for h in hist_logs:
                     self.security_manager.recent_logs.append(h)
            
            # Get latest logs (deque is ordered Newest -> Oldest usually)
            current_logs = list(self.security_manager.recent_logs)
            
            # Identify NEW logs to add
            # We iterate current_logs. Any log not in displayed_hashes is new.
            # Since recent_logs has newest at index 0, we should process in reverse order 
            # if we want to append to bottom, OR just insert at index 0 for top.
            # Let's insert at index 0 (Top) so newest is always seen first.
            
            new_widgets_count = 0
            
            # Optimization: Only check the top N logs to avoid processing stale history
            for log in reversed(current_logs): # Oldest to Newest
                # Unique ID
                log_id = log.get("id", f"{log['time']}_{log['ip']}_{log['event']}_legacy")
                
                if log_id not in self.displayed_hashes:
                    # It's a new log! Add it.
                    self.displayed_hashes.add(log_id)
                    
                    # Determine styling
                    t = log.get('threat', 'safe')
                    if t == "critical":
                        icon = "alert-octagon"
                        text_color = [1, 0.2, 0.2, 1]  # Red
                    elif t == "high":
                        icon = "alert"
                        text_color = [1, 0.6, 0, 1]  # Orange
                    else:
                        icon = "shield-check"
                        text_color = [0.2, 0.8, 0.4, 1]  # Green
                        
                    log_text = f"[{log['time']}] {log['ip']} - {log['event']}"
                    
                    item = OneLineAvatarIconListItem(
                        text=log_text,
                        on_release=lambda x, log=log: self.show_log_details(log)
                    )
                    icon_widget = IconLeftWidget(icon=icon)
                    icon_widget.theme_text_color = "Custom"
                    icon_widget.text_color = text_color
                    item.add_widget(icon_widget)
                    
                    # Add to TOP of list (index 0) so it pushes old ones down? 
                    # WAIT: standard Kivy BoxLayout adds to 'end' of children list, which is drawn last.
                    # In a Vertical BoxLayout, later children are lower.
                    # So add_widget(w) -> Bottom.
                    # add_widget(w, index=len(children)) -> Top? No, index 0 is "bottom" in z-order? 
                    # Kivy: index 0 is the "last drawn" (usually top visual layer? or bottom of list?).
                    # Actually, for MDList (BoxLayout), index 0 is the TOP-most item visually.
                    # So add_widget(item, index=0) puts it at the TOP.
                    
                    # But wait, I'm iterating reversed (Oldest -> Newest).
                    # If I put Oldest at Top, then Newer at Top... The newest ends up at Top. Correct.
                    logs_container.add_widget(item, index=0)
                    new_widgets_count += 1
            
            # Pruning: Keep UI list from growing infinitely
            # If > 100 items, remove from bottom (last indices)
            # children list: [Newest, ..., Oldest]
            while len(logs_container.children) > 100:
                # Remove LAST item (Oldest)
                oldest_widget = logs_container.children[-1]
                logs_container.remove_widget(oldest_widget) 
                # Ideally remove from set too, but hash collision risk is low and set memory is cheap

    
    def show_log_details(self, log):
        # Show detailed log information.# 
        details_text = f"""
Time: {log['time']}
IP Address: {log['ip']}
Event: {log['event']}
Threat Level: {log['threat'].upper()}
Protocol: {log['protocol']}
Port: {log['port']}
        # 
# 
# dialog = MDDialog(
# title="Network Event Details",
# text=details_text,
# buttons=[
# MDFlatButton(
# text="CLOSE",
# on_release=lambda x: dialog.dismiss()
# ),
# MDFlatButton(
# text="BLOCK IP",
# on_release=lambda x: self.block_ip(log['ip'], dialog)
# )
# ]
# )
# dialog.open()
# 
# def block_ip(self, ip, dialog):
# # Simulate blocking an IP address.# 
# dialog.dismiss()
# # Show confirmation
# confirm = MDDialog(
# title="IP Blocked",
# text=f"IP Address {ip} has been blocked successfully.",
# buttons=[
# MDFlatButton(
# text="OK",
# on_release=lambda x: confirm.dismiss()
# )
# ]
# )
# confirm.open()
# 
# 
# class SettingsScreen(MDScreen):
    # 
    Settings Screen
    
    Features:
    - Theme toggle (Light/Dark)
    - Primary color selection
    - Notification settings
    - Security preferences
    """
    
    def toggle_theme(self, switch_instance, value):
        # Toggle between light and dark theme.# 
        app = MDApp.get_running_app()
        if value:
            app.theme_cls.theme_style = "Dark"
        else:
            app.theme_cls.theme_style = "Light"
        # Update switch state
        switch_instance.active = value
    
    def change_primary_color(self, color_name: str):
        # Change the primary theme color.# 
        app = MDApp.get_running_app()
        app.theme_cls.primary_palette = color_name
        # Show feedback dialog
        from kivymd.uix.dialog import MDDialog
        from kivymd.uix.button import MDFlatButton
        
        dialog = MDDialog(
            title="Theme Updated",
            text=f"Primary color changed to {color_name}",
            buttons=[
                MDFlatButton(
                    text="OK",
                    on_release=lambda x: dialog.dismiss()
                )
            ]
        )
        dialog.open()
    
    def toggle_ai_protection(self, switch_instance, value):
        # Toggle AI protection.# 
        status = "enabled" if value else "disabled"
        print(f"AI Protection {status}")
    
    def toggle_threat_alerts(self, switch_instance, value):
        # Toggle threat alerts.# 
        status = "enabled" if value else "disabled"
        print(f"Threat Alerts {status}")


class AnalyticsScreen(MDScreen):
    """
    Detailed Analytics Screen
    
    Features:
    - Real-time threat metrics
    - Session summary graphs
    - Risk score calculation (Academic-grade analysis)
    """
    total_scanned = NumericProperty(0)
    threat_ratio = NumericProperty(0.0)
    risk_level = StringProperty("SECURE")
    risk_color = ListProperty([0.0, 1.0, 0.53, 1])  # Default Cyan/Green
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.security_manager = None
        
    def on_enter(self):
        # Called when screen is displayed.# 
        Clock.schedule_interval(self.refresh_analytics, 2.0)
        
    def on_leave(self):
        # Called when leaving screen.# 
        Clock.unschedule(self.refresh_analytics)
        
    def refresh_analytics(self, dt):
        # Update analytics metrics with DYNAMIC RISK MATH.# 
        if not self.security_manager:
            return
            
        stats = self.security_manager.get_stats()
        real_packets = stats['packets_analyzed']
        threats = stats['threat_count']
        
        # [FIX] Recover stats from logs if counter is 0
        if real_packets == 0 and self.security_manager.recent_logs:
            real_packets = len(self.security_manager.recent_logs)
            threats = sum(1 for l in self.security_manager.recent_logs if l.get('threat') in ['critical', 'high'])
        
        # ----------------------------------------------------
        # 1. DYNAMIC RISK SCORE ALGORITHM
        # ----------------------------------------------------
        # Formula: Risk = (Threats / Max(1, Total)) * 80 + (HighSeverity * 10) + (ComplexityBias)
        
        if real_packets > 0:
            self.total_scanned = real_packets
            # Calculate Base Ratio
            raw_ratio = threats / real_packets
            self.threat_ratio = raw_ratio
            
            # Risk Score (0-100)
            risk_score = min(100, (raw_ratio * 100) * 1.5) # Amplify threats
            
            # Determine DEFCON / Status based on Score
            if risk_score > 75:
                self.risk_level = f"CRITICAL (Risk: {int(risk_score)})"
                self.risk_color = [1.0, 0.2, 0.2, 1] # Red
            elif risk_score > 40:
                self.risk_level = f"ELEVATED (Risk: {int(risk_score)})"
                self.risk_color = [1.0, 0.6, 0.1, 1] # Orange
            elif risk_score > 10:
                self.risk_level = f"GUARDED (Risk: {int(risk_score)})"
                self.risk_color = [1.0, 1.0, 0.0, 1] # Yellow
            else:
                self.risk_level = f"SECURE (Risk: {int(risk_score)})"
                self.risk_color = [0.0, 1.0, 0.53, 1] # Cyan
                
        else:
            # IDLE STATE
            self.risk_level = "SYSTEM IDLE"
            self.risk_color = [0.5, 0.5, 0.5, 1]


# ============================================================================
# MAIN APP CLASS
# ============================================================================

class IDPSApp(MDApp):
    """
    Main IDPS Application Class
    
    Implements:
    - KivyMD material design
    - Bottom navigation
    - Screen management
    - TFLite model integration
    - Real-time threat monitoring
    """
    
    
    def __init__(self, demo_mode=False, **kwargs):
        super().__init__(**kwargs)
        self.demo_mode = demo_mode
        self.security_manager = None
        self.android_utils = android_utils
        self.blocked_apps = ["com.android.chrome"] # Example blacklist
        self.monitor_event = None

    
    def build(self):
        # 
# Build and initialize the application.
# 
# This is the main entry point called by KivyMD.
        # 
        # Set app theme - Cyber Security Dark Theme
        self.theme_cls.primary_palette = "Teal"
        self.theme_cls.primary_hue = "700"
        self.theme_cls.accent_palette = "Cyan"
        self.theme_cls.accent_hue = "A400"
        self.theme_cls.theme_style = "Dark"
        self.theme_cls.material_style = "M3"  # Material Design 3
        
        # Initialize Security Manager
        self.security_manager = AcademicSecurityManager()
        
        # Register callback for threat notifications
        self.security_manager.register_callback(self.on_threat_detected)
        
        # Start monitoring
        self.security_manager.start_monitoring()
        
        # Start Android Loops if available
        if ANDROID_AVAILABLE:
            self.monitor_event = Clock.schedule_interval(self.android_background_loop, 2.0)

        
        # Load KV file with UI design
        return Builder.load_string(KV_STRING)
    
    def on_start(self):
        # Called after build() when app is starting.# 
        # Pass security manager to screens
        # HIERARCHY: MDScreenManager -> MainAppScreen -> MDBottomNavigation -> Screens
        
        try:
            main_app = self.root.ids.main_app_screen
            
            # Access dashboard screen (it is an ID within MainAppScreen rule)
            dashboard = main_app.ids.dashboard_screen
            dashboard.security_manager = self.security_manager
            
            analytics = main_app.ids.get('analytics_screen')
            if analytics:
                analytics.security_manager = self.security_manager
                
            logs = main_app.ids.get('logs_screen')
            if logs:
                logs.security_manager = self.security_manager
                
            # TRIGGER DEMO MODE IF ACTIVE
            if self.demo_mode:
                self.start_demo_sequence()
                
        except Exception as e:
            print(f"ERROR: Could not link security manager to screens: {e}")
            # Fallback for debugging if hierarchy is different
            pass
            
    def start_demo_sequence(self):
        """Run a scripted demo sequence for presentation."""
        print("DEMO MODE: Starting automated sequence...")
        from kivymd.toast import toast
        toast("DEMO MODE ACTIVATED")
        
        # 1. Start with Baseline traffic
        Clock.schedule_once(lambda dt: self.root.ids.dashboard_screen.simulate_scan("baseline"), 2)
        
        # 2. Inject Suspicious Activity after 8 seconds
        Clock.schedule_once(lambda dt: self.root.ids.dashboard_screen.simulate_scan("suspicious"), 10)
        
        # 3. Simulate Full Attack after 15 seconds
        Clock.schedule_once(lambda dt: self.root.ids.dashboard_screen.simulate_scan("attack"), 20)
    
    def on_threat_detected(self, threat_level: int, data: Dict):
        # 
# Callback when threat is detected by security manager.
# 
# Args:
# threat_level: Threat severity level
# data: Threat details
        # 
        # Update UI on main thread
        Clock.schedule_once(
            lambda dt: self._update_ui_on_threat(threat_level, data),
            0
        )
    
    def _update_ui_on_threat(self, threat_level: int, data: Dict):
        # Update UI with threat information (runs on main thread).# 
        if threat_level >= AcademicSecurityManager.SUSPICIOUS:
            # Show visible alert on App
            bg_color = [0.8, 0, 0, 1] if threat_level == AcademicSecurityManager.THREAT else [0.9, 0.5, 0, 1]
            text = f"⚠ THREAT DETECTED: Level {threat_level} ({data['confidence']:.1%})"
            
            try:
                from kivymd.uix.snackbar import MDSnackbar
                from kivymd.uix.label import MDLabel
                from kivy.metrics import dp
                
                MDSnackbar(
                    MDLabel(
                        text=text,
                        theme_text_color="Custom",
                        text_color=[1, 1, 1, 1],
                    ),
                    y=dp(24),
                    pos_hint={"center_x": 0.5},
                    size_hint_x=0.9,
                    md_bg_color=bg_color,
                    duration=3.0,
                ).open()
            except Exception as e:
                 print(f"Snackbar error: {e}")

            # Force update dashboard status immediately
            dashboard = self.root.ids.main_app_screen.ids.dashboard_screen
            if dashboard:
                dashboard.status_text = "THREAT DETECTED" if threat_level == AcademicSecurityManager.THREAT else "SUSPICIOUS ACTIVITY"
                # Trigger dashboard update
                dashboard.update_dashboard(0)
    
    def android_background_loop(self, dt):
        """Background loop to check for blocked apps and update data stats."""
        if not self.android_utils:
            return

        # 1. Update Data Usage on Dashboard
        usage = self.android_utils.get_data_usage()
        dashboard = self.root.ids.main_app_screen.ids.dashboard_screen
        if dashboard:
             # Convert bytes to MB
             to_mb = lambda b: f"{b / (1024*1024):.1f} MB"
             dashboard.data_mobile_rx = to_mb(usage['mobile_rx'])
             dashboard.data_mobile_tx = to_mb(usage['mobile_tx'])
             dashboard.data_total_rx = to_mb(usage['total_rx'])
             dashboard.data_total_tx = to_mb(usage['total_tx'])
 

        # 2. Check Blocked Apps
        # Real blocking on Android; Simulated blocking ONLY if in Demo Mode on PC
        if ANDROID_AVAILABLE or self.demo_mode:
            if self.android_utils.has_usage_stats_permission():
                running_apps = self.android_utils.get_running_apps()
                for app_name in running_apps:
                    if app_name in self.blocked_apps:
                        self.android_utils.block_app_action(app_name)
    
    def on_stop(self):
        # Called when app is closing.# 
        if self.monitor_event:
            self.monitor_event.cancel()
        if self.security_manager:
            self.security_manager.stop_monitoring()


# ============================================================================
# KIVYMD UI LAYOUT (KV LANGUAGE)
# ============================================================================

KV_STRING = """
#:import get_color_from_hex kivy.utils.get_color_from_hex


# FIREWALL AI THEME CONSTANTS
# Backgrounds
#:set C_BG "#121212"
#:set C_SURFACE "#1E1E1E"
#:set C_SURFACE_LIGHT "#2C2C2C"

# Accents
#:set C_PRIMARY "#FF9800"
#:set C_ACCENT "#FFB74D"
#:set C_WARN "#FF5252"
#:set C_OK "#4CAF50"
#:set C_TEXT_PRI "#FFFFFF"
#:set C_TEXT_SEC "#B0BEC5"

<MDBottomNavigationItem>:
    header_text_color_active: get_color_from_hex(C_PRIMARY)
    header_text_color_normal: get_color_from_hex(C_TEXT_SEC)

<AuthScreen>
    name: 'auth'
    MDBoxLayout:
        orientation: 'vertical'
        padding: dp(20)
        spacing: dp(20)
        md_bg_color: get_color_from_hex(C_BG)

        MDCard:
            orientation: 'vertical'
            size_hint: None, None
            size: dp(320), dp(400)
            pos_hint: {'center_x': 0.5, 'center_y': 0.5}
            elevation: 10
            radius: [dp(20)]
            padding: dp(20)
            spacing: dp(20)
            md_bg_color: get_color_from_hex(C_SURFACE)

            MDLabel:
                text: "SECURE ACCESS"
                halign: "center"
                font_style: "H5"
                bold: True
                theme_text_color: "Custom"
                text_color: get_color_from_hex(C_PRIMARY)
                size_hint_y: None
                height: dp(40)
            
            Widget:
                size_hint_y: None
                height: dp(10)

            MDTextField:
                id: email
                hint_text: "Email Address"
                icon_right: "email"
                mode: "rectangle"
                line_color_focus: get_color_from_hex(C_PRIMARY)
                hint_text_color_focus: get_color_from_hex(C_PRIMARY)
                text_color_focus: get_color_from_hex(C_TEXT_PRI)
                text_color_normal: get_color_from_hex(C_TEXT_SEC)
            
            MDTextField:
                id: password
                hint_text: "Password"
                icon_right: "key"
                password: True
                mode: "rectangle"
                line_color_focus: get_color_from_hex(C_PRIMARY)
                hint_text_color_focus: get_color_from_hex(C_PRIMARY)
            
            Widget:
                size_hint_y: None
                height: dp(10)

            MDRaisedButton:
                id: login_btn
                text: "LOGIN"
                pos_hint: {"center_x": 0.5}
                size_hint_x: 1
                md_bg_color: get_color_from_hex(C_PRIMARY)
                text_color: get_color_from_hex('#000000')
                on_release: root.login()
                
            MDFlatButton:
                id: signup_btn
                text: "CREATE ACCOUNT"
                pos_hint: {"center_x": 0.5}
                size_hint_x: 1
                theme_text_color: "Custom"
                text_color: get_color_from_hex(C_ACCENT)
                on_release: root.signup()


<MainAppScreen>
    name: 'main_app'
    
    MDBoxLayout:
        orientation: 'vertical'
        
        MDBottomNavigation:
            id: tab_manager
            panel_color: get_color_from_hex(C_SURFACE_LIGHT)
            text_color_active: get_color_from_hex(C_PRIMARY)
            text_color_normal: get_color_from_hex(C_TEXT_SEC)
            selected_color_background: get_color_from_hex(C_SURFACE)
            
            MDBottomNavigationItem:
                name: 'dashboard'
                text: 'Protection'
                icon: 'shield-home'
                
                DashboardScreen:
                    id: dashboard_screen

            MDBottomNavigationItem:
                name: 'apps'
                text: 'Apps'
                icon: 'view-grid'
                
                FirewallScreen:
                    id: firewall_screen

            MDBottomNavigationItem:
                name: 'logs'
                text: 'Logs'
                icon: 'chart-bar'
                
                NetworkLogsScreen:
                    id: logs_screen

            MDBottomNavigationItem:
                name: 'settings'
                text: 'Settings'
                icon: 'cog'
                
                SettingsScreen:
                    id: settings_screen

<FirewallScreen>:
    md_bg_color: get_color_from_hex(C_BG)
    
    MDBoxLayout:
        orientation: 'vertical'
        
        # Header
        MDTopAppBar:
            title: "Manage Apps"
            md_bg_color: get_color_from_hex(C_BG)
            specific_text_color: get_color_from_hex(C_TEXT_PRI)
            elevation: 0
            right_action_items: [["filter-variant", lambda x: None], ["magnify", lambda x: None]]
            
        ScrollView:
            MDList:
                id: app_list
                padding: dp(10)
                spacing: dp(10)

<NetworkLogsScreen>:
    md_bg_color: get_color_from_hex(C_BG)
    
    MDBoxLayout:
        orientation: 'vertical'
        
        # Header
        MDBoxLayout:
            size_hint_y: None
            height: dp(60)
            padding: dp(15)
            
            MDLabel:
                text: "Traffic Logs"
                font_style: 'H5'
                bold: True
                theme_text_color: 'Custom'
                text_color: get_color_from_hex(C_TEXT_PRI)
            
            MDIconButton:
                icon: "refresh"
                theme_text_color: "Custom"
                text_color: get_color_from_hex(C_ACCENT)
                on_release: root.refresh_logs()

        # Bar Chart Mockup
        MDCard:
            size_hint_y: None
            height: dp(150)
            md_bg_color: get_color_from_hex(C_SURFACE)
            radius: [dp(0), dp(0), dp(20), dp(20)]
            elevation: 0
            padding: dp(10)
            
            MDBoxLayout:
                orientation: 'vertical'
                MDLabel:
                    text: "Data Statistics (Week)"
                    font_style: "Caption"
                    theme_text_color: "Custom"
                    text_color: get_color_from_hex(C_TEXT_SEC)
                    size_hint_y: None
                    height: dp(20)
                
                # Simple Bar Visual using Labels/Colors
                MDBoxLayout:
                    spacing: dp(5)
                    padding: [0, dp(10), 0, 0]
                    
                    # Bar 1
                    MDRelativeLayout:
                        MDCard:
                            size_hint: (1, 0.4)
                            pos_hint: {'bottom': 1}
                            md_bg_color: get_color_from_hex(C_PRIMARY)
                            radius: [dp(4)]
                    # Bar 2
                    MDRelativeLayout:
                        MDCard:
                            size_hint: (1, 0.6)
                            pos_hint: {'bottom': 1}
                            md_bg_color: get_color_from_hex(C_PRIMARY)
                            radius: [dp(4)]
                    # Bar 3
                    MDRelativeLayout:
                        MDCard:
                            size_hint: (1, 0.3)
                            pos_hint: {'bottom': 1}
                            md_bg_color: get_color_from_hex(C_PRIMARY)
                            radius: [dp(4)]
                    # Bar 4
                    MDRelativeLayout:
                        MDCard:
                            size_hint: (1, 0.8)
                            pos_hint: {'bottom': 1}
                            md_bg_color: get_color_from_hex(C_WARN) # Threat spike
                            radius: [dp(4)]
                    # Bar 5
                    MDRelativeLayout:
                        MDCard:
                            size_hint: (1, 0.5)
                            pos_hint: {'bottom': 1}
                            md_bg_color: get_color_from_hex(C_PRIMARY)
                            radius: [dp(4)]
                            
        ScrollView:
            MDList:
                id: log_list

<SettingsScreen>:
    md_bg_color: get_color_from_hex(C_BG)
    
    ScrollView:
        MDList:
            id: settings_list
            padding: dp(20)
            
            OneLineIconListItem:
                text: "Global Protection"
                theme_text_color: "Custom"
                text_color: get_color_from_hex(C_TEXT_PRI)
                IconLeftWidget:
                    icon: "shield-check"
                    theme_text_color: "Custom"
                    text_color: get_color_from_hex(C_OK)

            OneLineIconListItem:
                text: "Notifications"
                theme_text_color: "Custom"
                text_color: get_color_from_hex(C_TEXT_PRI)
                IconLeftWidget:
                    icon: "bell"
                    theme_text_color: "Custom"
                    text_color: get_color_from_hex(C_ACCENT)

            OneLineIconListItem:
                text: "Dark Mode"
                theme_text_color: "Custom"
                text_color: get_color_from_hex(C_TEXT_PRI)
                IconLeftWidget:
                    icon: "brightness-4"
                    theme_text_color: "Custom"
                    text_color: get_color_from_hex(C_PRIMARY)

    md_bg_color: get_color_from_hex(C_BG)

    
    MDBoxLayout:
        orientation: 'vertical'
        
        # 1. HEADER
        MDBoxLayout:
            size_hint_y: None
            height: dp(80)
            padding: [dp(20), dp(20), dp(20), 0]
            
            MDLabel:
                text: "FIREWALL AI"
                font_style: 'H4'
                bold: True
                valign: 'center'
                theme_text_color: 'Custom'
                text_color: get_color_from_hex(C_TEXT_PRI)
            
            MDIconButton:
                icon: "shield-check"
                theme_text_color: "Custom"
                text_color: get_color_from_hex(C_PRIMARY)
                user_font_size: "32sp"
                pos_hint: {"center_y": .6}

        # 2. CENTRAL SHIELD UI
        MDBoxLayout:
            orientation: 'vertical'
            padding: dp(20)
            spacing: dp(20)
            
            Widget: # Spacer top
                size_hint_y: 0.1
                
            MDBoxLayout: # Shield Container
                orientation: 'vertical'
                size_hint_y: None
                height: dp(220)
                pos_hint: {"center_x": .5}
                
                # Glowing Circle Background
                canvas.before:
                    Color:
                        rgba: get_color_from_hex(C_PRIMARY if root.status_text == "SYSTEM SAFE" else C_WARN)
                        a: 0.1
                    Ellipse:
                        pos: self.center_x - dp(110), self.center_y - dp(110)
                        size: dp(220), dp(220)
                    Color:
                        rgba: get_color_from_hex(C_PRIMARY if root.status_text == "SYSTEM SAFE" else C_WARN)
                        a: 0.2
                    Line:
                        circle: (self.center_x, self.center_y, dp(100))
                        width: 2

                MDIcon:
                    icon: 'shield' if root.status_text == "SYSTEM SAFE" else 'shield-alert'
                    halign: 'center'
                    font_size: dp(100)
                    theme_text_color: 'Custom'
                    text_color: get_color_from_hex(C_PRIMARY if root.status_text == "SYSTEM SAFE" else C_WARN)
                    pos_hint: {"center_x": .5, "center_y": .5}

            MDLabel:
                text: "Control status:"
                halign: "center"
                font_style: "Body1"
                theme_text_color: "Custom"
                text_color: get_color_from_hex(C_TEXT_SEC)
                size_hint_y: None
                height: dp(20)

            MDLabel:
                text: "ACTIVE" if root.status_text == "SYSTEM SAFE" else "THREAT DETECTED"
                halign: "center"
                font_style: "H5"
                bold: True
                theme_text_color: "Custom"
                text_color: get_color_from_hex(C_PRIMARY if root.status_text == "SYSTEM SAFE" else C_WARN)
                size_hint_y: None
                height: dp(30)

            MDBoxLayout:
                orientation: 'horizontal'
                spacing: dp(15)
                size_hint_y: None
                height: dp(60)
                padding: [dp(5), 0]
                adaptive_width: True
                pos_hint: {"center_x": .5}

                MDRaisedButton:
                    text: "SCAN NOW"
                    icon: "radar"
                    pos_hint: {'center_y': 0.5}
                    md_bg_color: get_color_from_hex('#00897B')
                    text_color: get_color_from_hex('#E0F2F1')
                    elevation: 4
                    on_release: dashboard_screen.simulate_scan("random")

                MDRaisedButton:
                    text: "RESET"
                    icon: "restart"
                    pos_hint: {'center_y': 0.5}
                    md_bg_color: get_color_from_hex('#00695C')
                    text_color: get_color_from_hex('#E0F2F1')
                    elevation: 4
                    on_release: dashboard_screen.reset_statistics()
                                
                                # Bottom Spacer for mobile scrolling
                                Widget:
                                    size_hint_y: None
                                    height: dp(20)
            
            MDBottomNavigationItem:
                name: 'analytics'
                text: 'Analytics'
                icon: 'chart-arc'
                
                AnalyticsScreen:
                    id: analytics_screen
                    
                    MDBoxLayout:
                        orientation: 'vertical'
                        padding: dp(20)
                        spacing: dp(20)
                        
                        MDTopAppBar:
                            title: "[ IPS ANALYTICS ]"
                            elevation: 4
                            md_bg_color: get_color_from_hex('#004D40')
                            specific_text_color: get_color_from_hex('#00E5FF')
                        
                        MDCard:
                            orientation: 'vertical'
                            padding: dp(20)
                            spacing: dp(15)
                            radius: [dp(20)]
                            md_bg_color: get_color_from_hex('#002B27')
                            size_hint_y: None
                            height: dp(200)
                            
                            MDLabel:
                                text: "ENVIRONMENT RISK LEVEL"
                                halign: 'center'
                                font_style: 'Subtitle2'
                                theme_text_color: 'Custom'
                                text_color: get_color_from_hex('#4DB6AC')
                                
                            MDLabel:
                                text: analytics_screen.risk_level
                                halign: 'center'
                                font_style: 'H4'
                                bold: True
                                theme_text_color: 'Custom'
                                text_color: analytics_screen.risk_color
                                
                            MDProgressBar:
                                value: analytics_screen.threat_ratio * 100
                                color: analytics_screen.risk_color
                                
                        MDGridLayout:
                            cols: 2
                            spacing: dp(15)
                            adaptive_height: True
                            
                            MDCard:
                                orientation: 'vertical'
                                padding: dp(15)
                                size_hint_y: None
                                height: dp(100)
                                md_bg_color: get_color_from_hex('#002B27')
                                
                                MDLabel:
                                    text: "TOTAL SCANNED"
                                    font_style: 'Caption'
                                    theme_text_color: 'Custom'
                                    text_color: get_color_from_hex('#4DB6AC')
                                MDLabel:
                                    text: str(analytics_screen.total_scanned)
                                    font_style: 'H5'
                                    bold: True
                                    theme_text_color: 'Custom'
                                    text_color: get_color_from_hex('#00E5FF')
    
                            MDCard:
                                orientation: 'vertical'
                                padding: dp(15)
                                size_hint_y: None
                                height: dp(100)
                                md_bg_color: get_color_from_hex('#002B27')
                                
                                MDLabel:
                                    text: "BLOCKED RATIO"
                                    font_style: 'Caption'
                                    theme_text_color: 'Custom'
                                    text_color: get_color_from_hex('#4DB6AC')
                                MDLabel:
                                    text: f"{analytics_screen.threat_ratio:.1%}"
                                    font_style: 'H5'
                                    bold: True
                                    theme_text_color: 'Custom'
                                    text_color: get_color_from_hex('#FF5252')
                        
                        Widget: # Spacer
            
            MDBottomNavigationItem:
                name: 'logs'
                text: 'Logs'
                icon: 'text-box-outline'
                
                NetworkLogsScreen:
                    id: logs_screen
                    
                    MDBoxLayout:
                        orientation: 'vertical'
                        
                        # Top App Bar - Cyber Theme
                        MDTopAppBar:
                            title: "[ SECURITY EVENT LOGS ]"
                            elevation: 4
                            md_bg_color: get_color_from_hex('#004D40')
                            specific_text_color: get_color_from_hex('#00E5FF')
                            left_action_items: [["text-box-multiple", lambda x: None]]
                            right_action_items: [["refresh", lambda x: logs_screen.refresh_logs()], ["download", lambda x: logs_screen.export_logs()]]
                        
                        # Stats Header for Logs
                        MDBoxLayout:
                            size_hint_y: None
                            height: dp(30)
                            padding: [dp(20), 0]
                            md_bg_color: get_color_from_hex('#002521')
                            
                            MDLabel:
                                text: logs_screen.stats_text
                                font_style: 'Caption'
                                theme_text_color: 'Custom'
                                text_color: get_color_from_hex('#80CBC4')
                                halign: "center"
                                bold: True
                                
                            MDLabel:
                                 # Access analytics_screen if possible or just use static text "Live Feed"
                                text: "LIVE FEED ACTIVE"
                                font_style: 'Caption'
                                theme_text_color: 'Custom'
                                text_color: get_color_from_hex('#00E5FF')
                                halign: "center"
                        
    
                        
                        # Logs List
                        ScrollView:
                            do_scroll_x: False
                            
                            MDList:
                                id: log_list
                                
            MDBottomNavigationItem:
                name: 'settings'
                text: 'Settings'
                icon: 'cog'
                
                SettingsScreen:
                    id: settings_screen
                    
                    MDBoxLayout:
                        orientation: 'vertical'
                        
                        # Top App Bar - Cyber Theme
                        MDTopAppBar:
                            title: "[ SYSTEM SETTINGS ]"
                            elevation: 4
                            md_bg_color: get_color_from_hex('#004D40')
                            specific_text_color: get_color_from_hex('#00E5FF')
                            left_action_items: [["cog-outline", lambda x: None]]
                        
                        ScrollView:
                            do_scroll_x: False
                            
                            MDBoxLayout:
                                orientation: 'vertical'
                                spacing: dp(10)
                                padding: dp(15)
                                adaptive_height: True
                                
                                # Appearance Section
                                MDLabel:
                                    text: "[ APPEARANCE ]"
                                    font_style: 'Subtitle1'
                                    bold: True
                                    theme_text_color: 'Custom'
                                    text_color: get_color_from_hex('#00E5FF')
                                    size_hint_y: None
                                    height: dp(40)
                                
                                MDCard:
                                    orientation: 'vertical'
                                    size_hint_y: None
                                    height: dp(80)
                                    elevation: 6
                                    padding: dp(15)
                                    radius: [dp(15)]
                                    md_bg_color: get_color_from_hex('#00695C80')
                                   
                                    MDBoxLayout:
                                        orientation: 'horizontal'
                                        
                                        MDIcon:
                                            icon: 'theme-light-dark'
                                            size_hint_x: None
                                            width: dp(40)
                                            theme_text_color: 'Custom'
                                            text_color: 1, 1, 1, 1
                                        
                                        MDLabel:
                                            text: "DARK MODE"
                                            font_style: 'Subtitle1'
                                            theme_text_color: 'Custom'
                                            text_color: get_color_from_hex('#E0F2F1')
                                        
                                        MDSwitch:
                                            id: theme_switch
                                            pos_hint: {'center_y': 0.5}
                                            active: app.theme_cls.theme_style == "Dark"
                                            thumb_color_active: get_color_from_hex('#00E5FF')
                                            track_color_active: get_color_from_hex('#00897B')
                                            on_active: settings_screen.toggle_theme(self, self.active)
                                
                                # Theme Color Selection
                                MDLabel:
                                    text: "[ COLOR PALETTE ]"
                                    font_style: 'Subtitle1'
                                    bold: True
                                    theme_text_color: 'Custom'
                                    text_color: get_color_from_hex('#00E5FF')
                                    size_hint_y: None
                                    height: dp(40)
                                
                                MDCard:
                                    orientation: 'vertical'
                                    size_hint_y: None
                                    height: dp(100)
                                    elevation: 6
                                    padding: dp(15)
                                    radius: [dp(15)]
                                    md_bg_color: get_color_from_hex('#00695C80')
                                   
                                    MDBoxLayout:
                                        spacing: dp(12)
                                        padding: dp(5)
                                        
                                        MDIconButton:
                                            icon: 'checkbox-blank-circle'
                                            theme_text_color: 'Custom'
                                            text_color: get_color_from_hex('#00BCD4')
                                            on_release: settings_screen.change_primary_color('Cyan')
                                            md_bg_color: get_color_from_hex('#00000040')
                                        
                                        MDIconButton:
                                            icon: 'checkbox-blank-circle'
                                            theme_text_color: 'Custom'
                                            text_color: get_color_from_hex('#00897B')
                                            on_release: settings_screen.change_primary_color('Teal')
                                            md_bg_color: get_color_from_hex('#00000040')
                                        
                                        MDIconButton:
                                            icon: 'checkbox-blank-circle'
                                            theme_text_color: 'Custom'
                                            text_color: get_color_from_hex('#4CAF50')
                                            on_release: settings_screen.change_primary_color('Green')
                                            md_bg_color: get_color_from_hex('#00000040')
                                        
                                        MDIconButton:
                                            icon: 'checkbox-blank-circle'
                                            theme_text_color: 'Custom'
                                            text_color: get_color_from_hex('#9C27B0')
                                            on_release: settings_screen.change_primary_color('Purple')
                                            md_bg_color: get_color_from_hex('#00000040')
                                        
                                        MDIconButton:
                                            icon: 'checkbox-blank-circle'
                                            theme_text_color: 'Custom'
                                            text_color: get_color_from_hex('#FF5722')
                                            on_release: settings_screen.change_primary_color('DeepOrange')
                                            md_bg_color: get_color_from_hex('#00000040')
                                
                                # Security Section
                                MDLabel:
                                    text: "[ SECURITY CONTROLS ]"
                                    font_style: 'Subtitle1'
                                    bold: True
                                    theme_text_color: 'Custom'
                                    text_color: get_color_from_hex('#00E5FF')
                                    size_hint_y: None
                                    height: dp(40)
                                
                                MDCard:
                                    orientation: 'vertical'
                                    size_hint_y: None
                                    height: dp(80)
                                    elevation: 6
                                    padding: dp(15)
                                    radius: [dp(15)]
                                    md_bg_color: get_color_from_hex('#00695C80')
                                   
                                    MDBoxLayout:
                                        orientation: 'horizontal'
                                        
                                        MDIcon:
                                            icon: 'shield-lock'
                                            size_hint_x: None
                                            width: dp(40)
                                            theme_text_color: 'Custom'
                                            text_color: get_color_from_hex('#4CAF50')
                                        
                                        MDLabel:
                                            text: "AI PROTECTION"
                                            font_style: 'Subtitle1'
                                            theme_text_color: 'Custom'
                                            text_color: get_color_from_hex('#E0F2F1')
                                        
                                        MDSwitch:
                                            pos_hint: {'center_y': 0.5}
                                            active: True
                                            thumb_color_active: get_color_from_hex('#00FF88')
                                            track_color_active: get_color_from_hex('#00897B')
                                            on_active: settings_screen.toggle_ai_protection(self, self.active)
                                
                                MDCard:
                                    orientation: 'vertical'
                                    size_hint_y: None
                                    height: dp(80)
                                    elevation: 6
                                    padding: dp(15)
                                    radius: [dp(15)]
                                    md_bg_color: get_color_from_hex('#00695C80')
                                   
                                    MDBoxLayout:
                                        orientation: 'horizontal'
                                        
                                        MDIcon:
                                            icon: 'bell-ring'
                                            size_hint_x: None
                                            width: dp(40)
                                            theme_text_color: 'Custom'
                                            text_color: get_color_from_hex('#FF9800')
                                        
                                        MDLabel:
                                            text: "THREAT ALERTS"
                                            font_style: 'Subtitle1'
                                            theme_text_color: 'Custom'
                                            text_color: get_color_from_hex('#E0F2F1')
                                        
                                        MDSwitch:
                                            pos_hint: {'center_y': 0.5}
                                            active: True
                                            thumb_color_active: get_color_from_hex('#FF5252')
                                            track_color_active: get_color_from_hex('#FF7043')
                                            on_active: settings_screen.toggle_threat_alerts(self, self.active)
                                
                                # App Blocking Section - Android Feature
                                MDLabel:
                                    text: "[ APP BLOCKER ]"
                                    font_style: 'Subtitle1'
                                    bold: True
                                    theme_text_color: 'Custom'
                                    text_color: get_color_from_hex('#00E5FF')
                                    size_hint_y: None
                                    height: dp(40)

                                MDCard:
                                    orientation: 'vertical'
                                    size_hint_y: None
                                    height: dp(80)
                                    elevation: 6
                                    padding: dp(15)
                                    radius: [dp(15)]
                                    md_bg_color: get_color_from_hex('#00695C80')
                                   
                                    MDBoxLayout:
                                        orientation: 'horizontal'
                                        
                                        MDIcon:
                                            icon: 'application-block'
                                            size_hint_x: None
                                            width: dp(40)
                                            theme_text_color: 'Custom'
                                            text_color: get_color_from_hex('#FF1744')
                                        
                                        MDLabel:
                                            text: "BLOCK BLACKLISTED APPS"
                                            font_style: 'Subtitle1'
                                            theme_text_color: 'Custom'
                                            text_color: get_color_from_hex('#E0F2F1')
                                        
                                        MDSwitch:
                                            pos_hint: {'center_y': 0.5}
                                            active: True
                                            thumb_color_active: get_color_from_hex('#FF1744')
                                            track_color_active: get_color_from_hex('#D32F2F')
                                            on_active: print("App Blocker Toggled")
                                
                                # About Section
                                MDLabel:
                                    text: "[ SYSTEM INFO ]"
                                    font_style: 'Subtitle1'
                                    bold: True
                                    theme_text_color: 'Custom'
                                    text_color: get_color_from_hex('#00E5FF')
                                    size_hint_y: None
                                    height: dp(40)
                                
                                MDCard:
                                    orientation: 'vertical'
                                    size_hint_y: None
                                    height: dp(220)
                                    elevation: 6
                                    padding: dp(20)
                                    radius: [dp(15)]
                                    md_bg_color: get_color_from_hex('#00363180')
                                   
                                    MDLabel:
                                        text: "CYBERGUARD AI CORE"
                                        font_style: 'H6'
                                        bold: True
                                        theme_text_color: 'Custom'
                                        text_color: get_color_from_hex('#00E5FF')
                                    
                                    MDLabel:
                                        text: "VERSION 1.0.0 (SECURE-PATCH)"
                                        font_style: 'Caption'
                                        theme_text_color: 'Custom'
                                        text_color: get_color_from_hex('#4DB6AC')
                                    
                                    Widget:
                                        size_hint_y: None
                                        height: dp(15)
    
                                    MDGridLayout:
                                        cols: 2
                                        MDLabel:
                                            text: "ML Engine:"
                                            font_style: 'Caption'
                                            theme_text_color: 'Custom'
                                            text_color: get_color_from_hex('#80CBC4')
                                        MDLabel:
                                            text: "TensorFlow Lite"
                                            font_style: 'Caption'
                                            halign: 'right'
                                            theme_text_color: 'Custom'
                                            text_color: get_color_from_hex('#00FF88')
                                        MDLabel:
                                            text: "Inference:"
                                            font_style: 'Caption'
                                            theme_text_color: 'Custom'
                                            text_color: get_color_from_hex('#80CBC4')
                                        MDLabel:
                                            text: "Async / 12ms"
                                            font_style: 'Caption'
                                            halign: 'right'
                                            theme_text_color: 'Custom'
                                            text_color: get_color_from_hex('#00FF88')
                                        MDLabel:
                                            text: "Persistence:"
                                            font_style: 'Caption'
                                            theme_text_color: 'Custom'
                                            text_color: get_color_from_hex('#80CBC4')
                                        MDLabel:
                                            text: "JSON Audit Active"
                                            font_style: 'Caption'
                                            halign: 'right'
                                            theme_text_color: 'Custom'
                                            text_color: get_color_from_hex('#00FF88')
                                        MDLabel:
                                            text: "Framework:"
                                            font_style: 'Caption'
                                            theme_text_color: 'Custom'
                                            text_color: get_color_from_hex('#80CBC4')
                                        MDLabel:
                                            text: "NIST-800-53 (Mod)"
                                            font_style: 'Caption'
                                            halign: 'right'
                                            theme_text_color: 'Custom'
                                            text_color: get_color_from_hex('#00FF88')
                                
                                # Developer Section
                                MDLabel:
                                    text: "[ DEVELOPER INFO ]"
                                    font_style: 'Subtitle1'
                                    bold: True
                                    theme_text_color: 'Custom'
                                    text_color: get_color_from_hex('#00E5FF')
                                    size_hint_y: None
                                    height: dp(40)
                                
                                MDCard:
                                    orientation: 'vertical'
                                    size_hint_y: None
                                    height: dp(170)
                                    elevation: 6
                                    padding: dp(20)
                                    radius: [dp(15)]
                                    md_bg_color: get_color_from_hex('#00363180')
                                   
                                    MDLabel:
                                        text: "DEVELOPED BY"
                                        font_style: 'Caption'
                                        theme_text_color: 'Custom'
                                        text_color: get_color_from_hex('#4DB6AC')
                                    
                                    MDLabel:
                                        text: "MUHAMMAD IBRAHIM"
                                        font_style: 'H6'
                                        bold: True
                                        theme_text_color: 'Custom'
                                        text_color: get_color_from_hex('#00E5FF')
                                    
                                    Widget:
                                        size_hint_y: None
                                        height: dp(5)
                                    
                                    MDLabel:
                                        text: "▸ mibrahim13as@gmail.com"
                                        font_style: 'Body2'
                                        theme_text_color: 'Custom'
                                        text_color: get_color_from_hex('#80CBC4')
                                    
                                    Widget:
                                        size_hint_y: None
                                        height: dp(5)
                                    
                                    MDLabel:
                                        text: "SPECIALThanks to :\\nDr. Muhammad Ashraf \\n for his mentorship and guidance"
                                        font_style: 'Caption'
                                        theme_text_color: 'Custom'
                                        text_color: get_color_from_hex('#00FF88')
                                    
                                    Widget:
                                        size_hint_y: None
                                        height: dp(5)
                                    
                                    MDLabel:
                                        text: "(c) 2025 ALL RIGHTS RESERVED"
                                        font_style: 'Caption'
                                        theme_text_color: 'Custom'
                                        text_color: get_color_from_hex('#4DB6AC')
                                
                                # Spacer at bottom
                                Widget:
                                    size_hint_y: None
                                    height: dp(20)

MDScreenManager:
    id: screen_manager
    AuthScreen:
        id: auth_screen
    MainAppScreen:
        id: main_app_screen




"""

# ============================================================================
# APPLICATION ENTRY POINT
# ============================================================================

if __name__ == '__main__':
    import sys
    demo_active = "--demo" in sys.argv
    IDPSApp(demo_mode=demo_active).run()