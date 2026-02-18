import socket
import time
import random
import sys

# CONFIGURATION
TARGET_IP = "10.7.64.232"
TARGET_PORT = 5005

def print_banner():
    """Print a cool cyber-security banner."""
    print("\033[91m") # Red Color
    print("=================================================")
    print("   🚀 RED TEAM ATTACK CONSOLE (IDPS TESTER)    ")
    print("=================================================")
    print(f" TARGET: {TARGET_IP}:{TARGET_PORT} (UDP)")
    print("=================================================")
    print("\033[0m")

def send_packet(size_min, size_max, count=1, delay=0.1, mode="Normal", payload_override=None, target_ip=None, target_port=None):
    """Send UDP packets of random content and specific size range."""
    
    # Use globals if not provided
    dest_ip = target_ip if target_ip else TARGET_IP
    dest_port = target_port if target_port else TARGET_PORT

    print(f"\n[*] Initiating {mode} Traffic Simulation to {dest_ip}:{dest_port}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    try:
        for i in range(count):
            if payload_override:
                payload = payload_override
                size = len(payload)
            else:
                # Generate random payload of target size
                size = random.randint(size_min, size_max)
                payload = bytes([random.randint(0, 255) for _ in range(size)])
            
            sock.sendto(payload, (dest_ip, dest_port))
            
            # Visual Feedback
            status_color = "\033[92m" if "Normal" in mode else ("\033[93m" if "Suspicious" in mode else "\033[91m")
            print(f"{status_color}   -> SENT Packet #{i+1} | Size: {size} bytes | Type: {mode}\033[0m")
            time.sleep(delay)
            
        print(f"\n[+] {count} Packets sent successfully.")
        
    except Exception as e:
        print(f"\n[!] Error sending packet: {e}")
    finally:
        sock.close()

def main():
    global TARGET_IP
    print_banner()
    
    # Feature: Support Command Line Arguments for Automation/External Use
    # Usage: python attack_script.py 192.168.1.X
    if len(sys.argv) > 1:
        TARGET_IP = sys.argv[1]
        print(f"\n[*] TARGET LOCKED: {TARGET_IP} (Provided via Command Line)")
    else:
        # Interactive Mode
        print("\n[?] TIP: To attack from another device, copy this file and run:")
        print("    python attack_script.py <IDPS_MACHINE_IP>")
        
        target_input = input(f"\nEnter Target IP (Default {TARGET_IP}): ").strip()
        if target_input:
            TARGET_IP = target_input
        
    while True:
        print(f"\n--- TARGET: {TARGET_IP} ---")
        print("SELECT ATTACK VECTOR:")
        print("1. [SAFE]       Web Browsing / Ping (Small Packets)")
        print("2. [SUSPICIOUS] Port Scanning / Probing (Medium Packets)")
        print("3. [CRITICAL]   DDoS / Buffer Overflow (Large Packets)")
        print("4. [CHAOS]      Mixed Traffic Burst (Demo Mode)")
        print("5. [RULE TEST]  Malware Signature (Triggers Hardcoded Rule)")
        print("6. [RULE TEST]  NOP Sled / Buffer Overflow (Triggers While Loop)")
        print("7. Exit")
        
        choice = input("\nroot@kalilinux:~# ")
        
        if choice == '1':
            # Normal: 20-100 bytes
            send_packet(20, 100, count=5, delay=0.5, mode="Normal")
        
        elif choice == '2':
            # Suspicious: 400-600 bytes
            send_packet(400, 600, count=5, delay=0.5, mode="Suspicious")
            
        elif choice == '3':
            # Attack: 850-1024 bytes
            send_packet(850, 1024, count=10, delay=0.2, mode="CRITICAL ATTACK")
            
        elif choice == '4':
            # Mixed Burst
            print("\n[*] STARTING CHAOS MODE...")
            for _ in range(5):
                r = random.random()
                if r < 0.5:
                     send_packet(20, 100, count=1, delay=0.1, mode="Normal")
                elif r < 0.8:
                     send_packet(400, 600, count=1, delay=0.1, mode="Suspicious")
                else:
                     send_packet(900, 1024, count=1, delay=0.1, mode="CRITICAL")
                time.sleep(0.2)

        elif choice == '5':
            # Trigger Hardcoded Rule: Malware Signature
            payload = b"GET /index.html HTTP/1.1\r\nUser-Agent: MALWARE-BOT\r\n\r\n"
            send_packet(0, 0, count=1, mode="RULE: MALWARE SIG", payload_override=payload)
            
        elif choice == '6':
            # Trigger Hardcoded Rule: NOP Sled (While Loop Check)
            # Create a payload with 10 NOP instructions (0x90)
            payload = b"\x90" * 20 + b"\xcc" * 10 # NOP sled + INT 3
            send_packet(0, 0, count=1, mode="RULE: BUFFER OVERFLOW", payload_override=payload)
                
        elif choice == '7':
            print("\nExiting Red Team Console...")
            break
        
        else:
            print("\n[!] Invalid Option")
        
        input("\nPress Enter to continue...")
        print("\n\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
