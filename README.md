MikroTik RouterOS Brute Force Tool
A Python-based security assessment tool for discovering MikroTik devices and testing credential strength via the Winbox/API interface.

Features
Network Discovery: Uses MNDP protocol to identify MikroTik devices on the local network

Multi-threaded Brute Force: Tests credentials across discovered devices simultaneously

Wordlist Support: Accepts custom username/password wordlists

Success Logging: Records compromised credentials to success.txt

Technical Implementation
Dependencies
# pip install scapy librouteros
Code Structure
Discovery Phase (discover_mikrotik_interfaces())

Broadcasts MNDP packets to identify MikroTik devices

Extracts:

- MAC address

- IP address

- Device identity

Brute Force Engine (brute_force_login())

Attempts authentication via RouterOS API (port 8728)

Handles:

- TrapError: Invalid credentials

- Connection errors: Network issues

Threading Model

- Spawns separate threads per target device

- Prevents network timeout locks

Usage
# python3 mikrotik-bruteforce.py
Input Prompts:

1. Network interface (e.g., eth0)

2. Path to username wordlist

3. Path to password wordlist

Sample Wordlists:
usernames.txt
text
admin
user
mikrotik

passwords.txt
text
admin
password
12345

Output Example
[+] Found MikroTik - MAC: 00:0C:42:1A:9D:3B, IP: 192.168.1.1, Identity: RouterOS
[!] Starting brute force on target 00:0C:42:1A:9D:3B (192.168.1.1)
[FAILED] admin:admin
[SUCCESS] IP: 192.168.1.1 | MAC: 00:0C:42:1A:9D:3B | Username: admin | Password: P@ssw0rd2023
