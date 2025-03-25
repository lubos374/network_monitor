#!/usr/bin/env python3
"""
Enhanced Network Monitor - Advanced troubleshooting for network issues
"""

import subprocess
import time
import sys
import socket
import argparse
import threading
import signal
from datetime import datetime
import csv
import os
import ipaddress
import json
from concurrent.futures import ThreadPoolExecutor
import re
import shutil
import platform
from collections import deque

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

class EnhancedNetworkMonitor:
    def __init__(self):
        self.devices = {}
        self.connections = {}
        self.bandwidth_history = {}
        self.stop_monitoring = False
        self.lock = threading.Lock()
        self.connection_log = []
        self.internet_status = True
        self.latency_history = {}
        self.packet_loss_history = {}
        self.suspicious_activity = []
        self.bandwidth_spikes = []
        self.device_history = {}
        self.dns_queries = {}
        # Keep a history of bandwidth measurements for trending
        self.bandwidth_trend = deque(maxlen=30)
        # Default known manufacturer prefixes
        self.manufacturer_prefixes = {
            "00:1A:11": "Google",
            "B8:27:EB": "Raspberry Pi",
            "00:04:4B": "Apple",
            "B8:06:D": "Apple",
            "32:1E:BF": "Apple",
            "C0:67:14": "Deutsche Telekom",
            "08:96:D7": "AVM GmbH",
            "74:40:BB": "Samsung",
            "50:00:A": "Chromecast/Google",
            "68:C6:3A": "Amazon",
            "EC:FA:BC": "Amazon",
            "D0:73:D5": "LG Electronics",
            "F4:60:E2": "Sony",
            "F8:CA:B8": "Samsung"
        }
        
    def print_banner(self):
        banner = f"""
{Colors.BLUE}
 _____       _                           _   
| ____|_ __ | |__   __ _ _ __   ___ ___| |_ 
|  _| | '_ \| '_ \ / _` | '_ \ / __/ _ \ __|
| |___| | | | | | | (_| | | | | (_|  __/ |_ 
|_____|_| |_|_| |_|\__,_|_| |_|\___\___|\__|
                                            
 _   _      _                      _      __  __             _ _             
| \ | | ___| |___      _____  _ __| | __ |  \/  | ___  _ __ (_) |_ ___  _ __ 
|  \| |/ _ \ __\ \ /\ / / _ \| '__| |/ / | |\/| |/ _ \| '_ \| | __/ _ \| '__|
| |\  |  __/ |_ \ V  V / (_) | |  |   <  | |  | | (_) | | | | | || (_) | |   
|_| \_|\___|\__| \_/\_/ \___/|_|  |_|\_\ |_|  |_|\___/|_| |_|_|\__\___/|_|   
                                                                                                                                     
{Colors.ENDC}{Colors.GREEN}                                                   
    Enhanced Network Monitor v2.0
{Colors.ENDC}
    """
        terminal_width = shutil.get_terminal_size().columns
        print(banner)
        print(f"{Colors.BLUE}{'-' * terminal_width}{Colors.ENDC}")
        
    def get_gateway_ip(self):
        """Attempt to find the default gateway IP"""
        if platform.system() == "Darwin":  # macOS
            try:
                result = subprocess.run(['route', '-n', 'get', 'default'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if 'gateway' in line:
                        return line.split(':')[1].strip()
            except:
                pass
        elif platform.system() == "Linux":
            try:
                result = subprocess.run(['ip', 'route'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if 'default' in line:
                        return line.split()[2]
            except:
                pass
                
        return None  # Couldn't determine gateway
    
    def get_local_ip(self):
        """Get local IP address"""
        try:
            # Create a socket and connect to an external server to determine local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return None
    
    def get_network_cidr(self):
        """Determine network CIDR based on local IP"""
        local_ip = self.get_local_ip()
        if local_ip:
            # Assume a /24 network (common for home networks)
            network_base = '.'.join(local_ip.split('.')[:3]) + '.0'
            return f"{network_base}/24"
        return None
    
    def ping(self, host, count=1, timeout=1):
        """Check if host is reachable via ping and get statistics"""
        if platform.system() == "Darwin":  # macOS
            command = ['ping', '-c', str(count), '-W', str(timeout * 1000), host]
        else:  # Linux and others
            command = ['ping', '-c', str(count), '-W', str(timeout), host]
        
        try:
            result = subprocess.run(command, capture_output=True, text=True)
            output = result.stdout
            
            # Check if ping was successful
            success = result.returncode == 0
            
            # Extract latency if successful
            latency = None
            packet_loss = 100  # Default to 100% loss
            
            if success:
                # Extract packet loss percentage
                loss_match = re.search(r'(\d+(?:\.\d+)?)% packet loss', output)
                if loss_match:
                    packet_loss = float(loss_match.group(1))
                
                # Extract latency
                if packet_loss < 100:
                    time_match = re.search(r'min/avg/max(?:/mdev)? = (\d+\.\d+)/(\d+\.\d+)/(\d+\.\d+)', output)
                    if time_match:
                        latency = float(time_match.group(2))  # Use average latency
            
            return {
                'success': success,
                'latency': latency,
                'packet_loss': packet_loss
            }
        except Exception as e:
            return {
                'success': False,
                'latency': None,
                'packet_loss': 100,
                'error': str(e)
            }
    
    def identify_manufacturer(self, mac_address):
        """Try to identify device manufacturer from MAC address"""
        if not mac_address or mac_address == "Unknown" or mac_address == "This device":
            return "Unknown"
            
        # Normalize MAC address format
        mac = mac_address.upper().replace(':', '').replace('-', '')
        
        # Check first 6 characters (OUI)
        oui = ':'.join([mac[i:i+2] for i in range(0, 6, 2)]).upper()
        
        # Check against our known prefixes
        for prefix, manufacturer in self.manufacturer_prefixes.items():
            if oui.startswith(prefix.upper().replace(':', '')):
                return manufacturer
                
        # If we couldn't identify, return Unknown with the OUI
        return f"Unknown ({oui})"
    
    def get_mac_from_ip(self, ip):
        """Get MAC address for an IP using ARP"""
        try:
            if platform.system() == "Darwin":  # macOS
                cmd = ['arp', '-n', ip]
            else:  # Linux and others
                cmd = ['arp', '-a', ip]
                
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            # Parse output to find MAC address
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if ip in line:
                        mac_match = re.search(r'(([0-9A-Fa-f]{1,2}[:-]){5}([0-9A-Fa-f]{1,2}))', line)
                        if mac_match:
                            return mac_match.group(1)
        except:
            pass
            
        return "Unknown"
    
    def get_hostname(self, ip):
        """Try to resolve hostname from IP"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return "Unknown"
    
    def check_internet(self):
        """Check internet connectivity by pinging multiple servers and testing DNS"""
        servers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
        
        # Test ping to servers
        for server in servers:
            ping_result = self.ping(server)
            if ping_result['success']:
                # Also check DNS resolution as a secondary test
                try:
                    socket.gethostbyname("www.google.com")
                    return True
                except:
                    # Ping works but DNS fails - could be DNS issue
                    self.suspicious_activity.append({
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'type': 'DNS_FAILURE',
                        'details': 'Internet ping successful but DNS resolution failed'
                    })
                    
        return False
    
    def monitor_dns_resolution(self):
        """Check DNS resolution for common domains"""
        domains = ["google.com", "amazon.com", "microsoft.com", "apple.com", "cloudflare.com"]
        results = {}
        
        for domain in domains:
            try:
                start_time = time.time()
                ip = socket.gethostbyname(domain)
                resolve_time = time.time() - start_time
                results[domain] = {
                    'success': True,
                    'ip': ip,
                    'time': resolve_time
                }
            except Exception as e:
                results[domain] = {
                    'success': False,
                    'error': str(e)
                }
                
        self.dns_queries[datetime.now().strftime('%Y-%m-%d %H:%M:%S')] = results
        return results
    
    def get_active_connections(self):
        """Get all active network connections on the system"""
        try:
            # Use lsof to get all network connections
            cmd = ['lsof', '-i', '-n', '-P']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            active_connections = {}
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines[1:]:  # Skip header line
                    parts = line.split()
                    if len(parts) >= 9:
                        program = parts[0]
                        pid = parts[1]
                        user = parts[2]
                        protocol = 'unknown'
                        
                        # Extract protocol
                        if len(parts) > 8 and '(' in parts[8]:
                            protocol_match = re.search(r'\(([^)]+)\)', parts[8])
                            if protocol_match:
                                protocol = protocol_match.group(1)
                        
                        # Extract source and destination addresses
                        network_info = parts[8]
                        
                        src_ip = "unknown"
                        src_port = "unknown"
                        dst_ip = "N/A"
                        dst_port = "N/A"
                        state = "UNKNOWN"
                        
                        if '->' in network_info:
                            # Connected socket
                            src, dst = network_info.split('->')
                            
                            # Extract source IP and port
                            src_match = re.search(r'([^:]+):(\d+)', src)
                            if src_match:
                                src_ip = src_match.group(1)
                                src_port = src_match.group(2)
                                
                            # Extract destination IP and port
                            dst_match = re.search(r'([^:]+):(\d+)', dst)
                            if dst_match:
                                dst_ip = dst_match.group(1)
                                dst_port = dst_match.group(2)
                                
                            state = "ESTABLISHED"
                        else:
                            # Listening socket
                            src_match = re.search(r'([^:]+):(\d+)', network_info)
                            if src_match:
                                src_ip = src_match.group(1)
                                src_port = src_match.group(2)
                                
                            state = "LISTENING"
                                
                        # Create a connection key
                        conn_key = f"{pid}:{src_ip}:{src_port}:{dst_ip}:{dst_port}"
                        
                        # Save connection details
                        active_connections[conn_key] = {
                            'program': program,
                            'pid': pid,
                            'user': user,
                            'protocol': protocol,
                            'src_ip': src_ip,
                            'src_port': src_port,
                            'dst_ip': dst_ip,
                            'dst_port': dst_port,
                            'state': state,
                            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        }
            
            return active_connections
        except Exception as e:
            print(f"{Colors.FAIL}Error getting active connections: {e}{Colors.ENDC}")
            return {}
    
    def get_network_statistics(self):
        """Get network traffic statistics"""
        try:
            # Use netstat to get interface statistics
            cmd = ['netstat', '-ib']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            iface_stats = {}
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for line in lines[1:]:  # Skip header line
                    parts = line.split()
                    if len(parts) >= 10 and not parts[0].startswith('Name'):
                        iface = parts[0]
                        ibytes = int(parts[6])
                        obytes = int(parts[9])
                        
                        iface_stats[iface] = {
                            'iface': iface,
                            'ibytes': ibytes,
                            'obytes': obytes,
                            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        }
            
            return iface_stats
        except Exception as e:
            print(f"{Colors.FAIL}Error getting network statistics: {e}{Colors.ENDC}")
            return {}
    
    def get_process_info(self, pid):
        """Get detailed information about a process"""
        try:
            cmd = ['ps', '-p', pid, '-o', 'command=']
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                return result.stdout.strip()
            return "Unknown"
        except:
            return "Unknown"
    
    def resolve_service(self, port):
        """Try to resolve port to service name"""
        try:
            return socket.getservbyport(int(port))
        except:
            # Check common ports not in the standard database
            common_ports = {
                '3389': 'RDP',
                '8080': 'HTTP-Alt',
                '8443': 'HTTPS-Alt',
                '1194': 'OpenVPN',
                '5060': 'SIP',
                '5353': 'mDNS',
                '1723': 'PPTP',
                '1701': 'L2TP',
                '1812': 'RADIUS',
                '5900': 'VNC',
                '5901': 'VNC-1',
                '5902': 'VNC-2',
                '4500': 'IPsec NAT-T',
                '8888': 'HTTP Proxy',
                '8081': 'HTTP Alt',
                '8082': 'HTTP Alt',
                '6881': 'BitTorrent',
                '6969': 'BitTorrent',
                '6666': 'IRC',
                '11434': 'Ollama'
            }
            
            if port in common_ports:
                return common_ports[port]
                
            return "Unknown"
    
    def scan_host(self, ip):
        """Scan a single host and gather information"""
        ping_result = self.ping(ip)
        reachable = ping_result['success']
        
        if reachable:
            # Try to get MAC address
            mac = self.get_mac_from_ip(ip)
            
            # Try to get hostname
            hostname = self.get_hostname(ip)
            
            # Try to identify manufacturer
            manufacturer = self.identify_manufacturer(mac)
            
            # Check common ports to help identify device type
            device_type = "Unknown"
            ports_to_check = [80, 443, 8080, 8443, 22, 5000, 7000]
            open_ports = []
            
            for port in ports_to_check:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(0.5)
                        result = s.connect_ex((ip, port))
                        if result == 0:
                            open_ports.append(port)
                except:
                    pass
            
            # Make educated guess about device type
            if 80 in open_ports or 443 in open_ports:
                if manufacturer == "Google" or "Chromecast" in manufacturer:
                    device_type = "Chromecast/Google Device"
                elif "Apple" in manufacturer:
                    device_type = "Apple Device"
                elif "Samsung" in manufacturer or "LG" in manufacturer or "Sony" in manufacturer:
                    device_type = "Smart TV"
                elif 8080 in open_ports:
                    device_type = "Network Camera/IoT Device"
                else:
                    device_type = "Web Server/Smart Device"
            
            with self.lock:
                # Update device info
                self.devices[ip] = {
                    "ip": ip,
                    "mac": mac,
                    "hostname": hostname,
                    "manufacturer": manufacturer,
                    "device_type": device_type,
                    "open_ports": open_ports,
                    "status": "online",
                    "latency": ping_result['latency'],
                    "packet_loss": ping_result['packet_loss'],
                    "last_seen": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                
                # Update device history
                if ip not in self.device_history:
                    self.device_history[ip] = []
                    
                self.device_history[ip].append({
                    "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    "status": "online",
                    "latency": ping_result['latency']
                })
                
            return True
        return False
    
    def scan_network(self, network, max_workers=50):
        """Scan the entire network for devices"""
        try:
            network = ipaddress.ip_network(network)
        except ValueError as e:
            print(f"{Colors.FAIL}Error: {e}{Colors.ENDC}")
            return
            
        print(f"{Colors.HEADER}Scanning network {network}{Colors.ENDC}")
        print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        hosts = list(network.hosts())
        host_count = len(hosts)
        
        # Add the gateway to the list
        gateway_ip = self.get_gateway_ip()
        if gateway_ip:
            self.scan_host(gateway_ip)
            if gateway_ip in self.devices:
                self.devices[gateway_ip]["is_gateway"] = True
            
        # Add the local machine
        local_ip = self.get_local_ip()
        if local_ip:
            with self.lock:
                self.devices[local_ip] = {
                    "ip": local_ip,
                    "mac": "This device",
                    "hostname": "localhost",
                    "manufacturer": "Apple",
                    "device_type": "Computer/Mac",
                    "status": "online",
                    "last_seen": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    "is_self": True
                }
        
        spinner = ['|', '/', '-', '\\']
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = []
            for i, ip in enumerate(hosts):
                host = str(ip)
                # Skip gateway and local IP as we've already checked them
                if host == gateway_ip or host == local_ip:
                    continue
                    
                futures.append(executor.submit(self.scan_host, host))
                
                # Update spinner
                if i % 5 == 0:
                    sys.stdout.write(f"\r{Colors.BLUE}Scanning hosts {spinner[int(i/5) % 4]} {i}/{host_count}{Colors.ENDC}")
                    sys.stdout.flush()
            
            # Wait for all futures to complete
            for future in futures:
                future.result()
                
        print(f"\r{Colors.GREEN}Found {len(self.devices)} devices on the network{Colors.ENDC}")
        self.print_devices()
    
    def print_devices(self):
        """Print all discovered devices"""
        terminal_width = shutil.get_terminal_size().columns
        
        print(f"\n{Colors.HEADER}Network Devices:{Colors.ENDC}")
        print(f"{'IP Address':<15} {'MAC Address':<18} {'Manufacturer':<15} {'Type':<20} {'Hostname':<25} {'Status':<10} {'Latency':<8} {'Last Seen':<20}")
        print("-" * terminal_width)
        
        # Sort devices by IP
        for ip in sorted(self.devices.keys(), key=lambda x: [int(i) for i in x.split('.')]):
            device = self.devices[ip]
            
            # Special formatting for gateway and self
            prefix = ""
            if device.get("is_gateway"):
                prefix = f"{Colors.BLUE}[GATEWAY] {Colors.ENDC}"
            elif device.get("is_self"):
                prefix = f"{Colors.GREEN}[THIS DEVICE] {Colors.ENDC}"
                
            status_color = Colors.GREEN if device["status"] == "online" else Colors.FAIL
            
            # Format latency with color based on value
            latency = device.get("latency")
            if latency:
                if latency < 10:
                    latency_str = f"{Colors.GREEN}{latency:.1f}ms{Colors.ENDC}"
                elif latency < 50:
                    latency_str = f"{Colors.BLUE}{latency:.1f}ms{Colors.ENDC}"
                elif latency < 100:
                    latency_str = f"{Colors.WARNING}{latency:.1f}ms{Colors.ENDC}"
                else:
                    latency_str = f"{Colors.FAIL}{latency:.1f}ms{Colors.ENDC}"
            else:
                latency_str = "N/A"
                
            manufacturer = device.get("manufacturer", "Unknown")
            device_type = device.get("device_type", "Unknown")
            
            print(f"{prefix}{device['ip']:<15} {device['mac']:<18} {manufacturer:<15} {device_type:<20} {device['hostname']:<25} {status_color}{device['status']:<10}{Colors.ENDC} {latency_str:<8} {device['last_seen']:<20}")
    
    def analyze_connections(self):
        """Analyze current connections and print results"""
        # Get current connections
        current_connections = self.get_active_connections()
        
        # Update connection history
        with self.lock:
            self.connections.update(current_connections)
        
        # Group by program
        programs = {}
        for conn_id, conn in current_connections.items():
            program = conn['program']
            if program not in programs:
                programs[program] = []
            programs[program].append(conn)
        
        # Print results
        terminal_width = shutil.get_terminal_size().columns
        
        print(f"\n{Colors.HEADER}Active Network Connections:{Colors.ENDC}")
        print(f"{'Program':<20} {'PID':<7} {'User':<10} {'Protocol':<8} {'Local Address':<22} {'Remote Address':<22} {'State':<12}")
        print("-" * terminal_width)
        
        for program, conns in sorted(programs.items()):
            for conn in conns:
                local_addr = f"{conn['src_ip']}:{conn['src_port']}"
                remote_addr = f"{conn['dst_ip']}:{conn['dst_port']}" if conn['dst_ip'] != 'N/A' else "N/A"
                
                # Try to resolve service name
                if conn['src_port'].isdigit() and conn['src_port'] != 'unknown':
                    service = self.resolve_service(conn['src_port'])
                    if service != "Unknown":
                        local_addr += f" ({service})"
                
                if conn['dst_port'].isdigit() and conn['dst_port'] != 'N/A':
                    service = self.resolve_service(conn['dst_port'])
                    if service != "Unknown":
                        remote_addr += f" ({service})"
                
                state_color = Colors.GREEN if conn['state'] == 'ESTABLISHED' else Colors.BLUE
                
                print(f"{conn['program']:<20} {conn['pid']:<7} {conn['user']:<10} {conn['protocol']:<8} {local_addr:<22} {remote_addr:<22} {state_color}{conn['state']:<12}{Colors.ENDC}")
        
        # Get full command line for processes with network activity
        print(f"\n{Colors.HEADER}Process Details:{Colors.ENDC}")
        unique_pids = set(conn['pid'] for conn in current_connections.values())
        
        for pid in unique_pids:
            command = self.get_process_info(pid)
            if command:
                program = next(conn['program'] for conn in current_connections.values() if conn['pid'] == pid)
                print(f"{Colors.BOLD}{program} (PID {pid}):{Colors.ENDC} {command}")
    
    def monitor_bandwidth(self, interval=2):
        """Monitor bandwidth usage for each interface"""
        prev_stats = self.get_network_statistics()
        
        print(f"\n{Colors.HEADER}Bandwidth Monitoring:{Colors.ENDC}")
        print(f"{'Interface':<10} {'RX/s':<10} {'TX/s':<10} {'Total RX':<15} {'Total TX':<15} {'Status':<10}")
        print("-" * 70)
        
        while not self.stop_monitoring:
            time.sleep(interval)
            
            curr_stats = self.get_network_statistics()
            
            # Calculate bandwidth
            current_readings = {}
            for iface, curr in curr_stats.items():
                if iface in prev_stats:
                    prev = prev_stats[iface]
                    
                    # Calculate rates (bytes per second)
                    rx_rate = (curr['ibytes'] - prev['ibytes']) / interval
                    tx_rate = (curr['obytes'] - prev['obytes']) / interval
                    
                    # Store for history
                    if iface not in self.bandwidth_history:
                        self.bandwidth_history[iface] = []
                        
                    self.bandwidth_history[iface].append({
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'rx_rate': rx_rate,
                        'tx_rate': tx_rate,
                        'total_rx': curr['ibytes'],
                        'total_tx': curr['obytes']
                    })
                    
                    # Detect bandwidth spikes
                    if len(self.bandwidth_history[iface]) > 1:
                        prev_reading = self.bandwidth_history[iface][-2]
                        prev_rx = prev_reading['rx_rate']
                        
                        # If 3x increase in bandwidth, log as a spike
                        if rx_rate > prev_rx * 3 and rx_rate > 1000000:  # Over 1 MB/s
                            self.bandwidth_spikes.append({
                                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                'interface': iface,
                                'prev_rx': prev_rx,
                                'current_rx': rx_rate,
                                'increase_factor': rx_rate / prev_rx if prev_rx > 0 else float('inf')
                            })
                    
                    # Format for display
                    rx_rate_str = self.format_bytes(rx_rate) + "/s"
                    tx_rate_str = self.format_bytes(tx_rate) + "/s"
                    total_rx = self.format_bytes(curr['ibytes'])
                    total_tx = self.format_bytes(curr['obytes'])
                    
                    # Determine status based on activity
                    if rx_rate > 1000000 or tx_rate > 1000000:  # Over 1 MB/s
                        status = f"{Colors.WARNING}HIGH{Colors.ENDC}"
                    elif rx_rate > 100000 or tx_rate > 100000:  # Over 100 KB/s
                        status = f"{Colors.BLUE}ACTIVE{Colors.ENDC}"
                    elif rx_rate > 1000 or tx_rate > 1000:  # Over 1 KB/s
                        status = f"{Colors.GREEN}NORMAL{Colors.ENDC}"
                    else:
                        status = "IDLE"
                    
                    # Store current readings for trending
                    current_readings[iface] = {
                        'rx_rate': rx_rate,
                        'tx_rate': tx_rate
                    }
                    
                    # Skip interfaces with no activity
                    if rx_rate > 0 or tx_rate > 0 or iface.startswith('en'):
                        print(f"{iface:<10} {rx_rate_str:<10} {tx_rate_str:<10} {total_rx:<15} {total_tx:<15} {status:<10}")
            
            # Add to bandwidth trend
            self.bandwidth_trend.append(current_readings)
            
            # Update previous stats
            prev_stats = curr_stats
            
            if not self.stop_monitoring:
                # Clear previous lines
                interfaces_shown = sum(1 for iface in curr_stats if curr_stats[iface]['ibytes'] > 0 or curr_stats[iface]['obytes'] > 0 or iface.startswith('en'))
                print("\033[F" * (interfaces_shown + 2))
    
    def format_bytes(self, bytes_value):
        """Format bytes value to human-readable format"""
        if bytes_value < 1024:
            return f"{bytes_value:.1f}B"
        elif bytes_value < 1024 * 1024:
            return f"{bytes_value/1024:.1f}KB"
        elif bytes_value < 1024 * 1024 * 1024:
            return f"{bytes_value/(1024*1024):.1f}MB"
        else:
            return f"{bytes_value/(1024*1024*1024):.1f}GB"
    
    def monitor_latency(self, targets=None, interval=30):
        """Monitor latency to important targets"""
        if targets is None:
            # Default targets: gateway and major DNS providers
            gateway = self.get_gateway_ip()
            targets = ["8.8.8.8", "1.1.1.1"]
            if gateway:
                targets.insert(0, gateway)
        
        while not self.stop_monitoring:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            results = {}
            
            for target in targets:
                ping_result = self.ping(target, count=3)
                results[target] = ping_result
                
                # Store latency history
                if target not in self.latency_history:
                    self.latency_history[target] = []
                    
                self.latency_history[target].append({
                    'timestamp': timestamp,
                    'latency': ping_result['latency'],
                    'packet_loss': ping_result['packet_loss']
                })
                
                # Store packet loss history
                if target not in self.packet_loss_history:
                    self.packet_loss_history[target] = []
                    
                self.packet_loss_history[target].append({
                    'timestamp': timestamp,
                    'packet_loss': ping_result['packet_loss']
                })
                
                # Detect network degradation
                if (ping_result['latency'] and ping_result['latency'] > 100) or ping_result['packet_loss'] > 0:
                    self.suspicious_activity.append({
                        'timestamp': timestamp,
                        'type': 'NETWORK_DEGRADATION',
                        'target': target,
                        'latency': ping_result['latency'],
                        'packet_loss': ping_result['packet_loss']
                    })
            
            time.sleep(interval)
    
    def monitor_internet(self, interval=10):
        """Monitor internet connectivity"""
        terminal_width = shutil.get_terminal_size().columns
        
        print(f"\n{Colors.HEADER}Internet Connectivity Monitoring:{Colors.ENDC}")
        print(f"Checking connection every {interval} seconds.")
        print(f"{'Timestamp':<20} {'Status':<10} {'Gateway':<10} {'DNS':<10} {'Latency':<10} {'Packet Loss':<15}")
        print("-" * terminal_width)
        
        last_status = None
        outage_start = None
        
        # Start DNS monitoring
        dns_results = self.monitor_dns_resolution()
        dns_status = all(result['success'] for result in dns_results.values())
        
        while not self.stop_monitoring:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # Check internet connectivity
            internet_available = self.check_internet()
            
            # Check gateway
            gateway_ip = self.get_gateway_ip()
            gateway_status = "N/A"
            gateway_latency = None
            gateway_loss = None
            
            if gateway_ip:
                gateway_ping = self.ping(gateway_ip, count=3)
                gateway_status = "OK" if gateway_ping['success'] else "FAIL"
                gateway_latency = gateway_ping['latency']
                gateway_loss = gateway_ping['packet_loss']
            
            # Check DNS resolution periodically
            if int(time.time()) % 60 < interval:  # Check DNS roughly once per minute
                dns_results = self.monitor_dns_resolution()
                dns_status = all(result['success'] for result in dns_results.values())
            
            # Format status with colors
            status_color = Colors.GREEN if internet_available else Colors.FAIL
            status_text = "ONLINE" if internet_available else "OFFLINE"
            
            gateway_color = Colors.GREEN if gateway_status == "OK" else (Colors.FAIL if gateway_status == "FAIL" else Colors.WARNING)
            dns_color = Colors.GREEN if dns_status else Colors.FAIL
            dns_text = "OK" if dns_status else "FAIL"
            
            # Format latency with color
            if gateway_latency:
                if gateway_latency < 10:
                    latency_text = f"{Colors.GREEN}{gateway_latency:.1f}ms{Colors.ENDC}"
                elif gateway_latency < 50:
                    latency_text = f"{Colors.BLUE}{gateway_latency:.1f}ms{Colors.ENDC}"
                elif gateway_latency < 100:
                    latency_text = f"{Colors.WARNING}{gateway_latency:.1f}ms{Colors.ENDC}"
                else:
                    latency_text = f"{Colors.FAIL}{gateway_latency:.1f}ms{Colors.ENDC}"
            else:
                latency_text = "N/A"
                
            # Format packet loss
            if gateway_loss is not None:
                if gateway_loss == 0:
                    loss_text = f"{Colors.GREEN}0%{Colors.ENDC}"
                elif gateway_loss < 5:
                    loss_text = f"{Colors.BLUE}{gateway_loss:.1f}%{Colors.ENDC}"
                elif gateway_loss < 20:
                    loss_text = f"{Colors.WARNING}{gateway_loss:.1f}%{Colors.ENDC}"
                else:
                    loss_text = f"{Colors.FAIL}{gateway_loss:.1f}%{Colors.ENDC}"
            else:
                loss_text = "N/A"
            
            # Only log when status changes or significant degradation
            if (last_status != internet_available or 
                (gateway_latency and gateway_latency > 100) or 
                (gateway_loss and gateway_loss > 10)):
                
                print(f"{timestamp:<20} {status_color}{status_text:<10}{Colors.ENDC} {gateway_color}{gateway_status:<10}{Colors.ENDC} {dns_color}{dns_text:<10}{Colors.ENDC} {latency_text:<10} {loss_text:<15}")
                
                # Record connection events
                if not internet_available and last_status:
                    outage_start = timestamp
                    # Capture current connections during outage
                    self.analyze_connections()
                    
                    # Check for bandwidth spikes just before outage
                    # (this helps identify if a specific application might be causing issues)
                    if len(self.bandwidth_trend) > 5:
                        # Print bandwidth trends leading up to outage
                        print(f"{Colors.WARNING}Bandwidth trend before outage:{Colors.ENDC}")
                        for i in range(5, 0, -1):
                            if len(self.bandwidth_trend) >= i:
                                for iface, data in self.bandwidth_trend[-i].items():
                                    if iface.startswith('en') and (data['rx_rate'] > 100000 or data['tx_rate'] > 100000):
                                        rx = self.format_bytes(data['rx_rate']) + "/s"
                                        tx = self.format_bytes(data['tx_rate']) + "/s"
                                        print(f"  {i} readings ago: {iface} RX: {rx}, TX: {tx}")
                elif outage_start and internet_available and not last_status:
                    # Calculate outage duration
                    start_time = datetime.strptime(outage_start, '%Y-%m-%d %H:%M:%S')
                    end_time = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
                    duration = (end_time - start_time).total_seconds()
                    
                    self.connection_log.append({
                        "event": "outage",
                        "start": outage_start,
                        "end": timestamp,
                        "duration_seconds": duration
                    })
                    
                    print(f"{Colors.WARNING}Outage duration: {duration:.1f} seconds{Colors.ENDC}")
                    outage_start = None
                    
                # Update status
                last_status = internet_available
                
                # If connection was restored, rescan network and analyze connections
                if internet_available and not last_status:
                    print(f"{Colors.BLUE}Connection restored. Analyzing network...{Colors.ENDC}")
                    network = self.get_network_cidr()
                    if network:
                        self.scan_network(network)
                    self.analyze_connections()
            
            # Wait for the next check
            time.sleep(interval)
    
    def analyze_network_health(self):
        """Analyze overall network health and print a report"""
        print(f"\n{Colors.HEADER}Network Health Analysis:{Colors.ENDC}")
        
        # Check gateway latency trends
        gateway_ip = self.get_gateway_ip()
        if gateway_ip and gateway_ip in self.latency_history and len(self.latency_history[gateway_ip]) > 0:
            latencies = [entry['latency'] for entry in self.latency_history[gateway_ip] if entry['latency'] is not None]
            if latencies:
                avg_latency = sum(latencies) / len(latencies)
                max_latency = max(latencies)
                min_latency = min(latencies)
                
                print(f"Gateway Latency: Avg: {avg_latency:.1f}ms, Min: {min_latency:.1f}ms, Max: {max_latency:.1f}ms")
                
                if avg_latency > 50:
                    print(f"{Colors.WARNING}High average gateway latency detected. This may indicate local network issues.{Colors.ENDC}")
        
        # Check packet loss
        if gateway_ip and gateway_ip in self.packet_loss_history and len(self.packet_loss_history[gateway_ip]) > 0:
            losses = [entry['packet_loss'] for entry in self.packet_loss_history[gateway_ip]]
            avg_loss = sum(losses) / len(losses)
            
            print(f"Gateway Packet Loss: Avg: {avg_loss:.1f}%")
            
            if avg_loss > 0:
                print(f"{Colors.WARNING}Packet loss detected to gateway. This indicates local network issues.{Colors.ENDC}")
        
        # Internet latency (to DNS servers)
        internet_targets = ["8.8.8.8", "1.1.1.1"]
        internet_latencies = []
        
        for target in internet_targets:
            if target in self.latency_history and len(self.latency_history[target]) > 0:
                target_latencies = [entry['latency'] for entry in self.latency_history[target] if entry['latency'] is not None]
                if target_latencies:
                    avg = sum(target_latencies) / len(target_latencies)
                    internet_latencies.append(avg)
        
        if internet_latencies:
            avg_internet_latency = sum(internet_latencies) / len(internet_latencies)
            print(f"Internet Latency: Avg: {avg_internet_latency:.1f}ms")
            
            if avg_internet_latency > 150:
                print(f"{Colors.WARNING}High internet latency detected. This may indicate ISP or internet backbone issues.{Colors.ENDC}")
        
        # Connection stability
        if self.connection_log:
            outage_count = len(self.connection_log)
            total_outage_time = sum(event['duration_seconds'] for event in self.connection_log)
            
            print(f"Connection Stability: {outage_count} outages, total duration: {total_outage_time:.1f} seconds")
            
            if outage_count > 0:
                print(f"{Colors.WARNING}Connection instability detected with {outage_count} outages.{Colors.ENDC}")
        
        # Bandwidth usage
        active_interfaces = [iface for iface in self.bandwidth_history.keys() if iface.startswith('en') and len(self.bandwidth_history[iface]) > 0]
        
        for iface in active_interfaces:
            rx_rates = [entry['rx_rate'] for entry in self.bandwidth_history[iface]]
            tx_rates = [entry['tx_rate'] for entry in self.bandwidth_history[iface]]
            
            if rx_rates and tx_rates:
                avg_rx = sum(rx_rates) / len(rx_rates)
                max_rx = max(rx_rates)
                avg_tx = sum(tx_rates) / len(tx_rates)
                max_tx = max(tx_rates)
                
                print(f"Interface {iface}: Avg RX: {self.format_bytes(avg_rx)}/s, Max RX: {self.format_bytes(max_rx)}/s")
                print(f"Interface {iface}: Avg TX: {self.format_bytes(avg_tx)}/s, Max TX: {self.format_bytes(max_tx)}/s")
                
                if max_rx > 10 * 1024 * 1024:  # 10 MB/s
                    print(f"{Colors.WARNING}High bandwidth usage detected on {iface}. This may cause network congestion.{Colors.ENDC}")
        
        # Bandwidth spikes
        if self.bandwidth_spikes:
            print(f"{Colors.WARNING}Detected {len(self.bandwidth_spikes)} bandwidth spikes.{Colors.ENDC}")
            for i, spike in enumerate(self.bandwidth_spikes[-3:]):  # Show last 3 spikes
                print(f"  Spike {i+1}: {spike['timestamp']} - Interface {spike['interface']}, {self.format_bytes(spike['current_rx'])}/s ({spike['increase_factor']:.1f}x increase)")
        
        # Suspicious activity
        if self.suspicious_activity:
            print(f"{Colors.WARNING}Detected {len(self.suspicious_activity)} suspicious network events.{Colors.ENDC}")
            for i, event in enumerate(self.suspicious_activity[-3:]):  # Show last 3 events
                print(f"  Event {i+1}: {event['timestamp']} - {event['type']}")
        
        # Devices with unusual behavior
        for ip, history in self.device_history.items():
            if len(history) > 1:
                # Check for devices that disappear and reappear
                status_changes = sum(1 for i in range(1, len(history)) if history[i]['status'] != history[i-1]['status'])
                if status_changes > 2:
                    device_name = self.devices.get(ip, {}).get('hostname', 'Unknown')
                    print(f"{Colors.WARNING}Device {ip} ({device_name}) has unstable connectivity ({status_changes} status changes).{Colors.ENDC}")
    
    def save_connection_log(self, filename="network_monitor_data.json"):
        """Save all monitoring data to JSON file"""
        data = {
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "devices": self.devices,
            "connections": self.connections,
            "connection_log": self.connection_log,
            "bandwidth_history": self.bandwidth_history,
            "latency_history": self.latency_history,
            "packet_loss_history": self.packet_loss_history,
            "suspicious_activity": self.suspicious_activity,
            "bandwidth_spikes": self.bandwidth_spikes,
            "dns_queries": self.dns_queries
        }
            
        try:
            with open(filename, 'w') as jsonfile:
                json.dump(data, jsonfile, indent=2, default=str)
                    
            print(f"{Colors.GREEN}Network monitoring data saved to {filename}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}Error saving data: {e}{Colors.ENDC}")
    
    def print_recommendations(self):
        """Print recommendations based on monitoring data"""
        print(f"\n{Colors.HEADER}Network Recommendations:{Colors.ENDC}")
        
        recommendations = []
        
        # Gateway issues
        gateway_ip = self.get_gateway_ip()
        if gateway_ip and gateway_ip in self.latency_history:
            latencies = [entry['latency'] for entry in self.latency_history[gateway_ip] if entry['latency'] is not None]
            if latencies and sum(latencies) / len(latencies) > 50:
                recommendations.append(f"Your router has high response times. Consider restarting your router or checking for interference.")
        
        # Packet loss
        if gateway_ip and gateway_ip in self.packet_loss_history:
            losses = [entry['packet_loss'] for entry in self.packet_loss_history[gateway_ip]]
            if losses and sum(losses) / len(losses) > 1:
                recommendations.append(f"Packet loss detected on your local network. This could indicate Wi-Fi interference or router issues.")
        
        # Connection stability
        if len(self.connection_log) > 0:
            recommendations.append(f"Your internet connection has experienced {len(self.connection_log)} outages. Contact your ISP if this continues.")
        
        # Bandwidth issues
        if self.bandwidth_spikes:
            recommendations.append(f"Detected sudden bandwidth spikes. Check for large downloads, video streams, or system updates.")
        
        # Device behavior
        unstable_devices = []
        for ip, history in self.device_history.items():
            if len(history) > 1:
                status_changes = sum(1 for i in range(1, len(history)) if history[i]['status'] != history[i-1]['status'])
                if status_changes > 2:
                    device_name = self.devices.get(ip, {}).get('hostname', 'Unknown')
                    device_type = self.devices.get(ip, {}).get('device_type', 'Unknown')
                    unstable_devices.append(f"{ip} ({device_name}, {device_type})")
        
        if unstable_devices:
            recommendations.append(f"These devices have unstable connectivity which may affect your network: {', '.join(unstable_devices)}")
        
        # DNS issues
        dns_failures = sum(1 for results in self.dns_queries.values() for domain, result in results.items() if not result['success'])
        if dns_failures > 0:
            recommendations.append(f"DNS resolution failures detected. Consider using alternative DNS servers like 1.1.1.1 or 8.8.8.8.")
        
        # Print recommendations
        if recommendations:
            for i, recommendation in enumerate(recommendations):
                print(f"{i+1}. {recommendation}")
        else:
            print("No specific recommendations at this time. Your network appears to be operating normally.")
    
    def signal_handler(self, sig, frame):
        """Handle Ctrl+C"""
        print(f"\n{Colors.WARNING}Monitoring stopped by user.{Colors.ENDC}")
        self.stop_monitoring = True
        
        # Final analysis
        self.analyze_network_health()
        self.print_recommendations()
        
        # Save data
        self.save_connection_log()
            
        sys.exit(0)
    
    def main(self):
        """Main function to parse arguments and start monitoring"""
        parser = argparse.ArgumentParser(description='Enhanced Network Monitor')
        parser.add_argument('-n', '--network', help='Network to scan (CIDR notation, e.g., 192.168.1.0/24)')
        parser.add_argument('-i', '--interval', type=int, default=10, help='Interval between connectivity checks (seconds)')
        parser.add_argument('-b', '--bandwidth-interval', type=int, default=2, help='Interval between bandwidth measurements (seconds)')
        parser.add_argument('-l', '--latency-interval', type=int, default=30, help='Interval between latency measurements (seconds)')
        
        args = parser.parse_args()
        
        self.print_banner()
        
        # Register signal handler for Ctrl+C
        signal.signal(signal.SIGINT, self.signal_handler)
        
        # If network not specified, try to determine it
        network = args.network
        if not network:
            network = self.get_network_cidr()
            if not network:
                print(f"{Colors.FAIL}Error: Could not determine network. Please specify with -n option.{Colors.ENDC}")
                return
        
        # Initial network scan
        self.scan_network(network)
        
        # Initial connection analysis
        print(f"\n{Colors.HEADER}Initial Connection Analysis:{Colors.ENDC}")
        self.analyze_connections()
        
        # Start bandwidth monitoring in a separate thread
        bandwidth_thread = threading.Thread(target=self.monitor_bandwidth, 
                                          args=(args.bandwidth_interval,), 
                                          daemon=True)
        bandwidth_thread.start()
        
        # Start latency monitoring in a separate thread
        latency_thread = threading.Thread(target=self.monitor_latency,
                                         args=(None, args.latency_interval),
                                         daemon=True)
        latency_thread.start()
        
        # Start internet connectivity monitoring
        self.monitor_internet(args.interval)

if __name__ == "__main__":
    try:
        monitor = EnhancedNetworkMonitor()
        monitor.main()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}Monitor interrupted by user.{Colors.ENDC}")
    except Exception as e:
        print(f"\n{Colors.FAIL}Error: {e}{Colors.ENDC}")