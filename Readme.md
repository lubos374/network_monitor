Run by :python3 network_monitor.py

# Enhanced Network Monitor

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

A powerful command-line tool for comprehensive network diagnostics, monitoring, and troubleshooting. This utility provides real-time insights into your network's health, devices, connections, and performance metrics.

![Network Monitor Banner](https://via.placeholder.com/800x200?text=Enhanced+Network+Monitor)

## ✨ Features

- **Network Discovery**: Automatically scans and identifies all devices on your local network
- **Device Identification**: Determines device types, manufacturers, and hostnames
- **Connection Analysis**: Monitors active network connections and associated processes
- **Bandwidth Monitoring**: Real-time tracking of network interface bandwidth usage
- **Latency & Packet Loss**: Continuous measurement of network reliability metrics
- **Internet Connectivity**: Monitors connection stability and outage detection
- **DNS Resolution**: Tests and monitors DNS performance
- **Suspicious Activity Detection**: Identifies abnormal network behavior and bandwidth spikes
- **Network Health Analysis**: Provides comprehensive assessment of overall network health
- **Intelligent Recommendations**: Suggests improvements based on detected issues

## 📋 Requirements

- Python 3.6+
- Works on macOS and Linux (some features may be limited on other platforms)
- Standard system utilities: ping, arp, netstat, lsof, ps

## 🚀 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/network-monitor.git
   cd network-monitor
   ```

2. Make the script executable:
   ```bash
   chmod +x network_monitor.py
   ```

3. Install required Python packages:
   ```bash
   pip install ipaddress
   ```

## 💻 Usage

Run the network monitor with default settings:

```bash
./network_monitor.py
```

With custom parameters:

```bash
./network_monitor.py --network 192.168.1.0/24 --interval 5
```

### Command-line Options

| Option | Short | Description |
|--------|-------|-------------|
| `--network` | `-n` | Network to scan (CIDR notation, e.g., 192.168.1.0/24) |
| `--interval` | `-i` | Interval between connectivity checks in seconds (default: 10) |
| `--bandwidth-interval` | `-b` | Interval between bandwidth measurements in seconds (default: 2) |
| `--latency-interval` | `-l` | Interval between latency measurements in seconds (default: 30) |

## 📊 Output Examples

The tool provides several visual reports:

### Network Devices

```
Network Devices:
IP Address      MAC Address         Manufacturer    Type                 Hostname                  Status     Latency   Last Seen           
-------------------------------------------------------------------------------------------------------------------------------
192.168.1.1     00:11:22:33:44:55   Google          Router              router.local              online     5.3ms     2023-06-01 12:30:45
192.168.1.100   66:77:88:99:AA:BB   Apple           Computer/Mac        macbook-pro.local         online     2.1ms     2023-06-01 12:30:48
```

### Active Network Connections

```
Active Network Connections:
Program            PID    User      Protocol  Local Address           Remote Address          State       
----------------------------------------------------------------------------------------------
chrome             12345  username  tcp       192.168.1.100:52986     142.250.72.110:443      ESTABLISHED
```

### Bandwidth Monitoring

```
Bandwidth Monitoring:
Interface   RX/s       TX/s       Total RX        Total TX        Status    
------------------------------------------------------------------------
en0         1.2MB/s    126.5KB/s  1.5GB           234.6MB         ACTIVE
```

### Network Health Analysis

```
Network Health Analysis:
Gateway Latency: Avg: 5.3ms, Min: 2.1ms, Max: 15.7ms
Gateway Packet Loss: Avg: 0.0%
Internet Latency: Avg: 45.2ms
```

## 🔍 Advanced Features

### Suspicious Activity Detection

The tool automatically detects and reports:
- Sudden bandwidth spikes
- Connectivity pattern changes
- Abnormal packet loss
- DNS resolution failures

### Network Recommendations

Based on gathered data, the tool provides actionable recommendations:
- Suggestions for improving connectivity
- Identifying problematic devices
- Addressing latency and packet loss issues
- DNS configuration improvements

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the project
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## ❓ Troubleshooting

### Common Issues

- **Permission denied**: Run with sudo for full network scanning capabilities
- **Network scanning incomplete**: Ensure you're using the correct network CIDR
- **Missing device information**: Some devices may not respond to ARP or hostname resolution

### Getting Help

If you encounter issues not covered here, please open an issue on GitHub with:
- Your operating system and version
- Python version
- Complete error message
- Steps to reproduce the issue