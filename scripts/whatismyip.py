#!/usr/bin/env python3
"""
Cross-platform script to display IPv4 addresses for all network interfaces.
Works on Windows, macOS, and Ubuntu/Linux systems.
"""

import re
import sys
import subprocess
import platform


def get_linux_ips():
    """Get IP addresses on Linux using 'ip -4 addr' command."""
    try:
        result = subprocess.run(
            ['ip', '-4', 'addr'],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def get_macos_ips():
    """Get IP addresses on macOS using 'ifconfig' command."""
    try:
        result = subprocess.run(
            ['ifconfig'],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def get_windows_ips():
    """Get IP addresses on Windows using 'ipconfig' command."""
    try:
        result = subprocess.run(
            ['ipconfig'],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def parse_linux_output(output):
    """Parse Linux 'ip -4 addr' output and format it nicely."""
    lines = output.strip().split('\n')
    formatted_lines = []
    first_interface = True
    
    for line in lines:
        # Check if this is a new interface (starts with number and colon)
        if re.match(r'^\d+:', line):
            # Add empty line before each interface except the first one
            if not first_interface:
                formatted_lines.append('')
            first_interface = False
        
        formatted_lines.append(line)
    
    return '\n'.join(formatted_lines)


def parse_macos_output(output):
    """Parse macOS 'ifconfig' output and extract IPv4 addresses."""
    lines = output.strip().split('\n')
    interfaces = {}
    current_interface = None
    
    for line in lines:
        # Check if this is an interface name line
        if_match = re.match(r'^(\w+):', line)
        if if_match:
            current_interface = if_match.group(1)
            interfaces[current_interface] = []
        
        # Check for inet (IPv4) addresses
        if current_interface:
            inet_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', line)
            if inet_match:
                ip = inet_match.group(1)
                # Extract netmask and calculate CIDR notation
                netmask_match = re.search(r'netmask (0x[0-9a-fA-F]+|[\d\.]+)', line)
                netmask = netmask_match.group(1) if netmask_match else ''
                
                # Convert hex netmask to CIDR if needed
                cidr = ''
                if netmask.startswith('0x'):
                    # Convert hex to CIDR notation
                    hex_val = int(netmask, 16)
                    cidr_bits = bin(hex_val).count('1')
                    cidr = f"/{cidr_bits}"
                elif '.' in netmask:
                    # Convert dotted decimal to CIDR
                    octets = netmask.split('.')
                    binary = ''.join([bin(int(o))[2:].zfill(8) for o in octets])
                    cidr_bits = binary.count('1')
                    cidr = f"/{cidr_bits}"
                
                interfaces[current_interface].append((ip, cidr))
    
    # Format output similar to Linux 'ip -4 addr'
    formatted_lines = []
    interface_num = 1
    for interface, ips in interfaces.items():
        if ips:  # Only show interfaces with IP addresses
            for ip, cidr in ips:
                formatted_lines.append(f"{interface_num}: {interface}: <UP>")
                formatted_lines.append(f"    inet {ip}{cidr} scope global {interface}")
                interface_num += 1
    
    return '\n'.join(formatted_lines)


def parse_windows_output(output):
    """Parse Windows 'ipconfig' output and format it nicely."""
    lines = output.strip().split('\n')
    interfaces = {}
    current_interface = None
    current_subnet = None
    
    for i, line in enumerate(lines):
        # Check if this is an adapter/interface name line
        # Windows format: "Ethernet adapter Ethernet:" or "Wireless LAN adapter Wi-Fi:"
        adapter_match = re.match(r'^([^:]+):\s*$', line.strip())
        if adapter_match:
            current_interface = adapter_match.group(1).strip()
            interfaces[current_interface] = []
            current_subnet = None
        
        # Check for IPv4 addresses
        # Windows format: "   IPv4 Address. . . . . . . . . . . : 192.168.1.100"
        if current_interface:
            ipv4_match = re.search(r'IPv4 Address[^:]*:\s*(\d+\.\d+\.\d+\.\d+)', line, re.IGNORECASE)
            if ipv4_match:
                ip = ipv4_match.group(1)
                # Look ahead for subnet mask (usually on next few lines)
                subnet = None
                for j in range(i + 1, min(i + 5, len(lines))):
                    subnet_match = re.search(r'Subnet Mask[^:]*:\s*(\d+\.\d+\.\d+\.\d+)', lines[j], re.IGNORECASE)
                    if subnet_match:
                        subnet = subnet_match.group(1)
                        break
                
                # Convert subnet mask to CIDR if available
                cidr = ''
                if subnet:
                    octets = subnet.split('.')
                    binary = ''.join([bin(int(o))[2:].zfill(8) for o in octets])
                    cidr_bits = binary.count('1')
                    cidr = f"/{cidr_bits}"
                
                interfaces[current_interface].append((ip, cidr))
    
    # Format output similar to Linux 'ip -4 addr'
    formatted_lines = []
    interface_num = 1
    for interface, ips in interfaces.items():
        if ips:  # Only show interfaces with IP addresses
            for ip, cidr in ips:
                # Clean up interface name (remove "adapter" and extra words)
                clean_name = re.sub(r'\s+adapter\s+', ' ', interface, flags=re.IGNORECASE)
                clean_name = clean_name.strip()
                formatted_lines.append(f"{interface_num}: {clean_name}: <UP>")
                formatted_lines.append(f"    inet {ip}{cidr} scope global {clean_name}")
                interface_num += 1
    
    return '\n'.join(formatted_lines)


def main():
    """Main function to detect OS and display IP addresses."""
    system = platform.system().lower()
    
    print()
    print(f"Detected OS: {platform.system()} {platform.release()}")
    print("=" * 60)
    print()
    
    if system == 'linux':
        output = get_linux_ips()
        if output:
            print(parse_linux_output(output))
        else:
            print("Error: Could not execute 'ip -4 addr' command.")
            sys.exit(1)
    
    elif system == 'darwin':  # macOS
        output = get_macos_ips()
        if output:
            formatted = parse_macos_output(output)
            if formatted:
                print(formatted)
            else:
                print("No IPv4 addresses found.")
        else:
            print("Error: Could not execute 'ifconfig' command.")
            sys.exit(1)
    
    elif system == 'windows':
        output = get_windows_ips()
        if output:
            formatted = parse_windows_output(output)
            if formatted:
                print(formatted)
            else:
                print("No IPv4 addresses found.")
        else:
            print("Error: Could not execute 'ipconfig' command.")
            sys.exit(1)
    
    else:
        print(f"Unsupported operating system: {system}")
        print("This script is designed for Windows, Linux, and macOS.")
        sys.exit(1)

    print()

if __name__ == '__main__':
    main()

