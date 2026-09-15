"""
myNmap.py
Program Description: Project #1: Creating a custom TCP port scanner without the usage of the nmap library.
Program Usage: python3 myNmap.py <target_ip_address>

Group Members: Ian Holbrook & Cole Faulk
Date: 9/15/2026
Course: Computer Security (CSCI 3250)
"""

#instead of using the nmap library, we can use Python's built-in library "socket" to help us create a TCP port scanner.
import socket



def scan_port(ip_address, port, timeout=1):
    """
    This function will scan a specific TCP port on the target IP address.

    Args:
        ip_address (str): The target IP address.
        port (int): The TCP port to scan.
        timeout (int, optional): Timeout in seconds for the connection attempt. Defaults to 1.

    Returns:
        bool: True if the port is open, False otherwise.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip_address, port))

            # Return True if the port is open (result is 0)
            return result == 0 
    except socket.error:
        return False



def scan_ports(ip_address, start_port=1, end_port=1024, timeout=1):
    """
    This function scans a range of TCP ports on the target IP address.

    Args:
        ip_address (str): The target IP address.
        start_port (int, optional): The starting port number. Defaults to 1.
        end_port (int, optional): The ending port number. Defaults to 1024.
        timeout (int, optional): Timeout in seconds for each connection attempt. Defaults to 1.

    Returns:
        list: A list of open ports.
    """
    open_ports = []
    for port in range(start_port, end_port + 1):
        if scan_port(ip_address, port, timeout):
            open_ports.append(port)
    return open_ports

#def main():
    #output the TCP open ports on the target

    #catch any errors. ex, no inputting the ip address of the target and inputting an non-reachable ip
