"""
myNmap.py
Program Description: Project #1: Creating a custom TCP port scanner without the usage of the nmap library.
Program Usage: python3 myNmap.py <target_ip_address>

Group Members: Ian Holbrook & Cole Faulk
Date: 9/15/2026
Course: Computer Security (CSCI 3250)
"""

#using ThreadPoolExecutor allows us to use multithreading to speed up the port scanning process so that we dont have to scan each port one by one
from concurrent.futures import ThreadPoolExecutor, as_completed

#instead of using the nmap library, we can use Python's built-in library "socket" to help us create a TCP port scanner.
import socket

#importing the sys module allows for command line arguments to be to be passed to the python program
import sys

#importing ipaddress module allows for validation of the provided IP address
import ipaddress

#we use the time library to measure the time taken for the scan to complete
import time


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



def scan_ports(ip_address, start_port=1, end_port=3400, timeout=1, max_threads=200):
    """
    This function scans a range of TCP ports on the target IP address.

    Args:
        ip_address (str): The target IP address.
        start_port (int, optional): The starting port number. Defaults to 1.
        end_port (int, optional): The ending port number. Defaults to 1024.
        timeout (int, optional): Timeout in seconds for each connection attempt. Defaults to 1.
        max_threads (int, optional): Maximum number of threads to use for scanning. Defaults to 200.
        
    Returns:
        list: A list of open ports.
    """
    open_ports = []
    ports = range(start_port, end_port + 1)

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_port = {executor.submit(scan_port, ip_address, port, timeout): port for port in ports}

        for future in as_completed(future_to_port):
            port = future_to_port[future]
            
            if future.result():
                open_ports.append(port)
            
    return sorted(open_ports)


def check_ip(ip_address):
    """
    This function checks if the parameter's provided IP address is valid and reachable. 
    Using the ipaddress module's ip_address() function

    Args:
        ip_address (str): The target IP address.

    Returns:
        bool: True if the IP address is valid, False otherwise.    
    """
    try:
        ip_type = ipaddress.ip_address(ip_address)

    except ValueError:
        return False

    #check if the IP address is valid. Also, if it ends with a 0 (not valid)
    if isinstance(ip_type, ipaddress.IPv4Address):
        last_octet = int(ip_address.split('.')[-1])

        if last_octet == 0:
            return False
        
    return True

def main(ip_address):
    """
    The main function first checks if the provided IP address is valid by using the check_ip() function. 
    If the IP address is valid, it will call the scan_ports() function to scan ports 1-3400 on the provided
    IP address. The ports will be displayed along with their service. Lastly, it displayes the time taken for
    the scan to complete

    Args:
        ip_address (str): The target IP address.

    """
    #Check if the given IP address is valid
    if check_ip(ip_address) != True:
        print(f'\n[*] Invalid IP address: {ip_address}')

    else:
        #Show that the scan has started
        print(f'\n[*] Starting scan on host: {ip_address}')
        print(f'[*] Scanning ports 1-3400…\n')

        #Begin the timer for the IP scan
        start_time = time.time() 

        #Use the scan_ports() function to scan ports 1-3400 on the target IP address and store the return list of all open ports in a variable
        port_list = scan_ports(ip_address, 1, 3400)

        #Iterate and display open ports from scan_port()'s return list of all open ports
        for port in port_list:
            try:
                service_name = socket.getservbyport(port)
            except OSError:
                service_name = "Unknown service"
            print(f'[+] Port {port} is open ({service_name})')

        #Display the time taken for the scan
        print(f'\n[*] Scan completed in {time.time() - start_time:.2f} seconds.')  


"""
this statement is vital to the code being runable in terminal. 
It allows the main() function to be called when someone types myNmap.py <target_ip_address> in cmd.
"""
if __name__ == "__main__":
    # in argv: [0 is myNmap.py, 1 is the target IP address]
    main(sys.argv[1])
