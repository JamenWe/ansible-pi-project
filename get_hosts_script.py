import subprocess
import netifaces
import socket
import os

def get_local_subnet():
    # Determine the local subnet by getting details from the network interface
    gateway_interface = netifaces.gateways()['default'][netifaces.AF_INET][1]
    ip_address = netifaces.ifaddresses(gateway_interface)[netifaces.AF_INET][0]['addr']
    netmask = netifaces.ifaddresses(gateway_interface)[netifaces.AF_INET][0]['netmask']
    
    # Calculate the network address using IP and netmask
    network_bits = socket.inet_aton(ip_address)
    netmask_bits = socket.inet_aton(netmask)
    network_address = socket.inet_ntoa(
        bytes(a & b for a, b in zip(network_bits, netmask_bits))
    )

    # Calculate the CIDR prefix length from netmask
    cidr_prefix_len = sum(bin(int(octet)).count('1') for octet in netmask.split('.'))
    
    return f"{network_address}/{cidr_prefix_len}", ip_address

def find_hosts(subnet, exclude_ips):
    print(f"Scanning subnet {subnet} for active hosts...")
    try:
        # Run nmap to find live hosts in the subnet
        result = subprocess.check_output(["nmap", "-sn", subnet], text=True)
        lines = result.split('\n')
        
        hosts = []
        for line in lines:
            if "Nmap scan report for" in line:
                parts = line.split()
                host_info = parts[-1]

            else:
                # Capture IP addresses directly
                ip = host_info.strip('()')
                if ip not in exclude_ips:
                    hosts.append(ip)
                    print(f"Captured IP: {ip}")

        return hosts

    except subprocess.CalledProcessError as e:
        print(f"Error scanning network: {e}")
        return []

def save_to_file(ips, filename):
    print(f"Saving IPs to {filename}...")
    with open(filename, 'w') as file:
        file.write("[hosts]\n")
        for ip in ips:
            file.write(f"itechpi@{ip}\n")

def validate_ansible_inventory(inventory_file):
    print(f"Validating Ansible inventory at {inventory_file}...")
    try:
        result = subprocess.check_output(
            ["ansible-inventory", "--inventory", inventory_file, "--list"],
            text=True
        )
        print("Ansible inventory is valid:")
        print(result)
    except subprocess.CalledProcessError as e:
        print(f"Error validating Ansible inventory: {e}")

def main():
    subnet, local_ip = get_local_subnet()  # Automatically determine the local subnet and local IP
    print(f"Detected subnet: {subnet}")
    
    # Get the gateway IP to exclude
    gateway_ip = netifaces.gateways()['default'][netifaces.AF_INET][0]

    # Exclude client's IP and gateway from the results
    exclude_ips = {local_ip, gateway_ip}
    
    host_entries = find_hosts(subnet, exclude_ips)

    if host_entries:
        # Define the path where the output file will be saved
        output_path = os.path.expanduser("/define/your/path/inventory_new.ini")
        save_to_file(host_entries, output_path)
        
        # Validate and parse the generated Ansible inventory file
        validate_ansible_inventory(output_path)
    else:
        print("No hosts found on the subnet.")

if __name__ == "__main__":
    main()

