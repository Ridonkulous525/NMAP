import subprocess
import sys
import tabulate

# Check if python-nmap is installed, if not, install it
try:
    import nmap
except ImportError:
    print("python-nmap is not installed. Installing...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "python-nmap"])
    import nmap

# Check if tabulate is installed, if not, install it
try:
    import tabulate
except ImportError:
    print("Tabulate is not installed. Installing...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "tabulate"])
    import tabulate

def scan_router(ip_address):
    # Specify the path to the nmap executable
    nm = nmap.PortScanner(nmap_search_path=['/usr/local/bin/nmap'])
    
    nm.scan(hosts=ip_address, arguments='-T4 -A -v')  # You can adjust scan arguments as needed

    # List to store vulnerability information
    vulnerabilities = []

    # Iterate through scan results
    for host in nm.all_hosts():
        # Iterate through open ports
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                # Check for vulnerability information
                if 'script' in nm[host][proto][port]:
                    scripts = nm[host][proto][port]['script']
                    for script in scripts:
                        # Extract vulnerability details
                        if 'id' in script and 'output' in script:
                            vulnerability = {
                                'Host': host,
                                'Port': port,
                                'Protocol': proto,
                                'Vulnerability': script['id'],
                                'Output': script['output']
                            }
                            vulnerabilities.append(vulnerability)

    # Print vulnerabilities table
    print("\nVulnerabilities Summary:")
    if vulnerabilities:
        print(tabulate.tabulate(vulnerabilities, headers="keys"))
        resolve_vulnerabilities(vulnerabilities)
    else:
        print("No vulnerabilities found.")

    # Write vulnerabilities summary to a text file
    write_summary_to_file(vulnerabilities)

def write_summary_to_file(vulnerabilities):
    with open("vulnerabilities_summary.txt", "w") as f:
        f.write("Vulnerabilities Summary:\n")
        if vulnerabilities:
            for vuln in vulnerabilities:
                f.write(f"Host: {vuln['Host']}, Port: {vuln['Port']}, Protocol: {vuln['Protocol']}\n")
                f.write(f"Vulnerability: {vuln['Vulnerability']}\n")
                f.write(f"Output: {vuln['Output']}\n\n")
        else:
            f.write("No vulnerabilities found.")

def resolve_vulnerabilities(vulnerabilities):
    # Example: You can add your resolution steps here based on the vulnerabilities found
    print("\nResolution Steps:")
    for vuln in vulnerabilities:
        print(f"Resolve {vuln['Vulnerability']} on {vuln['Host']}")

    # Instead of Metasploit, you might want to add code here to run other security tools or perform manual resolution steps

# IP Address to scan
router_ip = 'ADD IP ADDRESS HERE'

# Perform the scan
scan_router(router_ip)
