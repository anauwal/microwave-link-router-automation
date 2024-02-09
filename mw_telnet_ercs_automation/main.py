import subprocess
import telnetlib
import csv
import re
import datetime
import json
import logging
import concurrent.futures

# Configure logging
logging.basicConfig(filename='run.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def ping_ip(ip):
    try:
        output = subprocess.check_output(["ping", ip], stderr=subprocess.STDOUT, text=True)
        if "expired in transit" in output.lower():
            return False
        return True
    except subprocess.CalledProcessError:
        return False

def telnet_login(ip, username, password):
    try:
        tn = telnetlib.Telnet(ip, timeout=10, port=23)
        if b"User:" in tn.read_until(b"Password:", timeout=10):
            tn.write(username.encode('utf-8') + b"\n")
        else:
            tn.write(password.encode('utf-8') + b"\n")
        tn.read_until(b">", timeout=10)
        return tn
    except Exception as e:
        logging.error(f"Telnet login error for {ip}: {e}")
    return None

def execute_command(tn, command):
    tn.write(command.encode('utf-8') + b"\n")
    result = tn.read_until(b">", timeout=10).decode('utf-8')
    return result

def clean_keys(dictionary):
    return {key.lstrip('\ufeff'): value for key, value in dictionary.items()}

def process_ip(row, credentials, output_file):
    row = clean_keys(row)
    ip = row["IPv4"]
    ne_name = row["Network Element"]
    ne_state = row["NE State"]
    ne_type = row["NE Type"]

    if ping_ip(ip):
        logging.info(f"{ip} REACHABLE!")
        result_store = []
        sumthin_wrong = True
        for credential in credentials:
            logging.info(f"Trying {credential} {ip}")
            tn = telnet_login(ip, credential["username"], credential["password"])
            if tn:
                result = execute_command(tn, "show mac-address-table full")
                result = execute_command(tn, "show mac-address-table full")
                result_store.append(result)
                tn.close()
            else:
                logging.warning(f"Wrong credential {ip}")
                tn.close()

        result_store = ' '.join(result_store)
        pattern = re.compile(r'\s*(\d+)\s+([0-9a-f:]+)\s+([\w-]+)\s+(\d+)\s+([\w\s-]+\d+/\d+/\d+)\s*')
        #pattern = re.compile(r'\b\d+\s+([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\s+(\w+)\s+(\d+)\s+(\S+)\s+(\S+)\b')
        matches = pattern.findall(result_store)
        logging.info(f"RESULT {ip}: {result_store}")
        if matches :
            sumthin_wrong = False
            with open(output_file, mode='a', newline='', encoding='utf-8') as csvfile:
                fieldnames = ["Network Element", "IPv4", "NE State", "NE Type", "VLAN", "MAC Address", "Status", "Port",
                              "Interface"]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

                for match in matches:
                    vlan, mac, status, port, interface = match
                    
                    writer.writerow({
                        "Network Element": ne_name,
                        "IPv4": ip,
                        "NE State": ne_state,
                        "NE Type": ne_type,
                        "VLAN": vlan,
                        "MAC Address": mac,
                        "Status": status,
                        "Port": port,
                        "Interface": interface
                    })
        if "The new password must contain" in result_store and sumthin_wrong:
            logging.error(f"ASKING NEW PASSWORD FROM DEFAULT {ip}")
            with open(output_file, mode='a', newline='', encoding='utf-8') as csvfile:
                fieldnames = ["Network Element", "IPv4", "NE State", "NE Type", "VLAN", "MAC Address", "Status", "Port",
                              "Interface"]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writerow({
                    "Network Element": ne_name,
                    "IPv4": ip,
                    "NE State": ne_state,
                    "NE Type": ne_type,
                    "VLAN": "ASKING NEW PASSWORD FROM DEFAULT",
                    "MAC Address": "ASKING NEW PASSWORD FROM DEFAULT",
                    "Status": "ASKING NEW PASSWORD FROM DEFAULT",
                    "Port": "ASKING NEW PASSWORD FROM DEFAULT",
                    "Interface": "ASKING NEW PASSWORD FROM DEFAULT"
                })
        elif "VLAN" in result_store and sumthin_wrong:
            logging.error(f"NON GNE {ip}")
            with open(output_file, mode='a', newline='', encoding='utf-8') as csvfile:
                fieldnames = ["Network Element", "IPv4", "NE State", "NE Type", "VLAN", "MAC Address", "Status", "Port",
                              "Interface"]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writerow({
                    "Network Element": ne_name,
                    "IPv4": ip,
                    "NE State": ne_state,
                    "NE Type": ne_type,
                    "VLAN": "NON GNE",
                    "MAC Address": "NON GNE",
                    "Status": "NON GNE",
                    "Port": "NON GNE",
                    "Interface": "NON GNE"
                })
        elif sumthin_wrong:
            logging.error(f"SOMETHING IS WRONG, PLEASE MANUAL CHECK {ip}")
            with open(output_file, mode='a', newline='', encoding='utf-8') as csvfile:
                fieldnames = ["Network Element", "IPv4", "NE State", "NE Type", "VLAN", "MAC Address", "Status", "Port",
                              "Interface"]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writerow({
                    "Network Element": ne_name,
                    "IPv4": ip,
                    "NE State": ne_state,
                    "NE Type": ne_type,
                    "VLAN": "PLEASE CHECK MANUALLY, SOMETHING IS WRONG",
                    "MAC Address": "PLEASE CHECK MANUALLY, SOMETHING IS WRONG",
                    "Status": "PLEASE CHECK MANUALLY, SOMETHING IS WRONG",
                    "Port": "PLEASE CHECK MANUALLY, SOMETHING IS WRONG",
                    "Interface": "PLEASE CHECK MANUALLY, SOMETHING IS WRONG"
                })
    else:
        logging.error(f"{ip} UNREACHABLE!")
        with open(output_file, mode='a', newline='', encoding='utf-8') as csvfile:
            fieldnames = ["Network Element", "IPv4", "NE State", "NE Type", "VLAN", "MAC Address", "Status", "Port",
                          "Interface"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writerow({
                "Network Element": ne_name,
                "IPv4": ip,
                "NE State": ne_state,
                "NE Type": ne_type,
                "VLAN": "NOT REACHABLE",
                "MAC Address": "NOT REACHABLE",
                "Status": "NOT REACHABLE",
                "Port": "NOT REACHABLE",
                "Interface": "NOT REACHABLE"
            })

def main():
    now = datetime.datetime.now().strftime("%Y%m%d")
    csv_file = "template.csv"
    output_file = rf"output_{now}.csv"

    with open('accounts.json', 'r') as file:
        credentials = json.load(file)

    with open(output_file, mode='w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ["Network Element", "IPv4", "NE State", "NE Type", "VLAN", "MAC Address", "Status", "Port",
                      "Interface"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

    with open(csv_file, 'r', encoding='utf-8-sig') as csvfile:
        reader = csv.DictReader(csvfile)
        
        with concurrent.futures.ThreadPoolExecutor() as executor:
            # Process each row concurrently
            executor.map(lambda row: process_ip(row, credentials, output_file), reader)

if __name__ == "__main__":
    main()