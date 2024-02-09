import concurrent.futures
import paramiko
import openpyxl
import json
import logging
import time
import csv
import datetime
import re

# Configure logging
logging.basicConfig(filename='output.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def read_account_json(file_path):
    with open(file_path, 'r') as json_file:
        return json.load(json_file)

def read_excel(file_path):
    wb = openpyxl.load_workbook(file_path)
    sheet = wb.active
    return sheet

def ssh_connection(username, password, host):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username=username, password=password)
    return client

def execute_command(ssh_client, command):
    try:
        connection = ssh_client.invoke_shell()
        connection.send(command + '\n')
        timeout = 5
        max_wait_time = 60  # Maximum wait time for command execution (adjust as needed)
        start_time = time.time()
        result = b""

        while time.time() - start_time < max_wait_time:
            if connection.recv_ready():
                result += connection.recv(4096)
            else:
                time.sleep(timeout)

        logging.info(f"Command: {command}\nResult:\n{result.decode('utf-8')}")
        return result.decode('utf-8')

    except Exception as e:
        logging.error(f"Error executing command: {command}\n{str(e)}")
        raise e

def process_row(row, account_data, output_file):
    ip_address = row[4]
    router_type = row[2]
    ne_name = row[0]
    ne_id = row[1]
    parent_node = row[7]
    for acc in account_data:
        user = acc['username']
        passwd = acc['password']
        types = acc['type']
        
        for t in types:
            if t in router_type:
                try:
                    ssh_client = ssh_connection(acc['username'], acc['password'], row[4])
                    command_result = execute_command(ssh_client, 'show arp')
                    print(command_result)
                    pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)')
                    matches = pattern.findall(command_result)
                    print(matches)
                    
                    if matches:
                        with open(output_file, mode='a', newline='', encoding='utf-8') as csvfile:
                            fieldnames = ["NE Name","NE Id","Parent Node","IP Address", "Router Type", "Local IP Address", "Age", "Interface", "External VLAN ID", "Internal VLAN ID", "Sub Interface"]
                            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                            
                            for match in matches:
                                local_ip_address, age, mac_address, interface, exter_vlan_id, inter_vlan_id, sub_interface = match
                                if 'through' not in match and 'authentication' not in match: 
                                    writer.writerow({
                                        "NE Name" : ne_name,
                                        "NE Id" : ne_id,
                                        "Parent Node": parent_node,
                                        "IP Address": ip_address,
                                        "Router Type": router_type,
                                        "Local IP Address": local_ip_address,
                                        "Age": age,
                                        "Interface": interface,
                                        "External VLAN ID": exter_vlan_id,
                                        "Internal VLAN ID": inter_vlan_id,
                                        "Sub Interface": sub_interface
                                    })
                    
                    ssh_client.close()
                except Exception as e:
                    with open(output_file, mode='a', newline='', encoding='utf-8') as csvfile:
                        fieldnames = ["IP Address", "Router Type", "Local IP Address", "Age", "Interface", "External VLAN ID", "Internal VLAN ID", "Sub Interface"]
                        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                        writer.writerow({
                            "NE Name" : ne_name,
                            "NE Id" : ne_id,
                            "Parent Node": parent_node,
                            "IP Address": ip_address,
                            "Router Type": router_type,
                            "Local IP Address": e,
                            "Age": e,
                            "Interface": e,
                            "External VLAN ID": e,
                            "Internal VLAN ID": e,
                            "Sub Interface": e
                        })
                    
                    print(f"Error connecting to {row[4]}: {e}")
                    logging.error(f"Error connecting to {row[4]}: {e}")
                
                print(ip_address, user, passwd)

def main():
    now = datetime.datetime.now().strftime("%Y%m%d")
    csv_file = "template.csv"
    output_file = rf"output_{now}.csv"
    
    with open(output_file, mode='w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ["IP Address", "Router Type", "Local IP Address", "Age", "Interface", "External VLAN ID", "Internal VLAN ID", "Sub Interface"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
    account_data = read_account_json('accounts.json')
    excel_data = read_excel('template.xlsx')
    
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(process_row, row, account_data, output_file) for row in excel_data.iter_rows(min_row=2, values_only=True)]
        concurrent.futures.wait(futures)
    
if __name__ == "__main__":
    main()
