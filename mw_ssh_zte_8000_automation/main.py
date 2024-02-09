import requests
import time
import hashlib
import csv 
import json 
import pandas as pd
from io import StringIO
def md5_encode(input_string):
    md5_hash = hashlib.md5()
    md5_hash.update(input_string.encode('utf-8'))
    return md5_hash.hexdigest()

def make_get_request(url, headers):
    return requests.get(url, headers=headers,timeout=3)

def make_post_request(url, headers, data, cookies=None, params=None):
    return requests.post(url, headers=headers, data=data, cookies=cookies, params=params,timeout=3)

def clean_value(value):
    # Replace unwanted characters with an empty string
    cleaned_value = value.replace('ï»¿', '').strip()
    return cleaned_value

with open('accounts.json') as accounts_file:
    accounts_data = json.load(accounts_file)

with open('template.csv') as csv_file:
    csv_reader = csv.DictReader(csv_file)
    dfs = []
    for row in csv_reader:
        host = row['IP Address']
        ne_name = row['ï»¿Name'] 
        type_router = row['Type']
        source_node = row['Source Node']
        target_node = row['Target Node']
        parent_node = row['Parent Node']
        print(host)
        for account in accounts_data:
            try:
                user = account['username']
                password = md5_encode(account['password'])

                # 1. Obtain SESSIONID
                url_login = rf"http://{host}/webs/zte/logon.asp"
                headers_login = { 
                    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "accept-language": "en,id;q=0.9,zh-CN;q=0.8,zh;q=0.7,en-US;q=0.6",
                    "cache-control": "max-age=0",
                    "proxy-connection": "keep-alive",
                    "upgrade-insecure-requests": "1",
                }

                response_login = make_get_request(url_login, headers_login)

                cookies = response_login.cookies
                session_id = cookies.get("SESSIONID")
                csrf = cookies.get("csrftoken")

                # 2. Perform login
                url_post = rf"http://{host}/goform/formLogon?timeStamp={int(time.time() * 1000)}"
                headers_post = {
                    "accept": "*/*",
                    "accept-language": "en",
                    "content-type": "application/x-www-form-urlencoded",
                    "proxy-connection": "keep-alive",
                    "x-requested-with": "XMLHttpRequest",
                    "referrer": rf"http://{host}/webs/zte/logon.asp",
                    "referrerPolicy": "strict-origin-when-cross-origin",
                }
                body_post = f'username={user}&password={password}&SESSIONID={session_id}&csrftoken={csrf}'

                response_post = make_post_request(url_post, headers_post, body_post, cookies=cookies)

                # 3. Query data
                current_timestamp = int(time.time() * 1000)
                url_query = rf"http://{host}/goform/Lmp_QueryAll?timeStamp={current_timestamp}"
                headers_query = {
                    "accept": "*/*",
                    "accept-language": "en,id;q=0.9,zh-CN;q=0.8,zh;q=0.7,en-US;q=0.6",
                    "content-type": "application/x-www-form-urlencoded",
                    "proxy-connection": "keep-alive",
                    "x-requested-with": "XMLHttpRequest",
                }
                referrer_query = rf"http://{host}/webs/zte/macQuery.asp"
                body_query = f"action=MacTableQuery&SESSIONID={session_id}"

                response_query = make_post_request(url_query, headers_query, body_query, params={"referrer": referrer_query}, cookies=cookies)
                json_data = response_query.json()
                filename_query = json_data.get('fileName')

                # 4. Update data
                url_update = rf"http://{host}/goform/Lmp_UpdateAll"
                headers_update = {
                    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                    "accept-language": "en,id;q=0.9,zh-CN;q=0.8,zh;q=0.7,en-US;q=0.6",
                    "cache-control": "max-age=0",
                    "content-type": "application/x-www-form-urlencoded",
                    "proxy-connection": "keep-alive",
                    "upgrade-insecure-requests": "1",
                }
                referrer_update = rf"http://{host}/webs/zte/macQuery.asp"
                body_update = f"action=lmtDownloadFile&contentType=allBbx&fileName={filename_query}&fileType=application%2Fms-excel&SESSIONID={session_id}"

                response_update = make_post_request(url_update, headers_update, body_update, cookies=cookies)
                output = response_update.text.replace("\u0027", "").rstrip(',')

                if 'errorCode' in output:
                    print('WRONG USERNAME OR PASSWORD')
                else:
                    df = pd.read_csv(StringIO(output.replace("Index","Trash")))
                    df = df.drop(columns=["Trash"])
                    
                    df.insert(0, 'Parent Node', parent_node)
                    df.insert(0, 'Target Node', target_node)
                    df.insert(0, 'Source Node', source_node)
                    df.insert(0, 'Router Type', type_router)
                    df.insert(0, 'NE Name', ne_name)
                    df.insert(0, 'IP Address', host)
                    dfs.append(df)
                    print(df)
            except pd.errors.EmptyDataError:
                columns = [ 'NE', 'MAC', 'VLAN ID', 'Port', 'Type', 'Port Description']
                empty_df = pd.DataFrame(columns=columns)
                empty_df['NE'] = "NON GNE"
                empty_df['MAC'] = "NON GNE"
                empty_df['VLAN ID'] = "NON GNE"
                empty_df['Port'] = "NON GNE"
                empty_df['Type'] = "NON GNE"
                empty_df['Port Description'] = "NON GNE"
                empty_df.insert(0, 'Parent Node', parent_node)
                empty_df.insert(0, 'Target Node', target_node)
                empty_df.insert(0, 'Source Node', source_node)
                empty_df.insert(0, 'Router Type', type_router)
                empty_df.insert(0, 'NE Name', ne_name)
                empty_df.insert(0, 'IP Address', host)
                dfs.append(df)

                print("Yikes! No column to parse from the file.")
            except Exception as e:
                print(e)
    result_df = pd.concat(dfs, ignore_index=True)
    result_df.to_csv('test.csv',index=False)