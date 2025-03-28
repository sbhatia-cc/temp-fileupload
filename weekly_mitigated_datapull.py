import requests
import json
import pandas as pd
import urllib3
import time
import csv
from collections import defaultdict
from datetime import datetime, timedelta
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# Define the base URL and endpoint
API_URL = "https://fortytwo.corp.costco.com/rest"
ACCESS_KEY = '' #Insert your access key
SECRET_KEY = '' #Insert your secret key
TAG_EXT = "/asset/tag"
ASSET_EXT = "/asset"
VULN_EXT = "/analysis"
chunks = 50000
csv_filename = f"14days_Mitigated_vulns_{datetime.now().strftime('%Y%m%d')}.csv"
output_csv = f"Deduped_14days_Mitigated_vuln_{datetime.now().strftime('%Y%m%d')}.csv"

cur_date = datetime.now().strftime('%m/%d/%Y')

csv_headers = [
                    "Plugin ID", "Plugin Name", "Plugin Family", "Severity", "IP Address", "Operating System", "OS Category", "Protocol",
                    "Port", "Exploit Available", "Repository Name", "Repository Id", "MAC Address", "NetBIOS", "dnsname", "Hostname", "First Seen", "Last Seen", "Mitigated",
                    "CVE", "CVSS Vector", "CVSS Base Score", "VPR Score", "VPR Context", "Synopsis", "See Also", 
                    "CPE", "Exploit Ease", "Exploit Framework", "Check Type", "Plugin Output", "Plugin Info", "Plugin Publish Date",
                    "Vuln Publish Date", "Patch Publish Date", "Solution", "Age", "Age Group", "Age Group Sort", "Region", "Severity Rank",
                    "uid", "current_date", "vuln state", "SLA"
                ]
# Define the headers, including the authorization token
HEADERS = {
    "accept": "application/json",
    'x-apikey': f'accesskey={ACCESS_KEY}; secretkey={SECRET_KEY}'
}

def determine_region(repo_name):
    if repo_name:
        if any(substr in repo_name for substr in [
             "Azure NP_R", "Azure Prod_R", "DMZ_R", "DomainControllers_R", "Ecom_R", "SWIFT PCI_R",
             "Fuel Lab_R", "IDC and Home Office_R", "Moneris PCI Non Credentialed_R", "Moneris PCI_R", 
             "MOTO PCI - Non Credential_R", "MOTO PCI_R", "SIP - Global Ecomm_R", "TracyMeat_R", "Travel_R", 
             "US_FPM_PCI_R", "US_FPM_R", "US_HA_R", "US_OPT_R", "US_RX_R", "US_Warehouses_R", "WDC_R", "Citrix_R" ]
             ):
            return "United States"
        elif any(substr in repo_name for substr in [ 
            "CA Warehouses_R", "CA  Warehouses_R", "CA_FPM_PCI_R", "CA_FPM_R", "CA_HA_R", "CA_OPT_R", "CA_RX_R", "Canada PCI_R", "Canada_R" ]
            ):
            return "Canada"
        elif any(substr in repo_name for substr in [
            "Mexico PCI_R", "Mexico_R"]
            ): 
            return "Mexico"
        elif any(substr in repo_name for substr in [ 
            "AU_R", "Australia NP_R", "Australia PCI_R", "China_R", "France PCI_R", "France_R", "Iceland PCI_R", 
            "Iceland_R", "Japan PCI_R", "Japan_R", "Korea PCI_R", "Korea_R", "Spain PCI_R", "Spain_R", "Sweden PCI_R", 
            "Sweden_R", "Taiwan PCI_R", "Taiwan_R", "UK PCI_R", "UK_R" ]
                 ): 
            return "International"
    return "Other"

def cal_age(first_seen_date, last_seen_date):
    if first_seen_date and last_seen_date:
        first_seen = datetime.strptime(first_seen_date, '%Y-%m-%d')
        last_seen = datetime.strptime(last_seen_date, '%Y-%m-%d')
        sla_days = (last_seen - first_seen).days
        return sla_days
    
#Convert Unix datestamp to YYYYMMDD
def covert_time(timestamp):
    if timestamp and timestamp != "-1":
        return datetime.utcfromtimestamp(int(timestamp)).strftime('%Y-%m-%d')
        #return datetime.fromtimestamp(int(timestamp)).strftime('%Y%m%d')

def get_sla(severity, first_seen_date, last_seen_date):
    if first_seen_date and last_seen_date:
        first_seen = datetime.strptime(first_seen_date, '%Y-%m-%d')
        last_seen = datetime.strptime(last_seen_date, '%Y-%m-%d')
        sla_days = (last_seen - first_seen).days
        if severity.lower() == "critical" or severity.lower() == "high":
            threshold = 30
        elif severity.lower() == "medium":
            threshold = 60
        elif severity.lower() == "low":
            threshold = 90
        else:
            return "Unknown"
        
        return "Within SLA" if sla_days <= threshold else "Exceeded SLA"
    return ""

def sevrank(sev):
    if sev == "Critical":
        return 4
    elif sev == "High":
        return 3
    elif sev == "Medium":
        return 2
    elif sev == "Low":
        return 1
    else:
        return 0

def group_age(age):
    if age <= 30:
        return "0-30 days", "1"
    elif age <= 90:
        return "30-90 days", "2"
    elif age <= 180:
        return "90-180 days", "3"
    else:
        return "180+ days", "4"

def trun(text, max_length=30000):
    if text and len(text) > max_length:
        return text[:max_length]
    return text

def extract_host_name(dnsname,netbios):
  if dnsname:
    return dnsname.split('.')[0]
  elif netbios:
      return netbios.split("\\", 1)[-1]
  return ""

def extract_os_name(operatingSystem):
    if operatingSystem:
        os_lower = operatingSystem.lower()
        if "windows server" in os_lower:
            return "Windows Server"
        elif "windows" in os_lower:
            return "Windows OS"
        elif "linux" in os_lower or "aix" in os_lower:
            return "Unix"
    return "Others"

def dedupe():
    uid_map = defaultdict(lambda: {"Age": float('inf'), "row": None})
    with open(csv_filename, mode='r', encoding='utf-8') as infile:
        reader = csv.DictReader(infile)
        for row in reader:
            uid1 = row["uid"].lower()
            age = int(row["Age"]) if row["Age"].isdigit() else float('inf')
            if age < uid_map[uid1]["Age"]:
                uid_map[uid1] = {"Age": age, "row": row}

    with open(output_csv, mode='w', newline='', encoding='utf-8') as outfile:
        fieldnames = reader.fieldnames
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()
        for record in uid_map.values():
            writer.writerow(record["row"])

def get_all_vuln():
    with open(csv_filename, mode = "w", newline='', encoding='utf-8') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=csv_headers)
        writer.writeheader()

        startoffset = 0
        total_count = 1
        print(total_count)
        if total_count is not None:
            endoffset = startoffset + chunks
        while startoffset < total_count:
            print("---------In while---------------")
            print(startoffset)
            print(endoffset)
            payload = json.dumps({
                "type": "vuln",
                "sourceType": "patched",
                "query": 
                {
                    "tool": "vulndetails",
                    "type": "vuln",
                    "filters": [
                        {
                        "filterName": "severity", #Change severity value to 3 for high, 2 for medium, 1 for low, 0 for informational
                        "operator": "=",
                        "value": "4,3,2,1"
                    },
                    {
                        "filterName": "lastSeen",
                        "operator": "=",
                        "value": "0:45"
                    }
                    ]
                },
                "sortDir": "DESC",
                "sortField":"severity",
                "startOffset": startoffset,
                "endOffset": endoffset
            })
            response = requests.post(f"{API_URL}/analysis", headers=HEADERS, data=payload, verify=False)
            if response.status_code == 200:
                da = response.json().get('response')
                total_count = int(da.get('totalRecords',0))
                print(f'Total Vulnerability records found: {total_count}')
                data = da.get('results')
                #print(data)
                #print(data.get('pluginID'))
                if data:
                    for item in data:
                        first_seen = covert_time(item.get('firstSeen', ''))
                        last_seen = covert_time(item.get('lastSeen', ''))
                        age = cal_age(first_seen, last_seen)
                        age_group,age_sort = group_age(age)
                        severity = item.get('severity', {}).get('name','')
                        plugin_output = item.get('pluginText', '')
                        sev_rank = sevrank(severity)
                        out = trun(plugin_output)

                        sea = item.get('seeAlso', '')
                        sea_out = trun(sea)

                        repo_name = item.get('repository', {}).get('name','')
                        region = determine_region(repo_name)

                        plugin_id = item.get('pluginID', '')
                        ip = item.get('ip', '')
                        protocol = item.get('protocol', '')
                        port = item.get('port', '')
                        netbios = item.get('netbiosName', '')
                        dnsname = item.get('dnsName', '')
                        hostname = extract_host_name(dnsname,netbios)
                        uid = f"{plugin_id}_{ip}_{protocol}_{port}_{hostname}"

                        os = item.get('operatingSystem', '')
                        osname = extract_os_name(os)


                        sla_date1 = get_sla(severity, first_seen, last_seen)
                        row = {
                            "Plugin ID": item.get('pluginID', ''),
                            "Plugin Name": item.get('pluginName', ''),
                            "Plugin Family": item.get('family', {}).get('name',''),
                            "Severity": item.get('severity', {}).get('name',''),
                            "IP Address": item.get('ip', ''),
                            "Operating System": os,
                            "OS Category": osname,
                            "Protocol": item.get('protocol', ''),
                            "Port": item.get('port', ''),
                            "Exploit Available": item.get('exploitAvailable', ''),
                            "Repository Name": item.get('repository', {}).get('name',''),
                            "Repository Id": item.get('repository', {}).get('id',''),
                            "MAC Address": item.get('macAddress', ''),
                            "NetBIOS": item.get('netbiosName', ''),
                            "dnsname": item.get('dnsName', ''),
                            "Hostname": hostname,
                            "First Seen": covert_time(item.get('firstSeen', '')),
                            "Last Seen": covert_time(item.get('lastSeen', '')),
                            "Mitigated": item.get('hasBeenMitigated', ''),
                            "CVE": item.get('cve', ''),
                            "CVSS Vector": item.get('cvssV3Vector', ''),
                            "CVSS Base Score": item.get('cvssV3BaseScore', ''),
                            "VPR Score": item.get('vprScore', ''),
                            "VPR Context": item.get('vprContext', ''),
                            "Synopsis": item.get('synopsis', ''),
                            "See Also": sea_out,
                            "CPE": item.get('cpe', ''),
                            "Exploit Ease": item.get('exploitEase', ''),
                            "Exploit Framework": item.get('exploitFrameworks', ''),
                            "Check Type": item.get('checkType', ''),
                            "Plugin Output": out,
                            "Plugin Info": item.get('pluginInfo', ''),
                            "Plugin Publish Date": covert_time(item.get('pluginPubDate', '')),
                            "Vuln Publish Date": covert_time(item.get('vulnPubDate', '')),
                            "Patch Publish Date": covert_time(item.get('patchPubDate', '')),
                            "Solution": item.get('solution', ''),
                            "Age": age,
                            "Age Group": age_group, 
                            "Age Group Sort": age_sort,
                            "Region": region,
                            "Severity Rank": sev_rank,
                            "uid": uid,
                            "current_date": cur_date,
                            "vuln state": "Fixed",
                            "SLA": sla_date1
                        }
                        writer.writerow(row)
                print(f'Start offset = {startoffset}')
                print(f'End offset = {startoffset+chunks}')

            else:
                print("Failed to retreive Vuln Details")
                break

            startoffset += chunks
            if total_count is not None:
                endoffset = min(startoffset+chunks, total_count)
            print("----Before sleep----")
            print(startoffset)
            print(endoffset)
            time.sleep(0.1)
            print("----After sleep----")
                    

def main():
    vuln_data = get_all_vuln()
    dedupe()

if __name__ == "__main__":
    main()
