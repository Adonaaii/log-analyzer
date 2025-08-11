import re
from collections import Counter
def read_logs(file_path):
    with open(file_path, "r") as file:
        print(file.readlines())
def extract_ips(file_path):
    with open(file_path, 'r') as file:
        logs = file.readlines() 
        ip_s = []   
        for line in logs:
             ips = re.findall(r'\d+\.\d+\.\d+\.\d+', line)
             if ips:
                    ip_s.extend(ips)
        ctr = Counter(ip_s)
        print(len(ctr))
        print("All IPs found:", ip_s) 
        print(ctr.most_common(3))
file_path = "/workspaces/log-analyzer/log_analyzer/data/auth.log"
#read_logs(file_path)
extract_ips(file_path)
#extract_ips()


