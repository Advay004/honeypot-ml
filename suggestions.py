# suggestions.py

SUGGESTIONS = {
    "malware_download": {
        "summary": "Attacker attempted to fetch and execute remote payload(s).",
        "severity": 8,
        "recommendations": [
            "Block outgoing HTTP(S) to known malicious domains or apply egress filtering.",
            "Scan the filesystem for newly downloaded files and quarantine them.",
            "Harden execution permissions (use AppArmor/SELinux) and disallow execution from /tmp.",
            "Check process list and network connections for suspicious processes."
        ]
    },
    "reverse_shell": {
        "summary": "Attacker attempted to establish a reverse shell connection to an external host.",
        "severity": 9,
        "recommendations": [
            "Block outbound connections on uncommon ports.",
            "Monitor for reverse-shell patterns (nc -e, python sockets, bash -i >& /dev/tcp).",
            "Capture memory/process for forensic analysis.",
            "Isolate the host from network and rotate credentials if persistence suspected."
        ]
    },
    "reconnaissance": {
        "summary": "Attacker enumerated local files and system info (reconnaissance).",
        "severity": 4,
        "recommendations": [
            "Restrict reading of sensitive files to privileged users.",
            "Log and alert on attempts to read /etc/passwd, /etc/shadow, or system files.",
            "Harden service banners and remove unnecessary tools from exposed hosts."
        ]
    },
    "brute_force": {
        "summary": "Brute-force / credential guessing attempt.",
        "severity": 6,
        "recommendations": [
            "Block IPs with repeated authentication failures.",
            "Rate-limit login attempts and enable account lockout.",
            "Use multi-factor authentication where possible."
        ]
    },
    "credential_harvest": {
        "summary": "Attempt to access or read credential stores (/etc/shadow, config files).",
        "severity": 9,
        "recommendations": [
            "Rotate sensitive credentials and inspect logs for exfiltration.",
            "Ensure credential files are properly permissioned.",
            "Alert and isolate host for forensic capture."
        ]
    },
    "enumeration": {
        "summary": "System/file/service enumeration.",
        "severity": 5,
        "recommendations": [
            "Monitor unusual listing/scanning commands.",
            "Harden exposed services, remove unnecessary files/tooling.",
            "Detect automation patterns (fast repeated commands)."
        ]
    },
    "persistence_or_filesystem": {
        "summary": "Commands indicate attempts to create/modify filesystem for persistence.",
        "severity": 7,
        "recommendations": [
            "Detect and block suspicious cron entries or startup modifications.",
            "Alert on changes to system-wide startup scripts and monitor /etc/cron*.",
            "Audit file integrity (tripwire/OSSEC) to detect persistence artifacts."
        ]
    },
    "unknown": {
        "summary": "Unrecognized or ambiguous command sequence.",
        "severity": 3,
        "recommendations": [
            "Collect more context (process list, network connections) and re-analyze.",
            "Add rules or labeled examples for the new pattern."
        ]
    }
}

def get_suggestion(label):
    return SUGGESTIONS.get(label, SUGGESTIONS['unknown'])
