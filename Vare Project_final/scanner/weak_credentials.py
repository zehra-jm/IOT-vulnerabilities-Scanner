import paramiko

# List of default/weak credentials to check
weak_credentials = [
    ("admin", "admin"),
    ("root", "root"),
    ("user", "1234"),
    # Add more if needed
]

def check_ssh_weak_credentials(ip, port=22):
    for username, password in weak_credentials:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip, port=port, username=username, password=password, timeout=3)
            client.close()
            return (True, f"{username}/{password}")  # Weak credential found
        except Exception:
            continue
    return (False, None)
