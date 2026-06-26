import paramiko

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

try:
    client.connect(
        "127.0.0.1",
        port=2222,
        username="admin",
        password="password123",
        timeout=5,
    )
except paramiko.AuthenticationException:
    print("Login rejected (correct — honeypot working)")
except Exception as e:
    print(f"Error: {e}")
finally:
    client.close()
