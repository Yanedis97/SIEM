import paramiko
import subprocess

def configure_device(device_type, hostname, username, password, syslog_server_ip):
    try:
        if device_type in ['router', 'switch']:
            configure_router_switch(hostname, username, password, syslog_server_ip)
        elif device_type == 'firewall':
            configure_firewall(hostname, username, password, syslog_server_ip)
        elif device_type == 'linux_server':
            configure_linux_server(hostname, username, password, syslog_server_ip)
        elif device_type == 'windows_server':
            configure_windows_server(syslog_server_ip)
        else:
            print(f"Tipo de dispositivo desconocido: {device_type}")
    except Exception as e:
        print(f"Error al configurar el dispositivo {hostname}: {str(e)}")

def configure_router_switch(hostname, username, password, syslog_server_ip):
    commands = [
        "configure terminal",
        f"logging host {syslog_server_ip}",
        "logging trap informational",
        "exit",
        "write memory"
    ]
    send_commands_via_ssh(hostname, username, password, commands)

def configure_firewall(hostname, username, password, syslog_server_ip):
    commands = [
        "configure terminal",
        f"logging host {syslog_server_ip}",
        "logging trap informational",
        "logging enable",
        "exit",
        "write memory"
    ]
    send_commands_via_ssh(hostname, username, password, commands)

def configure_linux_server(hostname, username, password, syslog_server_ip):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname, username=username, password=password)
    
    command = f"echo '*.* @{syslog_server_ip}:514' | sudo tee -a /etc/rsyslog.conf && sudo systemctl restart rsyslog"
    ssh.exec_command(command)
    ssh.close()
    print(f"Configuración de syslog en el servidor Linux {hostname} completada.")

def configure_windows_server(syslog_server_ip):
    command = f"""
    $nxlog_config = @"
    <Extension _syslog>
        Module      om_udp
        Host        {syslog_server_ip}
        Port        514
    </Extension>
    <Route 1>
        Path        in => _syslog
    </Route>
    "@
    Set-Content -Path "C:\\Program Files (x86)\\nxlog\\conf\\nxlog.conf" -Value $nxlog_config
    Restart-Service -Name nxlog
    """
    subprocess.run(["powershell", "-Command", command], check=True)
    print(f"Configuración de syslog en el servidor Windows completada.")

def send_commands_via_ssh(hostname, username, password, commands):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname, username=username, password=password)
    
    shell = ssh.invoke_shell()
    for command in commands:
        shell.send(command + "\n")
        time.sleep(1)
    
    ssh.close()

if __name__ == "__main__":
    devices = [
        {"device_type": "router", "hostname": "192.168.1.1", "username": "admin", "password": "adminpass"},
        {"device_type": "linux_server", "hostname": "192.168.1.10", "username": "root", "password": "rootpass"}
    ]
    
    syslog_server_ip = "192.168.1.100"
    
    for device in devices:
        configure_device(device["device_type"], device["hostname"], device["username"], device["password"], syslog_server_ip)
