import os

def configure_nxlog(server_ip):
    # Ruta del archivo de configuración de NXLog
    config_file = "C:/Program Files/nxlog/conf/nxlog.conf"
    
    # Leer el archivo de configuración
    with open(config_file, 'r') as file:
        config = file.readlines()
    
    # Modificar la línea donde se define la IP del servidor syslog
    for i, line in enumerate(config):
        if "SyslogHost" in line:
            config[i] = f"SyslogHost {server_ip}\n"
    
    # Guardar el archivo actualizado
    with open(config_file, 'w') as file:
        file.writelines(config)

    print("NXLog configurado correctamente.")
