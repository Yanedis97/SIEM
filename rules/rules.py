from datetime import datetime, timedelta
from collections import defaultdict
from database.db_connection import SessionLocal
from app.models.alerts import Alerts

# Parámetros de reglas de correlación
TIME_RELATION_THRESHOLD = 5  # en minutos
BRUTE_FORCE_THRESHOLD = 3    # Mínimo de intentos fallidos
MAX_ATTEMPTS = 10            # Máximo de intentos fallidos permitidos
SUSPICIOUS_TRAFFIC_THRESHOLD = 1000  # Umbral de eventos para tráfico sospechoso
SUSPICIOUS_TRAFFIC_THRESHOLD_SMALL = 500  # Umbral reducido para redes pequeñas
TRAFFIC_WINDOW = timedelta(minutes=10)  # Ventana de tiempo de 10 minutos


login_tracker = defaultdict(list)  # Almacena intentos fallidos por IP
event_tracker = defaultdict(list)  # Almacena eventos para correlacionar por IP
traffic_tracker = defaultdict(list) # Almacena eventos por dispositivo (IP de origen o dispositivo)

active_alerts = {}  # Almacena alertas activas para evitar duplicación

def clean_old_entries(ip, interval):
    """
    Limpia entradas antiguas de intentos fallidos para una IP.
    """
    current_time = datetime.now()
    login_tracker[ip] = [
        t for t in login_tracker[ip] 
        if current_time - t <= timedelta(minutes=interval)
    ]
    event_tracker[ip] = [
        t for t in event_tracker[ip]
        if current_time - t <= timedelta(minutes=TIME_RELATION_THRESHOLD)
    ]

def is_alert_active(alert_id):
    """
    Verifica si una alerta con este ID ya está activa.
    """
    return alert_id in active_alerts

def activate_alert(alert_id: str, message: str, context: dict = {}):
    """
    Activa una alerta y la guarda en el almacén temporal.
    """
    active_alerts[alert_id] = datetime.now()

    print(f"Alerta generada: {message}")

    session = SessionLocal()
    try:
        
        alert_data = Alerts(
            second_id = alert_id,
            log_ids = str(context.get("log_ids",None)),  
            alert_type = 1,  
            message = message,
            source_ip = context.get("source_ip",None),  
            dest_ip = context.get("source_ip",None),
            severity = 1,  
            context = context,
            status = 1,
            created_at = datetime.now()
        )

        session.add(alert_data)
        session.commit()
    except Exception as e:
        session.rollback()  # Si ocurre un error, revertir los cambios
        print(f"Error al guardar la alerta: {e}")
    finally:
        session.close()
        

def check_brute_force(logs):
    """
    Detecta ataques de fuerza bruta basados en intentos fallidos en los logs de autenticación.
    Args:
        logs: Logs extraídos de Elasticsearch
        es_client: Cliente Elasticsearch
    """
    for log in logs:
        timestamp = log["_source"].get("timestamp")
        src_ip = log["_source"].get("src_ip")
        msg = log["_source"].get("msg", "")
        
        if "authentication failed" in msg.lower():  
            log_time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
            login_tracker[src_ip].append(log_time)

    for ip, timestamps in login_tracker.items():
        clean_old_entries(ip, TIME_RELATION_THRESHOLD)

        if len(timestamps) >= BRUTE_FORCE_THRESHOLD:
            if len(timestamps) <= MAX_ATTEMPTS:
                alert_id = f"brute_force_{ip}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
                message = f"Posible ataque de fuerza bruta detectado desde la IP {ip}. {len(timestamps)} intentos fallidos en los últimos {TIME_RELATION_THRESHOLD} minutos."
                context = {
                    "log_ids": [log["_id"] for log in logs], 
                    "source_ip": ip, 
                    "event_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
                activate_alert(alert_id, message, context)


def check_privilege_change(logs):
    """
    Detecta cambios de privilegios en los logs.
    Args:
        logs: Logs extraídos de Elasticsearch.
    """
    for log in logs:
        timestamp = log["_source"].get("timestamp")
        msg = log["_source"].get("msg", "")
        
        if "privilege change" in msg.lower(): 
            log_time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
            
            alert_id = f"privilege_change_{log['_id']}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            message = f"Cambio de privilegio detectado: {msg}. Log ID: {log['_id']}"
            context = {
                "log_ids": [log["_id"]],
                "event_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "msg": msg
            }
            activate_alert(alert_id, message, context)


def check_suspicious_traffic(logs):
    """
    Detecta tráfico anómalo en base a un umbral de eventos en una ventana de tiempo.
    Args:
        logs: Logs extraídos de Elasticsearch
        es_client: Cliente Elasticsearch
    """
    for log in logs:
        timestamp = log["_source"].get("timestamp")
        src_ip = log["_source"].get("src_ip")
        msg = log["_source"].get("msg", "")
        
        # Solo consideramos logs de dispositivos relevantes (Firewalls, routers)
        if "firewall" in msg.lower() or "router" in msg.lower():
            log_time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
            traffic_tracker[src_ip].append(log_time)

    # Limpiar entradas antiguas (en base a la ventana de 10 minutos)
    for device_ip, timestamps in traffic_tracker.items():
        clean_old_entries(device_ip, TRAFFIC_WINDOW)

        # Verificar si el número de eventos supera el umbral
        if len(timestamps) >= SUSPICIOUS_TRAFFIC_THRESHOLD:  # Red para redes grandes
            alert_id = f"suspicious_traffic_{device_ip}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            message = f"Tráfico sospechoso detectado desde la IP {device_ip}. Más de {SUSPICIOUS_TRAFFIC_THRESHOLD} eventos en los últimos 10 minutos."
            context = {
                "log_ids": [log["_id"] for log in logs], 
                "source_ip": device_ip, 
                "event_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            activate_alert(alert_id, message, context)
        
        # Si es una red pequeña, se usa un umbral reducido (500 eventos)
        elif len(timestamps) >= SUSPICIOUS_TRAFFIC_THRESHOLD_SMALL:
            alert_id = f"suspicious_traffic_{device_ip}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            message = f"Tráfico sospechoso detectado desde la IP {device_ip}. Más de {SUSPICIOUS_TRAFFIC_THRESHOLD_SMALL} eventos en los últimos 10 minutos."
            context = {
                "log_ids": [log["_id"] for log in logs], 
                "source_ip": device_ip, 
                "event_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            activate_alert(alert_id, message, context)


def check_system_errors(logs):
    """
    Detecta errores críticos en los logs del sistema y genera una alerta en tiempo real.
    Args:
        logs: Logs extraídos de Elasticsearch
    """
    for log in logs:
        timestamp = log["_source"].get("timestamp")
        msg = log["_source"].get("msg", "")

        # Considera solo los logs con errores críticos
        if "critical error" in msg.lower():  # Esto puede depender de cómo se registran los errores en los logs
            log_time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
            
            alert_id = f"critical_error_{log['_id']}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            message = f"Error crítico detectado: {msg}. Log ID: {log['_id']}"
            context = {
                "log_ids": [log["_id"]], 
                "event_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "msg": msg
            }
            activate_alert(alert_id, message, context)


def check_snort_alert(logs):
    """
    Regla de correlación para detectar alertas de Snort.
    """
    print(">>>>> Entra en Regla de correlación para detectar alertas de Snort.")
    
    for log in logs:
        process_snort_log(log)

def process_snort_log(log_entry):
    """
    Procesa un único registro de log para detectar alertas de Snort.
    """
    if log_entry.get('_source', {}).get('type') == 'snort':
        alert_message = log_entry['_source'].get('msg', 'No message available')
        source_ip = log_entry['_source'].get('src_ip', 'IP desconocida')
        dest_ip = log_entry['_source'].get('dst_ip', 'IP desconocida')
        protocol = log_entry['_source'].get('protocol', 'Protocolo desconocido')
        sid = log_entry['_source'].get('sid', 'SID desconocido')
        
        # Lógica de filtrado por SID y msg
        if sid == "1000001":  # Syn Flood Attack (DoS)
            alert_type = "Ataque SYN Flood (DoS)"
        elif sid == "1000002":  # Nmap Scan (Exploración de Puertos)
            alert_type = "Exploración de Puertos (Nmap)"
        elif sid == "1000003":  # SQL Injection
            alert_type = "Intento de Inyección SQL"
        elif sid == "1000004":  # XSS Attack
            alert_type = "Ataque XSS (Cross-Site Scripting)"
        elif sid == "1000005":  # Brute Force Attack
            alert_type = "Ataque de Fuerza Bruta (SSH)"
        elif sid == "1000006":  # SMB Exploit (EternalBlue)
            alert_type = "Exploit SMB (EternalBlue)"
        elif sid == "1000007":  # Phishing
            alert_type = "Intento de Phishing"
        elif sid == "1000008":  # Malware Communication
            alert_type = "Comunicación de Malware"
        elif sid == "1000009":  # ARP Spoofing
            alert_type = "Ataque ARP Spoofing"
        elif sid == "1000010":  # DNS Tunneling
            alert_type = "Detección de DNS Tunneling"
        else:
            alert_type = "Alerta desconocida"

        timestamp_str = log_entry['_source'].get('timestamp')
        if timestamp_str:
            try:
                timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S")
                alert_id = f"snort_alert_{sid}_{source_ip}_{dest_ip}_{timestamp.strftime('%Y%m%d%H%M%S')}"
                
                # Verifica si la alerta ya está activa para evitar duplicación
                if not is_alert_active(alert_id):
                    message = f"{alert_type}: {alert_message} desde {source_ip} hacia {dest_ip} usando {protocol}"
                    context = {
                        "source_ip": source_ip,
                        "dest_ip": dest_ip,
                        "alert_message": alert_message,
                        "protocol": protocol,
                        "alert_type": alert_type,
                        "timestamp": timestamp.isoformat()
                    }
                    activate_alert(alert_id, message, context)
            except ValueError:
                print(f"Formato de fecha inválido en log: {timestamp_str}")


def check_time_related_events(logs):
    """
    Detecta más de 5 eventos desde una misma IP en los últimos 5 minutos.
    Args:
        logs: Logs extraídos de Elasticsearch.
    """
    for log in logs:
        timestamp = log["_source"].get("timestamp")
        src_ip = log["_source"].get("src_ip")
        
        log_time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
        event_tracker[src_ip].append(log_time)

    # Limpiar entradas antiguas (basado en la ventana de 5 minutos)
    for ip, timestamps in event_tracker.items():
        clean_old_entries(ip, TIME_RELATION_THRESHOLD)

        # Verificar si el número de eventos supera el umbral
        if len(timestamps) > 5:
            alert_id = f"time_related_events_{ip}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            message = f"Más de 5 eventos detectados desde la IP {ip} en los últimos 5 minutos."
            context = {
                "log_ids": [log["_id"] for log in logs], 
                "source_ip": ip, 
                "event_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            activate_alert(alert_id, message, context)


def check_apt(logs):
    """
    Detecta posibles APTs basados en el umbral de más de 20 eventos en un intervalo de 30 minutos.
    Args:
        logs: Logs extraídos de Elasticsearch
    """
    # Utiliza un diccionario para rastrear los eventos por dispositivo
    apt_tracker = defaultdict(list)

    for log in logs:
        timestamp = log["_source"].get("timestamp")
        device = log["_source"].get("device")  # Asumiendo que cada log tiene un campo 'device'

        # Convertimos el timestamp a un objeto datetime
        log_time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
        
        # Añadir evento al rastreador de APT
        apt_tracker[device].append(log_time)

    # Limpiar entradas antiguas (más de 30 minutos)
    for device, timestamps in apt_tracker.items():
        clean_old_entries(device, 30)  # Limpiar registros mayores a 30 minutos

        # Verificar si el número de eventos supera el umbral de 20 eventos en 30 minutos
        if len(timestamps) > 20:
            alert_id = f"apt_alert_{device}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            message = f"Posible APT detectada en el dispositivo {device}. Más de 20 eventos en los últimos 30 minutos."
            context = {
                "log_ids": [log["_id"] for log in logs],
                "device": device,
                "event_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            activate_alert(alert_id, message, context)


def check_recon_activity(logs):
    """
    Detecta escaneos de red (recon) basados en múltiples intentos en un corto periodo de tiempo.
    Args:
        logs: Logs extraídos de Elasticsearch
    """
    recon_tracker = defaultdict(list)  # Para almacenar intentos de escaneo por IP y dispositivo
    recon_threshold = 3  # Umbral mínimo de intentos para detectar un escaneo
    recon_window = timedelta(minutes=3)  # Ventana de tiempo de 3 minutos

    for log in logs:
        timestamp = log["_source"].get("timestamp")
        src_ip = log["_source"].get("src_ip")
        dest_ip = log["_source"].get("dest_ip")
        msg = log["_source"].get("msg", "")
        
        # Considerar logs de routers y switches
        if "router" in msg.lower() or "switch" in msg.lower():
            log_time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
            recon_tracker[(src_ip, dest_ip)].append(log_time)

    # Limpiar entradas antiguas (en base a la ventana de 3 minutos)
    for (src_ip, dest_ip), timestamps in recon_tracker.items():
        clean_old_entries((src_ip, dest_ip), 3)

        # Verificar si el número de intentos supera el umbral
        if len(timestamps) >= recon_threshold:
            alert_id = f"recon_activity_{src_ip}_{dest_ip}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            message = f"Posible escaneo de red detectado desde la IP {src_ip} hacia el dispositivo {dest_ip}. {len(timestamps)} intentos en los últimos 3 minutos."
            context = {
                "log_ids": [log["_id"] for log in logs],
                "source_ip": src_ip,
                "dest_ip": dest_ip,
                "event_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            activate_alert(alert_id, message, context)


def check_exploitation_attempts(logs):
    """
    Detecta intentos de explotación en función de los logs de autenticación.
    Umbral: Más de 3 intentos de explotación en un intervalo de 5 minutos.
    
    Args:
        logs: Logs extraídos de Elasticsearch
    """
    for log in logs:
        timestamp = log["_source"].get("timestamp")
        src_ip = log["_source"].get("src_ip")
        msg = log["_source"].get("msg", "")

        # Filtramos los logs que contienen intentos de explotación
        if "exploit attempt" in msg.lower():  # Este texto depende de cómo se logean los intentos de explotación
            log_time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
            event_tracker[src_ip].append(log_time)

    # Limpiar entradas antiguas para evitar acumular intentos fuera del intervalo
    for ip, timestamps in event_tracker.items():
        clean_old_entries(ip, TIME_RELATION_THRESHOLD)

        # Verificar si el número de intentos supera el umbral
        if len(timestamps) > BRUTE_FORCE_THRESHOLD:
            alert_id = f"exploitation_attempt_{ip}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            message = f"Intentos de explotación detectados desde la IP {ip}. Más de {BRUTE_FORCE_THRESHOLD} intentos fallidos en los últimos 5 minutos."
            context = {
                "log_ids": [log["_id"] for log in logs],  # Contexto con los IDs de los logs relevantes
                "source_ip": ip,
                "event_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            activate_alert(alert_id, message, context)


def check_unauthorized_access(logs):
    """
    Detecta intentos de acceso no autorizado basados en intentos fallidos de autenticación.
    Args:
        logs: Logs extraídos de Elasticsearch
    """
    for log in logs:
        timestamp = log["_source"].get("timestamp")
        src_ip = log["_source"].get("src_ip")
        msg = log["_source"].get("msg", "")

        # Verificar si es un intento fallido de autenticación
        if "authentication failed" in msg.lower():  # Ajusta esto según los logs específicos
            log_time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
            login_tracker[src_ip].append(log_time)

    # Limpiar entradas antiguas
    for ip, timestamps in login_tracker.items():
        clean_old_entries(ip, TIME_RELATION_THRESHOLD)  # Limpiar los registros de más de 3 minutos

        # Verificar si hay más de 5 intentos fallidos en los últimos 3 minutos
        if len(timestamps) > BRUTE_FORCE_THRESHOLD:
            alert_id = f"unauthorized_access_{ip}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            message = f"Acceso no autorizado detectado desde la IP {ip}. Más de 5 intentos fallidos en los últimos 3 minutos."
            context = {
                "log_ids": [log["_id"] for log in logs],
                "source_ip": ip,
                "event_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            activate_alert(alert_id, message, context)
