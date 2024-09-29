from datetime import datetime, timedelta
from collections import defaultdict

# Parámetros de reglas de correlación
BRUTE_FORCE_THRESHOLD = 5   # Número de intentos fallidos para generar alerta
BRUTE_FORCE_INTERVAL = 10   # Ventana de tiempo en minutos para considerar intentos fallidos

# Almacenamiento temporal para intentos fallidos y alertas generadas
login_tracker = defaultdict(list)  # Almacena intentos fallidos por IP
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

def is_alert_active(alert_id):
    """
    Verifica si una alerta con este ID ya está activa.
    """
    return alert_id in active_alerts

def activate_alert(alert_id, message):
    """
    Activa una alerta y la guarda en el almacén temporal.
    """
    # Se podría almacenar la alerta en Elasticsearch u otro sistema de almacenamiento
    active_alerts[alert_id] = datetime.now()
    # Imprime la alerta generada para monitoreo
    print(f"Alerta generada: {message}")

def check_brute_force(log):
    """
    Regla de correlación para detectar fuerza bruta.
    """
    if log['_source']['event']['action'] == 'login_failed':
        ip = log['_source']['source']['ip']
        timestamp = datetime.strptime(log['_source']['@timestamp'], "%Y-%m-%dT%H:%M:%S.%fZ")
        
        # Agregar el intento fallido al tracker
        login_tracker[ip].append(timestamp)
        clean_old_entries(ip, BRUTE_FORCE_INTERVAL)
        
        # Verificar si se debe generar una alerta
        if len(login_tracker[ip]) >= BRUTE_FORCE_THRESHOLD:
            alert_id = f"brute_force_{ip}_{timestamp.strftime('%Y%m%d%H%M%S')}"
            if not is_alert_active(alert_id):
                message = f"Posible ataque de fuerza bruta desde {ip}"
                activate_alert(alert_id, message)

def check_privilege_change(log):
    """
    Regla de correlación para detectar cambios de privilegios en usuarios.
    """
    if log['_source']['event']['action'] == 'privilege_change':
        user = log['_source']['user']['name']
        timestamp = datetime.strptime(log['_source']['@timestamp'], "%Y-%m-%dT%H:%M:%S.%fZ")
        
        alert_id = f"privilege_change_{user}_{timestamp.strftime('%Y%m%d%H%M%S')}"
        if not is_alert_active(alert_id):
            message = f"Cambio de privilegios detectado para el usuario {user}"
            activate_alert(alert_id, message)

def check_suspicious_traffic(log):
    """
    Regla de correlación para detectar tráfico sospechoso.
    """
    if log['_source']['event']['category'] == 'network_traffic':
        source_ip = log['_source']['source']['ip']
        dest_ip = log['_source']['destination']['ip']
        traffic_type = log['_source']['event']['type']
        
        # Detectar tráfico anómalo, por ejemplo, muchas conexiones en poco tiempo
        if traffic_type == 'anomalous':
            timestamp = datetime.strptime(log['_source']['@timestamp'], "%Y-%m-%dT%H:%M:%S.%fZ")
            
            alert_id = f"suspicious_traffic_{source_ip}_{dest_ip}_{timestamp.strftime('%Y%m%d%H%M%S')}"
            if not is_alert_active(alert_id):
                message = f"Tráfico sospechoso detectado entre {source_ip} y {dest_ip}"
                activate_alert(alert_id, message)

def check_system_errors(log):
    """
    Regla de correlación para detectar errores del sistema.
    """
    if log['_source']['event']['category'] == 'system_error':
        error_message = log['_source']['message']
        timestamp = datetime.strptime(log['_source']['@timestamp'], "%Y-%m-%dT%H:%M:%S.%fZ")
        
        alert_id = f"system_error_{timestamp.strftime('%Y%m%d%H%M%S')}"
        if not is_alert_active(alert_id):
            message = f"Error del sistema detectado: {error_message}"
            activate_alert(alert_id, message)

def process_log(log):
    """
    Procesa un log individual y aplica las reglas de correlación.
    """
    check_brute_force(log)
    check_privilege_change(log)
    check_suspicious_traffic(log)
    check_system_errors(log)
