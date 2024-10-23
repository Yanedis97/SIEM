from datetime import datetime, timedelta
from collections import defaultdict
from flask_socketio import SocketIO
from main import app

# Inicializar SocketIO
socketio = SocketIO(app)

# Parámetros de reglas de correlación
BRUTE_FORCE_THRESHOLD = 5   # Número de intentos fallidos para generar alerta
BRUTE_FORCE_INTERVAL = 10   # Ventana de tiempo en minutos para considerar intentos fallidos
TIME_RELATION_THRESHOLD = 60 # Ventana de tiempo en minutos para eventos relacionados
APT_THRESHOLD = 5  # Número de eventos
APT_TIMEFRAME = 60  # Ventana de tiempo en minutos
WORK_HOURS_START = 9  # Horas laborales inician a las 9 AM
WORK_HOURS_END = 17  # Horas laborales terminan a las 5 PM
SYSTEM_EVENT_TIMEFRAME = 5  # Ventana de tiempo en minutos
RECON_THRESHOLD = 3
EXPLOITATION_THRESHOLD = 2
unauthorized_access_threshold = 3
suspicious_activity_threshold = 5

recon_tracker = defaultdict(list)  # Almacena eventos de reconocimiento
exploit_tracker = defaultdict(list)  # Almacena intentos de explotación
system_event_tracker = defaultdict(list)  # Almacena eventos de sistema
access_tracker = defaultdict(list)  # Almacena intentos de acceso no autorizado
activity_tracker = defaultdict(list) 
login_tracker = defaultdict(list)  # Almacena intentos fallidos por IP
event_tracker = defaultdict(list)  # Almacena eventos para correlacionar por IP
apt_tracker = defaultdict(list)
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

def activate_alert(alert_id, message, es):
    """
    Activa una alerta y la guarda en el almacén temporal.
    """
    active_alerts[alert_id] = datetime.now()

    print(f"Alerta generada: {message}")
    alert_data = {
        "alert_id": alert_id,
        "message": message,
        "timestamp": datetime.now().isoformat(),
        "status": "active"
    }
    es.index(index="alerts", body=alert_data)
    # Enviar notificación al frontend (WebSocket)
    socketio.emit('new_alert', alert_data)

def check_brute_force(log, es):
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
                activate_alert(alert_id, message, es)

def check_privilege_change(log, es):
    """
    Regla de correlación para detectar cambios de privilegios en usuarios.
    """
    if log['_source']['event']['action'] == 'privilege_change':
        user = log['_source']['user']['name']
        timestamp = datetime.strptime(log['_source']['@timestamp'], "%Y-%m-%dT%H:%M:%S.%fZ")
        
        alert_id = f"privilege_change_{user}_{timestamp.strftime('%Y%m%d%H%M%S')}"
        if not is_alert_active(alert_id):
            message = f"Cambio de privilegios detectado para el usuario {user}"
            activate_alert(alert_id, message, es)

def check_suspicious_traffic(log, es):
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
                activate_alert(alert_id, message, es)

def check_system_errors(log, es):
    """
    Regla de correlación para detectar errores del sistema.
    """
    if log['_source']['event']['category'] == 'system_error':
        error_message = log['_source']['message']
        timestamp = datetime.strptime(log['_source']['@timestamp'], "%Y-%m-%dT%H:%M:%S.%fZ")
        
        alert_id = f"system_error_{timestamp.strftime('%Y%m%d%H%M%S')}"
        if not is_alert_active(alert_id):
            message = f"Error del sistema detectado: {error_message}"
            activate_alert(alert_id, message, es)

def check_snort_alert(log, es):
    """
    Regla de correlación para detectar alertas de Snort.
    """
    if log['_source']['event']['category'] == 'snort_alert':
        alert_message = log['_source']['message']
        timestamp = datetime.strptime(log['_source']['@timestamp'], "%Y-%m-%dT%H:%M:%S.%fZ")
        
        alert_id = f"snort_alert_{timestamp.strftime('%Y%m%d%H%M%S')}"
        if not is_alert_active(alert_id):
            message = f"Alerta de Snort: {alert_message}"
            activate_alert(alert_id, message, es)

def check_time_related_events(log, es):
    """
    Regla para verificar eventos relacionados en un intervalo de tiempo.
    """
    ip = log['_source']['source']['ip']
    timestamp = datetime.strptime(log['_source']['@timestamp'], "%Y-%m-%dT%H:%M:%S.%fZ")

    # Agregar el evento al tracker
    event_tracker[ip].append(timestamp)
    clean_old_entries(ip, TIME_RELATION_THRESHOLD)

    # Verificar si hay eventos relacionados en el tiempo
    if len(event_tracker[ip]) > 1:
        alert_id = f"time_related_events_{ip}_{timestamp.strftime('%Y%m%d%H%M%S')}"
        if not is_alert_active(alert_id):
            message = f"Eventos relacionados detectados para {ip} en el intervalo de tiempo especificado."
            activate_alert(alert_id, message, es)

def check_apt(log, es):
    source_ip = log['_source']['source']['ip']
    event_type = log['_source']['event']['category']
    timestamp = datetime.strptime(log['_source']['@timestamp'], "%Y-%m-%dT%H:%M:%S.%fZ")

    # Agregar el evento al tracker
    apt_tracker[source_ip].append(timestamp)
    clean_old_entries(source_ip, APT_TIMEFRAME)

    # Verificar si se supera el umbral de APT
    if len(apt_tracker[source_ip]) >= APT_THRESHOLD:
        alert_id = f"apt_detected_{source_ip}_{timestamp.strftime('%Y%m%d%H%M%S')}"
        if not is_alert_active(alert_id):
            message = f"Detección de posible ataque persistente (APT) desde {source_ip}."
            activate_alert(alert_id, message, es)


def check_unauthorized_access_and_activity(log, es):
    timestamp = datetime.strptime(log['_source']['@timestamp'], "%Y-%m-%dT%H:%M:%S.%fZ")
    user = log['_source']['user']['name']

    # Registro de acceso no autorizado
    if log['_source']['event']['category'] == 'unauthorized_access':
        access_tracker[user].append(timestamp)
        clean_old_entries(user, 60)  # Limpiar después de 60 minutos

        # Verificar acceso no autorizado
        if len(access_tracker[user]) >= unauthorized_access_threshold:
            alert_id = f"unauthorized_access_{user}_{timestamp.strftime('%Y%m%d%H%M%S')}"
            if not is_alert_active(alert_id):
                message = f"Acceso no autorizado detectado para el usuario {user}."
                activate_alert(alert_id, message, es)

    # Registro de actividad sospechosa
    if log['_source']['event']['category'] == 'suspicious_activity':
        activity_tracker[user].append(timestamp)
        clean_old_entries(user, 60)  # Limpiar después de 60 minutos

        # Verificar actividad sospechosa
        if len(activity_tracker[user]) >= suspicious_activity_threshold:
            alert_id = f"suspicious_activity_after_unauthorized_{user}_{timestamp.strftime('%Y%m%d%H%M%S')}"
            if not is_alert_active(alert_id):
                message = f"Actividad sospechosa detectada tras acceso no autorizado del usuario {user}."
                activate_alert(alert_id, message, es)


def check_access_outside_work_hours(log, es):
    if log['_source']['event']['category'] == 'resource_access':
        timestamp = datetime.strptime(log['_source']['@timestamp'], "%Y-%m-%dT%H:%M:%S.%fZ")
        access_hour = timestamp.hour
        user = log['_source']['user']['name']

        # Verificar si el acceso fue fuera de horario laboral
        if access_hour < WORK_HOURS_START or access_hour > WORK_HOURS_END:
            alert_id = f"access_outside_work_hours_{user}_{timestamp.strftime('%Y%m%d%H%M%S')}"
            if not is_alert_active(alert_id):
                message = f"Acceso a recursos fuera del horario laboral para el usuario {user}."
                activate_alert(alert_id, message, es)

def check_network_and_system_events(log, es):
    timestamp = datetime.strptime(log['_source']['@timestamp'], "%Y-%m-%dT%H:%M:%S.%fZ")
    event_type = log['_source']['event']['category']
    
    # Registro de eventos de red
    if event_type == 'network_event':
        source_ip = log['_source']['source']['ip']
        system_event_tracker[source_ip].append(timestamp)
        clean_old_entries(source_ip, SYSTEM_EVENT_TIMEFRAME)

    # Registro de eventos de sistema
    if event_type == 'system_event':
        source_ip = log['_source']['source']['ip']
        if source_ip in system_event_tracker and len(system_event_tracker[source_ip]) > 0:
            alert_id = f"network_and_system_event_{source_ip}_{timestamp.strftime('%Y%m%d%H%M%S')}"
            if not is_alert_active(alert_id):
                message = f"Correlación de evento de red y de sistema detectada para {source_ip}."
                activate_alert(alert_id, message, es)

def check_recon_and_exploitation(log, es):
    timestamp = datetime.strptime(log['_source']['@timestamp'], "%Y-%m-%dT%H:%M:%S.%fZ")
    source_ip = log['_source']['source']['ip']

    if log['_source']['event']['category'] == 'reconnaissance':
        recon_tracker[source_ip].append(timestamp)
        clean_old_entries(source_ip, 60)

        if len(recon_tracker[source_ip]) >= RECON_THRESHOLD:
            alert_id = f"recon_detected_{source_ip}_{timestamp.strftime('%Y%m%d%H%M%S')}"
            if not is_alert_active(alert_id):
                message = f"Actividades de reconocimiento detectadas desde {source_ip}."
                activate_alert(alert_id, message, es)

    if log['_source']['event']['category'] == 'exploitation':
        exploit_tracker[source_ip].append(timestamp)
        clean_old_entries(source_ip, 60)

        if len(exploit_tracker[source_ip]) >= EXPLOITATION_THRESHOLD:
            alert_id = f"exploitation_attempt_{source_ip}_{timestamp.strftime('%Y%m%d%H%M%S')}"
            if not is_alert_active(alert_id):
                message = f"Intentos de explotación detectados desde {source_ip} tras reconocimiento."
                activate_alert(alert_id, message, es)

def process_log(log, es):
    """
    Procesa un log individual y aplica las reglas de correlación.
    """
    check_brute_force(log, es)
    check_privilege_change(log, es)
    check_suspicious_traffic(log, es)
    check_system_errors(log, es)
    check_snort_alert(log, es)
    check_time_related_events(log, es)
    check_apt(log, es)
    check_unauthorized_access_and_activity(log, es)
    check_access_outside_work_hours(log, es)
    check_network_and_system_events(log, es)
    check_recon_and_exploitation(log, es)
