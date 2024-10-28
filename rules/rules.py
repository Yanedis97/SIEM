from datetime import datetime, timedelta
from collections import defaultdict
# from flask_socketio import SocketIO
# from main import app

# Inicializar SocketIO
# socketio = SocketIO(app)

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

def activate_alert(alert_id, message, es, context=None):
    """
    Activa una alerta y la guarda en el almacén temporal.
    """
    active_alerts[alert_id] = datetime.now()

    print(f"Alerta generada: {message}")
    alert_data = {
        "alert_id": alert_id,
        "message": message,
        "timestamp": datetime.now().isoformat(),
        "status": "active",
        "context": context if context else {}  # Incluye el contexto si está presente
    }
    es.index(index="alerts", body=alert_data)
    # Enviar notificación al frontend (WebSocket)
    # socketio.emit('new_alert', alert_data)

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
                context = {
                    "ip": ip,
                    "failed_attempts": len(login_tracker[ip]),
                    "timestamp": timestamp.isoformat()
                }
                activate_alert(alert_id, message, es, context)

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
            context = {
                "user": user,
                "timestamp": timestamp.isoformat()
            }
            activate_alert(alert_id, message, es, context)

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
                context = {
                    "source_ip": source_ip,
                    "dest_ip": dest_ip,
                    "timestamp": timestamp.isoformat()
                }
                activate_alert(alert_id, message, es, context)

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
            context = {
                "error_message": error_message,
                "timestamp": timestamp.isoformat()
            }
            activate_alert(alert_id, message, es, context)

def check_snort_alert(log, es):
    """
    Regla de correlación para detectar alertas de Snort.
    """
    if log['_source'].get('type') == 'snort':
        alert_message = log['_source'].get('msg', 'No message available')
        source_ip = log['_source'].get('src_ip', 'IP desconocida')
        dest_ip = log['_source'].get('dst_ip', 'IP desconocida')
        timestamp = datetime.strptime(log['_source']['@timestamp'], "%Y-%m-%dT%H:%M:%S.%fZ")

        # Generar un ID único para la alerta
        alert_id = f"snort_alert_{source_ip}_{dest_ip}_{timestamp.strftime('%Y%m%d%H%M%S')}"
        
        # Activar la alerta si no está activa
        if not is_alert_active(alert_id):
            message = f"Alerta de Snort detectada en el dispositivo {source_ip}: {alert_message}. Origen: {source_ip}, Destino: {dest_ip}"
            context = {
                "alert_message": alert_message,
                "source_ip": source_ip,
                "dest_ip": dest_ip,
                "device": source_ip
            }
            # Agregar el ID de log a la alerta
            log_id = log['_id']  # O el campo que identifica el log
            activate_alert(alert_id, message, es, log_ids=[log_id], context=context)


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
            context = {
                "ip": ip,
                "event_count": len(event_tracker[ip]),
                "timestamp": timestamp.isoformat()
            }
            activate_alert(alert_id, message, es, context)

def check_apt(log, es):
    source_ip = log['_source']['source']['ip']
    event_type = log['_source']['event']['category']
    timestamp = datetime.strptime(log['_source']['@timestamp'], "%Y-%m-%dT%H:%M:%S.%fZ")

    # Agregar el evento al tracker
    apt_tracker[source_ip].append(timestamp)
    clean_old_entries(source_ip, APT_TIMEFRAME)

    # Verificar si hay patrones APT
    if len(apt_tracker[source_ip]) >= APT_THRESHOLD:
        alert_id = f"apt_alert_{source_ip}_{timestamp.strftime('%Y%m%d%H%M%S')}"
        if not is_alert_active(alert_id):
            message = f"Posible ataque persistente avanzado desde {source_ip}."
            context = {
                "source_ip": source_ip,
                "event_type": event_type,
                "event_count": len(apt_tracker[source_ip]),
                "timestamp": timestamp.isoformat()
            }
            activate_alert(alert_id, message, es, context)

def check_recon_activity(log, es):
    """
    Función para verificar actividad de reconocimiento.
    """
    ip = log['_source']['source']['ip']
    timestamp = datetime.strptime(log['_source']['@timestamp'], "%Y-%m-%dT%H:%M:%S.%fZ")

    recon_tracker[ip].append(timestamp)
    clean_old_entries(ip, RECON_THRESHOLD)

    # Generar alerta si hay actividad sospechosa de reconocimiento
    if len(recon_tracker[ip]) >= RECON_THRESHOLD:
        alert_id = f"recon_activity_{ip}_{timestamp.strftime('%Y%m%d%H%M%S')}"
        if not is_alert_active(alert_id):
            message = f"Actividad de reconocimiento detectada desde {ip}."
            context = {
                "ip": ip,
                "event_count": len(recon_tracker[ip]),
                "timestamp": timestamp.isoformat()
            }
            activate_alert(alert_id, message, es, context)

def check_exploitation_attempts(log, es):
    """
    Función para verificar intentos de explotación.
    """
    ip = log['_source']['source']['ip']
    timestamp = datetime.strptime(log['_source']['@timestamp'], "%Y-%m-%dT%H:%M:%S.%fZ")

    exploit_tracker[ip].append(timestamp)
    clean_old_entries(ip, EXPLOITATION_THRESHOLD)

    # Generar alerta si hay intentos de explotación
    if len(exploit_tracker[ip]) >= EXPLOITATION_THRESHOLD:
        alert_id = f"exploit_attempt_{ip}_{timestamp.strftime('%Y%m%d%H%M%S')}"
        if not is_alert_active(alert_id):
            message = f"Intento de explotación detectado desde {ip}."
            context = {
                "ip": ip,
                "event_count": len(exploit_tracker[ip]),
                "timestamp": timestamp.isoformat()
            }
            activate_alert(alert_id, message, es, context)

def check_unauthorized_access(log, es):
    """
    Función para verificar intentos de acceso no autorizado.
    """
    ip = log['_source']['source']['ip']
    timestamp = datetime.strptime(log['_source']['@timestamp'], "%Y-%m-%dT%H:%M:%S.%fZ")

    access_tracker[ip].append(timestamp)
    clean_old_entries(ip, unauthorized_access_threshold)

    # Generar alerta si hay intentos de acceso no autorizado
    if len(access_tracker[ip]) >= unauthorized_access_threshold:
        alert_id = f"unauthorized_access_{ip}_{timestamp.strftime('%Y%m%d%H%M%S')}"
        if not is_alert_active(alert_id):
            message = f"Intento de acceso no autorizado desde {ip}."
            context = {
                "ip": ip,
                "event_count": len(access_tracker[ip]),
                "timestamp": timestamp.isoformat()
            }
            activate_alert(alert_id, message, es, context)

def check_suspicious_activity(log, es):
    """
    Función para verificar actividad sospechosa.
    """
    ip = log['_source']['source']['ip']
    timestamp = datetime.strptime(log['_source']['@timestamp'], "%Y-%m-%dT%H:%M:%S.%fZ")

    activity_tracker[ip].append(timestamp)
    clean_old_entries(ip, suspicious_activity_threshold)

    # Generar alerta si hay actividad sospechosa
    if len(activity_tracker[ip]) >= suspicious_activity_threshold:
        alert_id = f"suspicious_activity_{ip}_{timestamp.strftime('%Y%m%d%H%M%S')}"
        if not is_alert_active(alert_id):
            message = f"Actividad sospechosa detectada desde {ip}."
            context = {
                "ip": ip,
                "event_count": len(activity_tracker[ip]),
                "timestamp": timestamp.isoformat()
            }
            activate_alert(alert_id, message, es, context)
    