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

def check_brute_force(logs, es):
    # Revisar si el mensaje indica un intento fallido de login
    for log in logs:
        message = log['_source'].get('msg', '').lower()
        if 'login fallido' in message or 'fuerza bruta' in message:
            ip = log['_source'].get('src_ip', 'IP desconocida')
            
            timestamp_str = log['_source'].get('timestamp')
            if timestamp_str:
                try:
                    timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S")
                    # Agregar la marca de tiempo al tracker de intentos fallidos de login
                    login_tracker[ip].append(timestamp)
                    clean_old_entries(ip, BRUTE_FORCE_INTERVAL)
                    
                    if len(login_tracker[ip]) >= BRUTE_FORCE_THRESHOLD:
                        alert_id = f"brute_force_{ip}_{timestamp.strftime('%Y%m%d%H%M%S')}"
                        if not is_alert_active(alert_id):
                            message = f"Posible ataque de fuerza bruta detectado desde {ip}"
                            context = {
                                "ip": ip,
                                "failed_attempts": len(login_tracker[ip]),
                                "timestamp": timestamp.isoformat()
                            }
                            activate_alert(alert_id, message, es, context)
                except ValueError:
                    print(f"Formato de fecha inválido en log: {timestamp_str}")

def check_privilege_change(logs, es):
    """
    Regla de correlación para detectar cambios de privilegios en usuarios.
    """
    for log in logs:
        try:
            # Verificar si el mensaje indica un cambio de privilegios
            message = log.get('_source', {}).get('msg', '').lower()
            if 'cambio de privilegio' in message:
                # Usar 'src_ip' como identificador del usuario
                user_ip = log.get('_source', {}).get('src_ip', 'IP desconocida')
                
                # Obtener y convertir la marca de tiempo
                timestamp_str = log.get('_source', {}).get('timestamp')
                if timestamp_str:
                    try:
                        timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S")
                        
                        # Crear el ID de alerta usando la IP del usuario y la marca de tiempo
                        alert_id = f"privilege_change_{user_ip}_{timestamp.strftime('%Y%m%d%H%M%S')}"
                        
                        # Activar alerta si no hay una alerta activa con este ID
                        if not is_alert_active(alert_id):
                            message = f"Cambio de privilegios detectado desde la IP {user_ip}"
                            context = {
                                "user_ip": user_ip,
                                "timestamp": timestamp.isoformat()
                            }
                            activate_alert(alert_id, message, es, context)
                    except ValueError:
                        print(f"Formato de fecha inválido en log: {timestamp_str}")
        except Exception as e:
            print(f"Error al procesar el log: {e}")

def check_suspicious_traffic(logs, es):
    """
    Regla de correlación para detectar tráfico sospechoso.
    """
    for log in logs:
        try:
            # Obtener el mensaje (msg) y buscar patrones que indiquen tráfico sospechoso
            message = log.get('_source', {}).get('msg', '').lower()
            source_ip = log.get('_source', {}).get('src_ip')
            dest_ip = log.get('_source', {}).get('dst_ip')
            timestamp_str = log.get('_source', {}).get('timestamp')
            
            # Verificación de condiciones de tráfico sospechoso
            if source_ip and dest_ip and timestamp_str:
                if "sospechoso" in message:
                    try:
                        timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S")
                        alert_id = f"suspicious_traffic_{source_ip}_{dest_ip}_{timestamp.strftime('%Y%m%d%H%M%S')}"
                        
                        if not is_alert_active(alert_id):
                            message = f"Tráfico sospechoso detectado entre {source_ip} y {dest_ip}"
                            context = {
                                "source_ip": source_ip,
                                "dest_ip": dest_ip,
                                "timestamp": timestamp.isoformat()
                            }
                            activate_alert(alert_id, message, es, context)
                    except ValueError:
                        print(f"Formato de fecha inválido en log: {timestamp_str}")
        except Exception as e:
            print(f"Error al procesar el log: {e}")

def check_system_errors(logs, es):
    """
    Regla de correlación para detectar errores del sistema.
    """
    for log in logs:
        try:
            error_message = log.get('_source', {}).get('msg')
            timestamp_str = log.get('_source', {}).get('timestamp')
            
            if error_message and timestamp_str:
                timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S")
                alert_id = f"system_error_{timestamp.strftime('%Y%m%d%H%M%S')}"
                
                if not is_alert_active(alert_id):
                    message = f"Error del sistema detectado: {error_message}"
                    context = {
                        "error_message": error_message,
                        "timestamp": timestamp.isoformat()
                    }
                    activate_alert(alert_id, message, es, context)
        except Exception as e:
            print(f"Error al procesar el log: {e}")

def check_snort_alert(logs, es):
    """
    Regla de correlación para detectar alertas de Snort.
    """
    print(">>>>> Entra en Regla de correlación para detectar alertas de Snort.")
    
    for log in logs:
        process_snort_log(log, es)

def process_snort_log(log_entry, es):
    """
    Procesa un único registro de log para detectar alertas de Snort.
    """
    if log_entry.get('_source', {}).get('type') == 'snort':
        alert_message = log_entry['_source'].get('msg', 'No message available')
        source_ip = log_entry['_source'].get('src_ip', 'IP desconocida')
        dest_ip = log_entry['_source'].get('dst_ip', 'IP desconocida')

        timestamp_str = log_entry['_source'].get('timestamp')
        if timestamp_str:
            try:
                timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S")
                alert_id = f"snort_alert_{source_ip}_{dest_ip}_{timestamp.strftime('%Y%m%d%H%M%S')}"
                if not is_alert_active(alert_id):
                    message = f"Alerta de Snort: {alert_message} entre {source_ip} y {dest_ip}"
                    context = {
                        "source_ip": source_ip,
                        "dest_ip": dest_ip,
                        "alert_message": alert_message,
                        "timestamp": timestamp.isoformat()
                    }
                    activate_alert(alert_id, message, es, context)
            except ValueError:
                print(f"Formato de fecha inválido en log: {timestamp_str}")

