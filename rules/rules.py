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
    # Revisar si el mensaje indica un intento fallido de login
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


def check_privilege_change(log, es):
    """
    Regla de correlación para detectar cambios de privilegios en usuarios.
    """
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


def check_suspicious_traffic(log, es):
    """
    Regla de correlación para detectar tráfico sospechoso.
    """
    try:
        # Obtener el mensaje (msg) y buscar patrones que indiquen tráfico sospechoso
        message = log.get('_source', {}).get('msg', '').lower()
        source_ip = log.get('_source', {}).get('src_ip')
        dest_ip = log.get('_source', {}).get('dst_ip')
        timestamp_str = log.get('_source', {}).get('timestamp')
        
        # Verificación de condiciones de tráfico sospechoso
        if source_ip and dest_ip and timestamp_str:
            # Suponemos que los mensajes que contienen "tráfico sospechoso" o algo similar indican un problema
            if "sospechoso" in message:
                try:
                    # Convertir la marca de tiempo
                    timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S")
                    
                    # Crear un ID único para la alerta basado en las IPs de origen y destino y la marca de tiempo
                    alert_id = f"suspicious_traffic_{source_ip}_{dest_ip}_{timestamp.strftime('%Y%m%d%H%M%S')}"
                    
                    # Si no hay alerta activa, activar la alerta
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


def check_system_errors(log, es):
    """
    Regla de correlación para detectar errores del sistema.
    """
    try:
        # Extraer información del log
        error_message = log.get('_source', {}).get('msg')
        timestamp_str = log.get('_source', {}).get('timestamp')
        
        # Verificar que el log tenga el mensaje de error y la marca de tiempo
        if error_message and timestamp_str:
            # Convertir la marca de tiempo
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S")
            
            # Crear un ID único para la alerta basado en la marca de tiempo
            alert_id = f"system_error_{timestamp.strftime('%Y%m%d%H%M%S')}"
            
            # Si no hay alerta activa, activar la alerta
            if not is_alert_active(alert_id):
                message = f"Error del sistema detectado: {error_message}"
                context = {
                    "error_message": error_message,
                    "timestamp": timestamp.isoformat()
                }
                activate_alert(alert_id, message, es, context)
    except Exception as e:
        print(f"Error al procesar el log: {e}")


def check_snort_alert(log, es):
    """
    Regla de correlación para detectar alertas de Snort.
    """
    try:
        log_type = log.get('_source', {}).get('type')
        
        if log_type == 'snort':
            alert_message = log['_source'].get('msg', 'No message available')
            source_ip = log['_source'].get('src_ip', 'IP desconocida')
            dest_ip = log['_source'].get('dst_ip', 'IP desconocida')
            timestamp_str = log['_source'].get('@timestamp')
            
            if timestamp_str:
                timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S.%fZ")
                
                alert_id = f"snort_alert_{source_ip}_{dest_ip}_{timestamp.strftime('%Y%m%d%H%M%S')}"
                
                if not is_alert_active(alert_id):
                    message = (
                        f"Alerta de Snort detectada en el dispositivo {source_ip}: {alert_message}. "
                        f"Origen: {source_ip}, Destino: {dest_ip}"
                    )
                    context = {
                        "alert_message": alert_message,
                        "source_ip": source_ip,
                        "dest_ip": dest_ip,
                        "device": source_ip
                    }
                    
                    log_id = log.get('_id', 'ID desconocido')
                    activate_alert(alert_id, message, es, log_ids=[log_id], context=context)
    except Exception as e:
        print(f"Error al procesar el log de Snort: {e}")


def check_time_related_events(log, es):
    """
    Regla para verificar eventos relacionados en un intervalo de tiempo.
    """
    try:
        # Extraer la IP y la marca de tiempo
        ip = log.get('_source', {}).get('src_ip')  # Verifica que 'src_ip' sea el campo correcto
        timestamp_str = log.get('_source', {}).get('timestamp')

        if ip and timestamp_str:
            # Convertir la marca de tiempo a un objeto datetime
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S")
            
            # Inicializar el event_tracker para la IP si no existe
            if ip not in event_tracker:
                event_tracker[ip] = []

            # Agregar el evento al tracker
            event_tracker[ip].append(timestamp)

            # Limpiar entradas antiguas basadas en el umbral de tiempo
            clean_old_entries(ip, TIME_RELATION_THRESHOLD)

            # Verificar si hay eventos relacionados en el tiempo
            if len(event_tracker[ip]) > 1:
                # Crear un ID único para la alerta basado en la IP y el timestamp
                alert_id = f"time_related_events_{ip}_{timestamp.strftime('%Y%m%d%H%M%S')}"
                
                # Si no hay alerta activa, activarla
                if not is_alert_active(alert_id):
                    message = f"Eventos relacionados detectados para {ip} en el intervalo de tiempo especificado."
                    context = {
                        "ip": ip,
                        "event_count": len(event_tracker[ip]),
                        "timestamp": timestamp.isoformat()
                    }
                    activate_alert(alert_id, message, es, context)
    except Exception as e:
        print(f"Error al procesar el log de eventos relacionados en el tiempo: {e}")


def check_apt(log, es):
    try:
        # Accediendo a los datos basados en la estructura de log proporcionada
        src_ip = log.get('_source', {}).get('src_ip')
        dst_ip = log.get('_source', {}).get('dst_ip')
        msg = log.get('_source', {}).get('msg')
        timestamp_str = log.get('_source', {}).get('timestamp')

        # Asegurarse de que todos los datos necesarios están presentes
        if src_ip and dst_ip and msg and timestamp_str:
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S")

            # Verificar si la IP de origen existe en el tracker, si no inicializarla
            if src_ip not in apt_tracker:
                apt_tracker[src_ip] = []

            # Agregar el evento al tracker
            apt_tracker[src_ip].append(timestamp)

            # Limpiar entradas antiguas fuera del marco de tiempo de APT
            clean_old_entries(src_ip, APT_TIMEFRAME)

            # Verificar si hay patrones APT (umbral de eventos)
            if len(apt_tracker[src_ip]) >= APT_THRESHOLD:
                alert_id = f"apt_alert_{src_ip}_{timestamp.strftime('%Y%m%d%H%M%S')}"
                if not is_alert_active(alert_id):
                    message = f"Posible ataque persistente avanzado detectado desde {src_ip} hacia {dst_ip}: {msg}"
                    context = {
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "msg": msg,
                        "event_count": len(apt_tracker[src_ip]),
                        "timestamp": timestamp.isoformat()
                    }
                    activate_alert(alert_id, message, es, context)

    except KeyError as e:
        print(f"Error al procesar el log: Falta clave {e}")
    except Exception as e:
        print(f"Error inesperado al procesar el log de APT: {e}")


def check_recon_activity(log, es):
    """
    Función para verificar actividad de reconocimiento.
    """
    try:
        # Accediendo a los datos basados en la estructura de log proporcionada
        src_ip = log.get('_source', {}).get('src_ip')
        timestamp_str = log.get('_source', {}).get('timestamp')

        # Asegurarse de que ambos datos estén presentes
        if src_ip and timestamp_str:
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S")

            # Inicializar el tracker para la IP si no existe
            if src_ip not in recon_tracker:
                recon_tracker[src_ip] = []

            # Agregar el evento al tracker
            recon_tracker[src_ip].append(timestamp)

            # Limpiar entradas antiguas fuera del marco de tiempo de RECON
            clean_old_entries(src_ip, RECON_THRESHOLD)

            # Verificar si hay actividad de reconocimiento (umbral de eventos)
            if len(recon_tracker[src_ip]) >= RECON_THRESHOLD:
                alert_id = f"recon_activity_{src_ip}_{timestamp.strftime('%Y%m%d%H%M%S')}"
                if not is_alert_active(alert_id):
                    message = f"Actividad de reconocimiento detectada desde {src_ip}."
                    context = {
                        "src_ip": src_ip,
                        "event_count": len(recon_tracker[src_ip]),
                        "timestamp": timestamp.isoformat()
                    }
                    activate_alert(alert_id, message, es, context)

    except KeyError as e:
        print(f"Error al procesar el log: Falta clave {e}")
    except Exception as e:
        print(f"Error inesperado al procesar el log de actividad de reconocimiento: {e}")


def check_exploitation_attempts(log, es):
    """
    Función para verificar intentos de explotación.
    """
    try:
        # Accediendo a los datos basados en la estructura de log proporcionada
        src_ip = log.get('_source', {}).get('src_ip')
        timestamp_str = log.get('_source', {}).get('timestamp')

        # Asegurarse de que ambos datos estén presentes
        if src_ip and timestamp_str:
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S")

            # Inicializar el tracker para la IP si no existe
            if src_ip not in exploit_tracker:
                exploit_tracker[src_ip] = []

            # Agregar el evento al tracker
            exploit_tracker[src_ip].append(timestamp)

            # Limpiar entradas antiguas fuera del marco de tiempo de EXPLOITATION_THRESHOLD
            clean_old_entries(src_ip, EXPLOITATION_THRESHOLD)

            # Verificar si hay intentos de explotación (umbral de eventos)
            if len(exploit_tracker[src_ip]) >= EXPLOITATION_THRESHOLD:
                alert_id = f"exploit_attempt_{src_ip}_{timestamp.strftime('%Y%m%d%H%M%S')}"
                if not is_alert_active(alert_id):
                    message = f"Intento de explotación detectado desde {src_ip}."
                    context = {
                        "src_ip": src_ip,
                        "event_count": len(exploit_tracker[src_ip]),
                        "timestamp": timestamp.isoformat()
                    }
                    activate_alert(alert_id, message, es, context)

    except KeyError as e:
        print(f"Error al procesar el log: Falta clave {e}")
    except Exception as e:
        print(f"Error inesperado al procesar el log de intentos de explotación: {e}")


def check_unauthorized_access(log, es):
    """
    Función para verificar intentos de acceso no autorizado.
    """
    try:
        # Accediendo a los datos según la estructura de log proporcionada
        src_ip = log.get('_source', {}).get('src_ip')
        timestamp_str = log.get('_source', {}).get('timestamp')

        # Asegurarse de que ambos datos estén presentes
        if src_ip and timestamp_str:
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S")

            # Inicializar el tracker para la IP si no existe
            if src_ip not in access_tracker:
                access_tracker[src_ip] = []

            # Agregar el evento al tracker
            access_tracker[src_ip].append(timestamp)

            # Limpiar entradas antiguas fuera del marco de tiempo de unauthorized_access_threshold
            clean_old_entries(src_ip, unauthorized_access_threshold)

            # Verificar si hay intentos de acceso no autorizado
            if len(access_tracker[src_ip]) >= unauthorized_access_threshold:
                alert_id = f"unauthorized_access_{src_ip}_{timestamp.strftime('%Y%m%d%H%M%S')}"
                if not is_alert_active(alert_id):
                    message = f"Intento de acceso no autorizado desde {src_ip}."
                    context = {
                        "src_ip": src_ip,
                        "event_count": len(access_tracker[src_ip]),
                        "timestamp": timestamp.isoformat()
                    }
                    activate_alert(alert_id, message, es, context)

    except KeyError as e:
        print(f"Error al procesar el log: Falta clave {e}")
    except Exception as e:
        print(f"Error inesperado al procesar el log de acceso no autorizado: {e}")
        

def check_suspicious_activity(log, es):
    """
    Función para verificar actividad sospechosa.
    """
    try:
        # Accediendo a los datos según la estructura de log proporcionada
        src_ip = log.get('_source', {}).get('src_ip')
        timestamp_str = log.get('_source', {}).get('timestamp')

        # Asegurarse de que ambos datos estén presentes
        if src_ip and timestamp_str:
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S")

            # Inicializar el tracker para la IP si no existe
            if src_ip not in activity_tracker:
                activity_tracker[src_ip] = []

            # Agregar el evento al tracker
            activity_tracker[src_ip].append(timestamp)

            # Limpiar entradas antiguas fuera del marco de tiempo de suspicious_activity_threshold
            clean_old_entries(src_ip, suspicious_activity_threshold)

            # Verificar si hay actividad sospechosa
            if len(activity_tracker[src_ip]) >= suspicious_activity_threshold:
                alert_id = f"suspicious_activity_{src_ip}_{timestamp.strftime('%Y%m%d%H%M%S')}"
                if not is_alert_active(alert_id):
                    message = f"Actividad sospechosa detectada desde {src_ip}."
                    context = {
                        "src_ip": src_ip,
                        "event_count": len(activity_tracker[src_ip]),
                        "timestamp": timestamp.isoformat()
                    }
                    activate_alert(alert_id, message, es, context)

    except KeyError as e:
        print(f"Error al procesar el log: Falta clave {e}")
    except Exception as e:
        print(f"Error inesperado al procesar el log de actividad sospechosa: {e}")
    