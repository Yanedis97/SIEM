from datetime import datetime, timedelta
from collections import defaultdict
from database.db_connection import SessionLocal
from app.models.alerts import Alerts
from app.models.alerts_categories import AlertsCategory
from app.services.log_service import update_log
import json
import re

# Parámetros de reglas de correlación
TIME_RELATION_THRESHOLD = 5  # en minutos
EVENT_TIME_WINDOW = timedelta(minutes=5)
BRUTE_FORCE_THRESHOLD = 3    # Mínimo de intentos fallidos
SUSPICIOUS_TRAFFIC_THRESHOLD = 1000  # Umbral de eventos para tráfico sospechoso
SUSPICIOUS_TRAFFIC_THRESHOLD_SMALL = 500  # Umbral reducido para redes pequeñas
TRAFFIC_WINDOW = timedelta(minutes=10)  # Ventana de tiempo de 10 minutos
MALWARE_ACTIVITY_THRESHOLD = 10  # Número de eventos para considerar como actividad sospechosa
MALWARE_TIME_WINDOW = timedelta(minutes=10)
FAILED_ATTEMPT_THRESHOLD = 5
TIME_WINDOW = timedelta(minutes=15)
TRANSFER_THRESHOLD = 1 * 1024 * 1024 * 1024  # 1 GB en bytes
TIME_WINDOW = timedelta(minutes=10)
INTERNAL_CONNECTIONS_THRESHOLD = 10  # Número mínimo de intentos
TIME_WINDOW = timedelta(minutes=5)
APPLICATION_EVENT_THRESHOLD = 3  # Umbral de eventos críticos de acceso fallido
TIME_WINDOW = timedelta(minutes=5)

login_tracker = defaultdict(list)  # Almacena intentos fallidos por IP
event_tracker = defaultdict(list)  # Almacena eventos para correlacionar por IP
traffic_tracker = defaultdict(list) # Almacena eventos por dispositivo (IP de origen o dispositivo)
malware_tracker = defaultdict(list) # Almacena eventos de malware por dispositivo
user_attempt_tracker = defaultdict(list)
data_transfer_tracker = defaultdict(lambda: {"size": 0, "timestamp": None})
internal_connection_tracker = defaultdict(list)
app_event_tracker = defaultdict(list)

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

def activate_alert(alert_id: str, message: str, context: dict = {}, category:str = ""):
    """
    Activa una alerta y la guarda en el almacén temporal.
    """
    active_alerts[alert_id] = datetime.now()

    print(f"Alerta generada: {message}")

    session = SessionLocal()
    try:

        context_str = json.dumps(context) if context != {} else ""

        alert_category = session.query(AlertsCategory).filter(AlertsCategory.code == category).first()
        if alert_category is None:
            raise ValueError("No se encontro información de la categoria de la alerta")
        
        alert_data = Alerts(
            second_id = alert_id,
            log_ids = str(context.get("log_ids",None)),  
            alert_type = 1,  
            message = message,
            source_ip = context.get("source_ip",None),  
            dest_ip = context.get("dest_ip",None),
            severity = "",  
            context = context_str,
            alert_category = alert_category.id,
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
    failed_patterns = [
        # Inglés
        "failed password",  # Contraseña fallida
        "incorrect password",  # Contraseña incorrecta
        "failed to authenticate",  # Fallo en la autenticación
        "login failure",  # Fallo de inicio de sesión

        # Español
        "fallo de autenticación",  # Intentos fallidos de autenticación
        "contraseña incorrecta",  # Contraseña incorrecta
        "error de inicio de sesión",  # Error de inicio de sesión
        "usuario desconocido o contraseña incorrecta"  # Usuario o contraseña incorrecta
    ]
    login_tracker = {}
    for log in logs:
        log_id = log["_id"]
        timestamp = log["_source"].get("timestamp")
        src_ip = log["_source"].get("src_ip")
        msg = log["_source"].get("msg", "")
        auth_alert = log["_source"].get("auth_alert", 0)
        
        #if "authentication failure" in msg.lower() or "failed password" in msg.lower() or "logon failure" in msg.lower():  
        if any(pattern.lower() in msg.lower() for pattern in failed_patterns):
            if auth_alert == 0:
                if src_ip != 'Desconocido':
                    log_time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S")

                    if src_ip not in login_tracker:
                        login_tracker[src_ip] = []
                        
                    login_tracker[src_ip].append([log_time, log_id])

    for ip, timestamps_and_ids in login_tracker.items():
        
        if len(timestamps_and_ids) >= BRUTE_FORCE_THRESHOLD:
            
            # Ordenamos los intentos por timestamp
            timestamps_and_ids.sort(key=lambda x: x[0])

            # Recorremos los intentos y validamos si hay 3 en el rango de 5 minutos
            for i in range(len(timestamps_and_ids) - 2):  # -2 porque necesitamos al menos 3 intentos
                time_window_start = timestamps_and_ids[i][0]  # El primer timestamp del rango
                time_window_end = time_window_start + timedelta(minutes=5)  # Rango de 5 minutos
                
                # Contamos cuántos logs están dentro del rango de 5 minutos
                logs_in_window = [
                    log_id for log_time, log_id in timestamps_and_ids[i:i+BRUTE_FORCE_THRESHOLD]
                    if time_window_start <= log_time <= time_window_end
                ]

                if len(logs_in_window) >= BRUTE_FORCE_THRESHOLD:
                    alert_id = f"brute_force_{ip}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
                    message = f"Posible ataque de fuerza bruta detectado desde la IP {ip}. {len(timestamps_and_ids)} intentos fallidos en los últimos {TIME_RELATION_THRESHOLD} minutos."
    
                    context = {
                        "log_ids": logs_in_window, 
                        "source_ip": ip, 
                        "event_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }

                    for log_id in logs_in_window:
                        update_log(str(log_id), "auth_alert")
                    activate_alert(alert_id, message, context, "check_brute_force")
                    break


def check_privilege_change(logs):
    """
    Detecta cambios de privilegios en los logs.
    Args:
        logs: Logs extraídos de Elasticsearch.
    """
    for log in logs:
        timestamp = log["_source"].get("timestamp")
        msg = log["_source"].get("msg", "")
        has_alert = log["_source"].get("has_alert", 0)
        program = log["_source"].get("program", "")
        
        if "privilege change" in msg.lower() or program == "sudo":
            if has_alert == 0:
                try:
                    log_time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S")
                except ValueError as e:
                    continue 
                alert_id = f"privilege_change_{log['_id']}{datetime.now().strftime('%Y%m%d%H%M%S')}"
                message = f"Cambio de privilegio detectado: {msg}. Log ID: {log['_id']}"
                context = {
                    "log_ids": [log["_id"]],
                    "event_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "msg": msg,
                    "log_time": log_time.strftime("%Y-%m-%d %H:%M:%S")
                }
                update_log(str(log["_id"]), "has_alert")
                activate_alert(alert_id, message, context, "check_privilege_change")


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
            log_time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S")
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
            activate_alert(alert_id, message, context,"check_suspicious_traffic")
        
        # Si es una red pequeña, se usa un umbral reducido (500 eventos)
        elif len(timestamps) >= SUSPICIOUS_TRAFFIC_THRESHOLD_SMALL:
            alert_id = f"suspicious_traffic_{device_ip}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            message = f"Tráfico sospechoso detectado desde la IP {device_ip}. Más de {SUSPICIOUS_TRAFFIC_THRESHOLD_SMALL} eventos en los últimos 10 minutos."
            context = {
                "log_ids": [log["_id"] for log in logs], 
                "source_ip": device_ip, 
                "event_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            activate_alert(alert_id, message, context, "check_suspicious_traffic")


def check_system_errors(logs):
    """
    Detecta errores críticos en los logs del sistema y genera una alerta en tiempo real.
    Args:
        logs: Logs extraídos de Elasticsearch
    """

    # Definir patrones que indiquen errores críticos en los logs
    critical_error_patterns = [
        # Windows Errors (English and Spanish)
        r".*(The system has rebooted without cleanly shutting down first|Un dispositivo conectado al sistema no está funcionando).*",
        r".*(Windows failed to start|Windows no pudo iniciarse).*",
        r".*(The driver detected a controller error on|El controlador detectó un error en el controlador).*",
        r".*(Service failed to start|El servicio no pudo iniciarse).*",
        r".*(Network connection lost|Conexión de red perdida).*",
        r".*(The trust relationship between this workstation and the primary domain failed|La relación de confianza entre esta estación de trabajo y el dominio primario falló).*",
        
        # Linux Errors (English and Spanish)
        r".*(Can't open blockdev|No se puede abrir el dispositivo de bloque).*",
        r".*(kernel panic|pánico del kernel).*",
        r".*(critical error|error crítico).*",
        r".*(Out of memory|Fuera de memoria).*",
        r".*(disk failure|fallo de disco).*",
        r".*(no space left on device|No hay espacio disponible en el dispositivo).*",
        r".*(failed to mount|No se pudo montar).*",
        r".*(unable to load module|No se pudo cargar el módulo).*",
        
        # macOS Errors (English and Spanish)
        r".*(kernel panic|pánico del kernel).*",
        r".*(device not found|Dispositivo no encontrado).*",
        r".*(disk failure|Fallo de disco).*",
        r".*(out of memory|Falta de memoria).*",
        r".*(unable to boot|No se puede iniciar).*",
        r".*(the system cannot find the path specified|El sistema no puede encontrar la ruta especificada).*"
    ]

    for log in logs:
        timestamp = log["_source"].get("timestamp")
        msg = log["_source"].get("msg", "")
        system_alert = log["_source"].get("system_alert", 0)

        if system_alert == 0:
            if any(re.search(pattern, msg, re.IGNORECASE) for pattern in critical_error_patterns):
                try:
                    log_time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
                except (ValueError, TypeError):
                    # Si falla, usar la hora actual
                    log_time = datetime.now()
                
                alert_id = f"critical_error_{log['_id']}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
                message = f"Error crítico detectado: {msg}. Log ID: {log['_id']}"
                context = {
                    "log_ids": log.get('_id', ''), 
                    "event_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "msg": msg,
                    "log_time": log_time.strftime("%Y-%m-%d %H:%M:%S")
                }
                update_log(str(context.get("log_ids","")), "system_alert")
                activate_alert(alert_id, message, context, "check_system_errors")


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
        
        alert_type = ""
        # Clasificación de alertas basada en el mensaje
        if "Potente ataque DDos detectado" in alert_message or "Powerful DDoS attack detected" in alert_message:
            alert_type = "Ataque DDoS Detectado"
        elif "Exploración de puertos" in alert_message or "Port Scan" in alert_message:
            alert_type = "Exploración de Puertos Detectada"
        elif "Inyección SQL" in alert_message or "SQL Injection" in alert_message:
            alert_type = "Intento de Inyección SQL"

        timestamp_str = log_entry['_source'].get('timestamp')
        if timestamp_str and alert_type != "":
            try:
                timestamp = datetime.strptime(timestamp_str, "%Y-%m-%dT%H:%M:%S")
                alert_id = f"snort_alert_{sid}_{source_ip}_{dest_ip}_{timestamp.strftime('%Y%m%d%H%M%S')}"
                
                if log_entry['_source'].get('has_alert', 0) == 0:
                    # Verifica si la alerta ya está activa para evitar duplicación
                    if not is_alert_active(alert_id):
                        message = f"{alert_type}: {alert_message} desde {source_ip} hacia {dest_ip} usando {protocol}"
                        context = {
                            "source_ip": source_ip,
                            "dest_ip": dest_ip,
                            "alert_message": alert_message,
                            "protocol": protocol,
                            "alert_type": alert_type,
                            "timestamp": timestamp.isoformat(),
                            "log_ids": log_entry.get('_id', '')
                        }
                        
                        update_log(str(context.get("log_ids","")), "has_alert")
                        
                        activate_alert(alert_id, message, context, "check_snort_alert")
            except ValueError:
                print(f"Formato de fecha inválido en log: {timestamp_str}")


def check_time_related_events(logs):
    """
    Detecta eventos relacionados con la hora o el tiempo, como accesos inusuales fuera del horario laboral 
    o múltiples eventos sospechosos en un corto período.
    Args:
        logs: Logs extraídos de los dispositivos generadores de logs
    """
    event_tracker = {}
    for log in logs:
        log_id = log["_id"]
        timestamp = log["_source"].get("timestamp")
        src_ip = log["_source"].get("src_ip")
        time_related_alert = log["_source"].get("time_related_alert", 0)
        message = log["_source"].get("msg")

        if "pam" in message.lower():
            continue

        if time_related_alert == 0:
            log_time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S")

            # Si el evento está fuera del horario laboral (7:00 am - 6:00 pm)
            if log_time.time() < datetime.strptime("07:00", "%H:%M").time() or log_time.time() > datetime.strptime("18:00", "%H:%M").time():
                if src_ip != 'Desconocido':
                    if src_ip not in event_tracker:
                        event_tracker[src_ip] = []
                        
                    event_tracker[src_ip].append([log_time, log_id])

    for ip, timestamps in event_tracker.items():
        if len(timestamps) >= 5:
            timestamps.sort(key=lambda x: x[0])

            # Recorremos los eventos y validamos si hay más de 5 en el rango de 5 minutos
            for i in range(len(timestamps) - 4):  # -4 porque necesitamos al menos 5 eventos
                time_window_start = timestamps[i][0]  # El primer timestamp del rango
                time_window_end = time_window_start + EVENT_TIME_WINDOW  # Rango de 5 minutos
                
                logs_in_window = [
                    log_id for log_time, log_id in timestamps[i:i+5]
                    if time_window_start <= log_time <= time_window_end
                ]

                if len(logs_in_window) >= 5:
                    alert_id = f"time_related_events_{ip}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
                    message = f"Posible actividad sospechosa: más de 5 eventos desde la IP {ip} fuera del horario laboral o en un corto intervalo de tiempo."
                    
                    context = {
                        "log_ids": logs_in_window, 
                        "source_ip": ip, 
                        "event_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }

                    for log_id in logs_in_window:
                        update_log(str(log_id), "time_related_alert")
                    
                    activate_alert(alert_id, message, context, "check_time_related_events")
                    break

#-------------------------------------------------------------------------------7-----------------------------------------------------------------------------------------------

def check_apt(logs, time_window=30, threshold=3):
    """
    Detecta posibles ataques APT en función de múltiples intentos fallidos seguidos de un intento exitoso.
    Args:
        logs: Lista de logs extraídos.
        time_window: Ventana de tiempo para correlacionar eventos en minutos.
        threshold: Umbral de intentos fallidos para activar una alerta.
    Returns:
        alert_logs: Lista de alertas generadas.
    """
    event_groups = defaultdict(list)

    # Definir patrones de error comunes (sin especificar SO)
    error_patterns = [
        "Failed password",  # Intento de acceso fallido
        "authentication failure",  # Fallo en la autenticación
        "sudo: no tty present",  # Escalada de privilegios fallida
        "Segmentation fault",  # Comportamiento anómalo
        "Logon failure: user account locked",  # Acceso fallido
        "Access Denied",  # Acceso denegado
        "Failed to login",  # Error de inicio de sesión
        "Authentication failed",  # Autenticación fallida
    ]

    # Correlacionar los logs por IP y usuario dentro de un intervalo de tiempo
    for log in logs:
        for other_log in logs:
            if log["_source"].get("src_ip") == other_log["_source"].get("src_ip") and log["_source"].get("hostname") == other_log["_source"].get("hostname"):
                # Verificar si los logs están dentro del intervalo de tiempo
                if abs((log["_source"].get("timestamp") - other_log["_source"].get("timestamp")).total_seconds()) <= time_window * 60:
                    # Comprobar si el mensaje de log contiene patrones de error definidos
                    if any(pattern.lower() in (other_log["_source"].get("msg","")).lower() for pattern in error_patterns):
                        event_groups[(log["_source"].get("src_ip"), log["_source"].get("hostname"))].append((log["_source"].get("timestamp"), log["_source"].get("msg", ""), log["_id"]))

    # Validar la secuencia de eventos repetidos (ejemplo: varios intentos fallidos seguidos de un intento exitoso)
    for group, events in event_groups.items():
        failed_attempts = 0
        success_attempt = False
        log_ids = []
        unmarked_failed_attempts = 0

        # Ordenar los eventos por timestamp
        events_sorted = sorted(events, key=lambda e: e[0])

        for event in events_sorted:
            event_msg = event[1].lower()
            if "failed" in event_msg: 
                # Solo contar intentos fallidos que no están marcados con "login_apt_alert" = 1
                if not any(log["_id"] == event[2] and log["_source"].get("login_apt_alert") == 1 for log in logs):
                    failed_attempts += 1
                    unmarked_failed_attempts += 1  # Contar intentos fallidos no marcados
            elif "success" in event_msg:  # Intento exitoso
                success_attempt = True
            
            # Agregar el ID de log a la lista de log_ids
            log_ids.append(event[2])

        # Si se detectan más de un umbral de intentos fallidos seguidos de un intento exitoso
        if failed_attempts >= threshold and success_attempt:
            alert_id = f"login_apt_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            message = f"Se detectaron {unmarked_failed_attempts} intentos fallidos seguidos de un intento exitoso. Posible ataque APT."

            log_ids = [log["_id"] for log in logs]
            context = {
                "log_ids": log_ids, 
                "source_ip": group[0],
                "user_id": group[1],
                "event_count": len(events),
                "events": events
            }

            for log_id in log_ids:
                if not any(log["_id"] == log_id and log["_source"].get("login_apt_alert") == 1 for log in logs):
                    update_log(log_id, "login_apt_alert")

            activate_alert(alert_id, message, context, "check_apt")

            correlate_file_access(logs)
            correlate_command_execution(logs)
            correlate_access_to_multiple_systems(logs)
            break


def correlate_file_access(logs):
    access_patterns = defaultdict(list)
    
    # Definir la ventana de tiempo en la que se correlacionan los accesos
    time_window = timedelta(minutes=30)
    
    for log in logs:
        timestamp = log["_source"].get("timestamp")
        file_accessed = log["_source"].get("file", "")
        user = log["_source"].get("hostname", "")
        
        try:
            log_time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            log_time = datetime.now()
        
        # Si el archivo y el usuario son relevantes, registrar la información
        if file_accessed and user:
            access_patterns[file_accessed].append({"user": user, "time": log_time})
    
    # Revisar patrones de acceso a archivos
    for file, accesses in access_patterns.items():
        # Si más de X accesos al mismo archivo dentro de la ventana de tiempo
        if len(accesses) > 5:
            first_access_time = accesses[0]["time"]
            last_access_time = accesses[-1]["time"]
            
            if last_access_time - first_access_time <= time_window:
                alert_message = f"Acceso sospechoso al archivo {file} por el usuario {accesses[0]['user']} en un corto período de tiempo."
                alert_id = f"file_access_{file}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
                context = {
                    "file": file,
                    "user": accesses[0]['user'],
                    "first_access_time": first_access_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "last_access_time": last_access_time.strftime("%Y-%m-%d %H:%M:%S"),
                }
                activate_alert(alert_id, alert_message, context, "check_apt")

def correlate_command_execution(logs):
    command_sequences = defaultdict(list)
    
    # Definir la ventana de tiempo en la que se correlacionan los comandos
    time_window = timedelta(minutes=15)
    
    for log in logs:
        timestamp = log["_source"].get("timestamp")
        command = log["_source"].get("command", "")
        user = log["_source"].get("user", "")
        
        try:
            log_time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            log_time = datetime.now()
        
        if command and user:
            command_sequences[user].append({"command": command, "time": log_time})
    
    # Detectar secuencias de comandos ejecutados rápidamente
    for user, commands in command_sequences.items():
        # Si hay más de X comandos ejecutados en rápida sucesión
        if len(commands) > 3:
            first_command_time = commands[0]["time"]
            last_command_time = commands[-1]["time"]
            
            if last_command_time - first_command_time <= time_window:
                alert_message = f"Comandos ejecutados de manera secuencial por el usuario {user} en un corto período de tiempo."
                alert_id = f"command_sequence_{user}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
                context = {
                    "user": user,
                    "first_command": commands[0]['command'],
                    "last_command": commands[-1]['command'],
                    "first_command_time": first_command_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "last_command_time": last_command_time.strftime("%Y-%m-%d %H:%M:%S"),
                }
                activate_alert(alert_id, alert_message, context, "check_apt")

def correlate_access_to_multiple_systems(logs):
    access_patterns = defaultdict(list)
    
    # Definir la ventana de tiempo en la que se correlacionan los accesos
    time_window = timedelta(minutes=30)
    
    for log in logs:
        timestamp = log["_source"].get("timestamp")
        system_accessed = log["_source"].get("system", "")
        user = log["_source"].get("user", "")
        
        try:
            log_time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            log_time = datetime.now()
        
        if system_accessed and user:
            access_patterns[user].append({"system": system_accessed, "time": log_time})
    
    # Revisar patrones de acceso a múltiples sistemas
    for user, accesses in access_patterns.items():
        if len(accesses) > 3:
            first_access_time = accesses[0]["time"]
            last_access_time = accesses[-1]["time"]
            
            if last_access_time - first_access_time <= time_window:
                alert_message = f"Acceso a múltiples sistemas por el usuario {user} en un corto período de tiempo."
                alert_id = f"multiple_systems_access_{user}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
                context = {
                    "user": user,
                    "first_access_time": first_access_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "last_access_time": last_access_time.strftime("%Y-%m-%d %H:%M:%S"),
                }
                activate_alert(alert_id, alert_message, context, "check_apt")

#-------------------------------------------------------------------------------7-----------------------------------------------------------------------------------------------

def check_recon_activity(logs):
    """
    Detecta actividades de recopilación de información (escaneos de puertos, mapeo de redes).
    Args:
        logs: Logs extraídos de Elasticsearch
    """
    # Seguimiento de intentos de escaneo por IP
    scan_tracker = defaultdict(list)

    # Definir palabras clave que podrían indicar un escaneo
    recon_keywords = [
        "port scan", "network scan", "Nmap", "network mapping",  
        "connection attempt", "scan attempt", "suspicious probe",
        "icmp echo request", "icmp probe", "ARP request",
    ]
    
    for log in logs:
        log_id = log["_id"]
        timestamp = log["_source"].get("timestamp")
        src_ip = log["_source"].get("src_ip")
        msg = log["_source"].get("msg", "")
        recon_alert = log["_source"].get("recon_alert", 0)
        
        # Verificar si el mensaje de log contiene alguna palabra clave de escaneo
        if any(keyword.lower() in msg.lower() for keyword in recon_keywords) and recon_alert == 0:  
            log_time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S")
            scan_tracker[src_ip].append(log_time)

    for ip, timestamps in scan_tracker.items():
        if len(timestamps) >= BRUTE_FORCE_THRESHOLD:  # 3 intentos o más
            # Ordenamos los intentos por timestamp
            timestamps.sort()

            # Recorremos los intentos y validamos si hay entre 3 y 5 intentos en el rango de 3 minutos
            for i in range(len(timestamps) - 2):  # Al menos 3 intentos
                time_window_start = timestamps[i]  # El primer timestamp del rango
                time_window_end = time_window_start + timedelta(minutes=3)  # Rango de 3 minutos
                
                # Contamos cuántos logs están dentro del rango de 3 minutos
                count_in_time_window = sum(
                    1 for timestamp in timestamps[i:i+5]  # Revisa los siguientes 5 logs
                    if time_window_start <= timestamp <= time_window_end
                )

                if count_in_time_window >= 3:
                    alert_id = f"recon_activity_{ip}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
                    message = f"Posible actividad de recopilación de información detectada desde la IP {ip}. {len(timestamps)} intentos de escaneo en los últimos 3 minutos."
    
                    log_ids = [log["_id"] for log in logs]
                    context = {
                        "log_ids": log_ids, 
                        "source_ip": ip, 
                        "event_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }

                    for log_id in log_ids:
                        update_log(str(log_id), "recon_alert")
                    activate_alert(alert_id, message, context, "check_recon_activity")


def check_exploitation_attempts(logs):
    """
    Detecta intentos de explotación de vulnerabilidades en software o hardware.
    Args:
        logs: Logs extraídos de Elasticsearch
        es: Instancia de conexión a Elasticsearch
    """
    # Seguimiento de intentos de explotación por IP
    exploitation_tracker = defaultdict(list)

    # Definir palabras clave que podrían indicar un intento de explotación
    exploitation_keywords = [
        "exploit", "attempt", "vulnerability", "exploiting", "exploit attempt", 
        "buffer overflow", "remote code execution", "RCE", "payload", "zero-day", 
        "attempted compromise", "exploit attempt"
    ]
    
    for log in logs:
        log_id = log["_id"]
        timestamp = log["_source"].get("timestamp")
        src_ip = log["_source"].get("src_ip")
        msg = log["_source"].get("msg", "")
        exploitation_alert = log["_source"].get("exploitation_alert", 0)  # Verificar si ya tiene la alerta

        # Verificar si el mensaje de log contiene alguna palabra clave de explotación y si no tiene la alerta
        if any(keyword.lower() in msg.lower() for keyword in exploitation_keywords) and exploitation_alert == 0:
            log_time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S")
            exploitation_tracker[src_ip].append(log_time)

    for ip, timestamps in exploitation_tracker.items():
        if len(timestamps) >= 3:  # Al menos 3 intentos
            # Ordenamos los intentos por timestamp
            timestamps.sort()

            # Recorremos los intentos y validamos si hay entre 3 intentos en un rango de 5 minutos
            for i in range(len(timestamps) - 2):  # Al menos 3 intentos
                time_window_start = timestamps[i]  # El primer timestamp del rango
                time_window_end = time_window_start + timedelta(minutes=5)  # Rango de 5 minutos
                
                # Contamos cuántos logs están dentro del rango de 5 minutos
                count_in_time_window = sum(
                    1 for timestamp in timestamps[i:i+3]  # Revisa los siguientes 3 logs
                    if time_window_start <= timestamp <= time_window_end
                )

                if count_in_time_window >= 3:
                    alert_id = f"exploitation_attempt_{ip}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
                    message = f"Posible intento de explotación detectado desde la IP {ip}. {len(timestamps)} intentos de explotación en los últimos 5 minutos."
    
                    log_ids = [log["_id"] for log in logs]
                    context = {
                        "log_ids": log_ids, 
                        "source_ip": ip, 
                        "event_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }

                    for log_id in log_ids:
                        update_log(str(log_id), "exploitation_alert")  # Actualizamos el log para marcarlo como procesado
                    activate_alert(alert_id, message, context, "check_exploitation_attempts")


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
            log_time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S")
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
            activate_alert(alert_id, message, context, "check_unauthorized_access")

def clean_old_malware_entries(device, interval):
    """
    Limpia entradas antiguas de eventos de malware para un dispositivo.
    """
    current_time = datetime.now()
    malware_tracker[device] = [
        t for t in malware_tracker[device] 
        if current_time - t <= interval
    ]

def check_malware_activity(logs):
    """
    Detecta posibles actividades de malware basadas en eventos registrados en los logs.
    Args:
        logs: Logs extraídos de Elasticsearch
    """
    for log in logs:
        timestamp = log["_source"].get("timestamp")
        device_id = log["_source"].get("device_id")
        msg = log["_source"].get("msg", "")
        
        # Aquí podrías incluir más condiciones para detectar comportamientos típicos de malware
        if "file access" in msg.lower() or "suspicious connection" in msg.lower():
            log_time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S")
            malware_tracker[device_id].append(log_time)

    for device, timestamps in malware_tracker.items():
        clean_old_malware_entries(device, MALWARE_TIME_WINDOW)

        if len(timestamps) >= MALWARE_ACTIVITY_THRESHOLD:
            alert_id = f"malware_activity_{device}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            message = f"Posible actividad de malware detectada en el dispositivo {device}. {len(timestamps)} eventos sospechosos en los últimos {MALWARE_TIME_WINDOW} minutos."
            context = {
                "log_ids": [log["_id"] for log in logs], 
                "device_id": device, 
                "event_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            activate_alert(alert_id, message, context, "check_malware_activity")


def clean_old_attempts(user, interval):
    """
    Limpia los intentos de inicio de sesión fallidos antiguos para un usuario.
    """
    current_time = datetime.now()
    user_attempt_tracker[user] = [
        attempt for attempt in user_attempt_tracker[user] 
        if current_time - attempt <= interval
    ]

def check_user_behavior_anomaly(logs):
    """
    Detecta comportamiento anómalo de usuarios basado en múltiples intentos de inicio de sesión fallidos.
    Args:
        logs: Logs extraídos de Elasticsearch
    """
    for log in logs:
        timestamp = log["_source"].get("timestamp")
        username = log["_source"].get("username")
        msg = log["_source"].get("msg", "")

        # Verificar si el log indica un intento de inicio de sesión fallido
        if "authentication failed" in msg.lower():
            log_time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
            user_attempt_tracker[username].append(log_time)

    for user, attempts in user_attempt_tracker.items():
        clean_old_attempts(user, TIME_WINDOW)

        # Si el número de intentos fallidos supera el umbral
        if len(attempts) >= FAILED_ATTEMPT_THRESHOLD:
            alert_id = f"user_behavior_anomaly_{user}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            message = f"Comportamiento anómalo detectado para el usuario {user}: {len(attempts)} intentos de inicio de sesión fallidos en los últimos {TIME_WINDOW.seconds // 60} minutos."
            context = {
                "log_ids": [log["_id"] for log in logs],
                "username": user,
                "event_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            activate_alert(alert_id, message, context, "check_user_behavior_anomaly")


def check_data_exfiltration(logs):
    """
    Detecta transferencias masivas de datos hacia ubicaciones externas.
    Args:
        logs: Logs extraídos de Elasticsearch
    """
    for log in logs:
        timestamp = log["_source"].get("timestamp")
        device_id = log["_source"].get("device_id")
        data_size = log["_source"].get("data_size", 0)  # Asegúrate de que los logs tengan el campo `data_size`
        
        if data_size > 0:  # Solo procesamos los logs que tienen tamaño de datos
            log_time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
            
            # Inicializar o actualizar el tracker de transferencia para el dispositivo
            if device_id not in data_transfer_tracker or data_transfer_tracker[device_id]["timestamp"] is None:
                data_transfer_tracker[device_id]["timestamp"] = log_time
                data_transfer_tracker[device_id]["size"] = data_size
            else:
                # Si el log es dentro del intervalo de 10 minutos, sumar el tamaño de los datos
                if log_time - data_transfer_tracker[device_id]["timestamp"] <= TIME_WINDOW:
                    data_transfer_tracker[device_id]["size"] += data_size
                else:
                    # Si la transferencia está fuera del intervalo, reiniciar el contador
                    data_transfer_tracker[device_id]["timestamp"] = log_time
                    data_transfer_tracker[device_id]["size"] = data_size

            # Verificar si la transferencia excede el umbral
            if data_transfer_tracker[device_id]["size"] > TRANSFER_THRESHOLD:
                alert_id = f"data_exfiltration_{device_id}_{log_time.strftime('%Y%m%d%H%M%S')}"
                message = f"Posible exfiltración de datos detectada desde el dispositivo {device_id}. {data_transfer_tracker[device_id]['size'] / (1024 * 1024 * 1024)} GB transferidos en los últimos {TIME_WINDOW.seconds // 60} minutos."
                
                # Crear el contexto de la alerta
                context = {
                    "log_ids": [log["_id"] for log in logs],
                    "device_id": device_id,
                    "data_size": data_transfer_tracker[device_id]["size"],
                    "event_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }

                # Activar la alerta
                activate_alert(alert_id, message, context, "check_data_exfiltration")

                # Reiniciar el tracker después de generar la alerta para evitar duplicación
                data_transfer_tracker[device_id]["size"] = 0
                data_transfer_tracker[device_id]["timestamp"] = None


def check_security_configuration_changes(logs):
    """
    Detecta cambios en las configuraciones de seguridad (firewalls, servidores de seguridad, autenticación).
    Args:
        logs: Logs extraídos de Elasticsearch
    """
    for log in logs:
        timestamp = log["_source"].get("timestamp")
        device_id = log["_source"].get("device_id")
        msg = log["_source"].get("msg", "")
        
        # Buscamos cambios en configuraciones de seguridad
        if any(keyword in msg.lower() for keyword in ["changed", "updated", "modified", "configured"]):
            log_time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
            alert_id = f"security_config_change_{device_id}_{log_time.strftime('%Y%m%d%H%M%S')}"
            message = f"Cambio detectado en configuración de seguridad en el dispositivo {device_id}: {msg}"
            context = {
                "log_ids": [log["_id"] for log in logs],
                "device_id": device_id,
                "event_time": log_time.strftime("%Y-%m-%d %H:%M:%S")
            }
            activate_alert(alert_id, message, context, "check_security_configuration_changes")


def clean_old_entries(ip, interval):
    """
    Limpia entradas antiguas de intentos de conexión para una IP.
    """
    current_time = datetime.now()
    internal_connection_tracker[ip] = [
        t for t in internal_connection_tracker[ip]
        if current_time - t <= interval
    ]

def check_suspicious_internal_connections(logs):
    """
    Detecta conexiones internas sospechosas basadas en intentos de conexión repetidos en poco tiempo.
    Args:
        logs: Logs extraídos de Elasticsearch
    """
    for log in logs:
        timestamp = log["_source"].get("timestamp")
        src_ip = log["_source"].get("src_ip")
        dest_ip = log["_source"].get("dest_ip")
        msg = log["_source"].get("msg", "")
        
        # Filtra solo las conexiones internas (tienen que ser entre dispositivos internos)
        if src_ip != dest_ip:  # Asegurarse de que no sea una conexión con uno mismo
            log_time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
            # Se registran los intentos de conexión de las IPs internas
            internal_connection_tracker[(src_ip, dest_ip)].append(log_time)

    for (src_ip, dest_ip), timestamps in internal_connection_tracker.items():
        clean_old_entries((src_ip, dest_ip), TIME_WINDOW)

        if len(timestamps) >= INTERNAL_CONNECTIONS_THRESHOLD:
            alert_id = f"suspicious_internal_connection_{src_ip}_{dest_ip}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            message = f"Posible conexión interna sospechosa detectada entre las IPs {src_ip} y {dest_ip}. {len(timestamps)} intentos en los últimos {TIME_WINDOW} minutos."
            context = {
                "log_ids": [log["_id"] for log in logs],
                "source_ip": src_ip,
                "dest_ip": dest_ip,
                "event_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            activate_alert(alert_id, message, context, "check_suspicious_internal_connections")


def clean_old_application_entries(device_id, interval):
    """
    Limpia entradas antiguas para una aplicación en un intervalo de tiempo.
    """
    current_time = datetime.now()
    app_event_tracker[device_id] = [
        t for t in app_event_tracker[device_id] 
        if current_time - t <= interval
    ]

def check_application_specific_events(logs):
    """
    Detecta eventos críticos en aplicaciones específicas como accesos fallidos o actividad sospechosa.
    Args:
        logs: Logs extraídos de Elasticsearch.
    """
    for log in logs:
        timestamp = log["_source"].get("timestamp")
        device_id = log["_source"].get("device_id")
        msg = log["_source"].get("msg", "")
        
        # Verificamos si el evento está relacionado con un acceso fallido en una base de datos o sistema ERP
        if "access denied" in msg.lower() or "failed login" in msg.lower():  
            log_time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
            app_event_tracker[device_id].append(log_time)

    # Procesamos los eventos y verificamos si se alcanzó el umbral
    for device_id, timestamps in app_event_tracker.items():
        clean_old_application_entries(device_id, TIME_WINDOW)

        if len(timestamps) >= APPLICATION_EVENT_THRESHOLD:
            alert_id = f"app_event_{device_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            message = f"Posible acceso no autorizado o actividad sospechosa detectada en {device_id}. {len(timestamps)} eventos de acceso fallido en los últimos {TIME_WINDOW} minutos."
            context = {
                "log_ids": [log["_id"] for log in logs], 
                "device_id": device_id, 
                "event_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            activate_alert(alert_id, message, context, "check_application_specific_events")