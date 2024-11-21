from datetime import datetime, timedelta
from collections import defaultdict
from database.db_connection import SessionLocal
from app.models.alerts import Alerts
from app.models.alerts_categories import AlertsCategory
from app.services.log_service import update_log
import json

# Parámetros de reglas de correlación
TIME_RELATION_THRESHOLD = 5  # en minutos
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
            dest_ip = context.get("source_ip",None),
            severity = 1,  
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
    for log in logs:
        log_id = log["_id"]
        timestamp = log["_source"].get("timestamp")
        src_ip = log["_source"].get("src_ip")
        msg = log["_source"].get("msg", "")
        auth_alert = log["_source"].get("auth_alert", 0)
        
        if "authentication failure" in msg.lower() or "failed password" in msg.lower():  
            if auth_alert == 0:
                log_time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
                login_tracker[src_ip].append(log_time, log_id)

    for ip, timestamps_and_ids in login_tracker.items():
        
        if len(timestamps_and_ids) >= BRUTE_FORCE_THRESHOLD:
            
            # Ordenamos los intentos por timestamp
            timestamps_and_ids.sort(key=lambda x: x[0])

            # Recorremos los intentos y validamos si hay 3 en el rango de 5 minutos
            for i in range(len(timestamps_and_ids) - 2):  # -2 porque necesitamos al menos 3 intentos
                time_window_start = timestamps_and_ids[i][0]  # El primer timestamp del rango
                time_window_end = time_window_start + timedelta(minutes=5)  # Rango de 5 minutos
                
                # Contamos cuántos logs están dentro del rango de 5 minutos
                count_in_time_window = sum(
                    1 for timestamp, _ in timestamps_and_ids[i:i+3]  # Revisa los siguientes 3 logs
                    if time_window_start <= timestamp <= time_window_end
                )

                if count_in_time_window >= 3:
                    alert_id = f"brute_force_{ip}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
                    message = f"Posible ataque de fuerza bruta detectado desde la IP {ip}. {len(timestamps_and_ids)} intentos fallidos en los últimos {TIME_RELATION_THRESHOLD} minutos."
    
                    log_ids = [log["_id"] for log in logs]
                    context = {
                        "log_ids": log_ids, 
                        "source_ip": ip, 
                        "event_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }

                    for log_id in log_ids:
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
        
        if "privilege change" in msg.lower():
            if has_alert == 0:
                try:
                    log_time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
                except ValueError:
                    continue 
                
                alert_id = f"privilege_change_{log['_id']}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
                message = f"Cambio de privilegio detectado: {msg}. Log ID: {log['_id']}"
                context = {
                    "log_ids": [log["_id"]],
                    "event_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "msg": msg,
                    "log_time": log_time.strftime("%Y-%m-%d %H:%M:%S")
                }
                update_log(str(context.get("log_ids","")), "has_alert")
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
        if timestamp_str:
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
            activate_alert(alert_id, message, context, "check_time_related_events")


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
            activate_alert(alert_id, message, context, "check_apt")


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
            activate_alert(alert_id, message, context, "check_recon_activity")


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
            log_time = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
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