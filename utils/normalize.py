import uuid
import re
import time
import json
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from watchdog.observers.polling import PollingObserver


class LogHandler(FileSystemEventHandler):
    def __init__(self, normalizer):
        self.normalizer = normalizer

    def on_modified(self, event):
        if event.src_path.endswith(".log"):
            print(f"Archivo modificado: {event.src_path}")
            self.normalizer.normalize_file(event.src_path)


class LogNormalizer:
    def __init__(self, es):
        self.elasticsearch = es
        self.patterns = []
        self.processed_lines = {}  # Diccionario para guardar el progreso de cada archivo
        # self.incomplete_log = {}

    def add_pattern(self, pattern, log_type):
        self.patterns.append((pattern, log_type))

    def normalize_line(self, line):
        # Si ya estamos en un log multilinea (incompleto), lo añadimos
        # if not self.incomplete_log:
        #     self.incomplete_log['msg'] += "\n" + line.strip()
        #     if self.is_end_of_multiline_log(line):
        #         log_data = self.incomplete_log
        #         self.incomplete_log = {}  # Restablecer después de completar el log
        #         log_data['type'] = 'server_windows'  # El tipo de log específico para Windows
        #         return log_data
        #     return None

        # Revisar los patrones para logs de una sola línea
        for pattern, log_type in self.patterns:
            match = re.match(pattern, line)
            print(">>>", match)
            if match:
                log_data = match.groupdict()
                log_data['type'] = log_type

                # Establecer valor predeterminado para 'src_ip'
                log_data['src_ip'] = log_data.get('src_ip', "Desconocido")

                if 'timestamp' not in log_data:
                    log_data['timestamp'] = "Desconocido"
                else:
                    try:
                        datetime.fromisoformat(log_data['timestamp'])
                    except ValueError:
                        try:
                            timestamp_str = log_data['timestamp']
                            current_year = datetime.now().year
                            timestamp_with_year = f"{current_year} {timestamp_str}"

                            log_data['timestamp'] = datetime.strptime(timestamp_with_year, "%Y %b %d %H:%M:%S").isoformat()
                        except ValueError as e:
                            print(f"Error al parsear timestamp: {e}, valor original: {timestamp_str}")
                            log_data['timestamp'] = "Desconocido"
                
                # Verificar si el log es desechable
                if self.is_desechable_log(log_data):
                    print(f"Log desechable ignorado: {log_data}")
                    return None  # Ignorar este log

                return log_data

        # Logs no reconocidos
        return {"raw_log": line, "type": "unrecognized", "msg": line.strip()}

    def is_end_of_multiline_log(self, line):
        # Aquí definimos un patrón para identificar el final del log multilinea
        # En el caso de los logs de Windows, podría ser cuando aparece un nuevo timestamp al inicio de la línea
        return bool(re.match(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', line))
    
    def save_logs_to_elasticsearch(self, logs):
        for log in logs:
            if 'timestamp' not in log or log['timestamp'] == "Desconocido":
                print("Timestamp faltante en log, omitiendo:", log)
                continue

            log_json = json.dumps(log)
            self.elasticsearch.index(index="logs", id=log["id"], body=log_json)
            print(">>>>Guardado: ", log_json)
    
    def is_desechable_log(self, log_data):
        """
        Determina si un log es considerado desechable, como logs de limpieza de systemd o anacron.
        """
        if 'program' in log_data:
            program = log_data['program']
            # Patrón para identificar logs de systemd y anacron, ahora buscando en el campo 'program'
            disposable_patterns = [
                r"systemd\[.*\]:.*Cleanup of Temporary Directories.*",
                r".*anacron\[.*\]:.*Anacron.*"
            ]
            for pattern in disposable_patterns:
                if re.match(pattern, program):
                    return True
        return False


    def normalize_file(self, input_file):
        # Leer el archivo desde la última posición procesada de manera segura
        last_position = self.processed_lines.get(input_file, 0)

        with open(input_file, "r") as f:
            f.seek(last_position)  # Ir a la última posición procesada

            normalized_logs = []
            for line in f:
                normalized_log = self.normalize_line(line)
                print(f"normalize_log: {normalized_log}")

                if normalized_log is not None:
                    log_id = str(uuid.uuid4())
                    normalized_log["id"] = log_id
                    normalized_logs.append(normalized_log)

            self.save_logs_to_elasticsearch(normalized_logs)

            self.processed_lines[input_file] = f.tell()


def start_monitoring(log_directory, es):
    normalizer = LogNormalizer(es)
    normalizer.add_pattern(
        r'<(?P<pri>\d+)>(?P<timestamp>\S+ +\d+ \d+:\d+:\d+).*snort\[\d+\]: \[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\] (?P<msg>.+?) \{(?P<protocol>\w+)\} (?P<src_ip>\d+\.\d+\.\d+\.\d+)(?::\d+)? -> (?P<dst_ip>\d+\.\d+\.\d+\.\d+)(?::\d+)?',
        'snort'
    )

    normalizer.add_pattern(
        r'<(?P<pri>\d+)>(?P<seq>\d+): \*(?P<timestamp>\S+ \d+ \d+:\d+:\d+\.\d+): \%(?P<facility>[\w-]+)-(?P<severity>\d+)-(?P<mnemonic>[\w-]+): (?P<msg>.+)',
        'router'
    )

    normalizer.add_pattern(
        r'(?P<timestamp>\w+ \d+ \d+:\d+:\d+)\s+(?P<hostname>\S+)\s+(?P<service>\S+): (?P<msg>.+)', 
        'linux_log'
    )

    normalizer.add_pattern(
        r'(?P<level>\w+)\s+(?P<timestamp>\d{1,2}/\d{1,2}/\d{4} \d{1,2}:\d{2}:\d{2} [ap]\. [m]+\.\w+)\s+(?P<source>[\w\s-]+)\s+(?P<event_id>\d+)\s+(?P<category>\w+)\s+"(?P<msg>.+)"',
        'windows_event'
    )

    normalizer.add_pattern(
        r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[(?P<level>\w+)\] (?P<msg>.+)', 
        'hp_support_assistant'
    )

    normalizer.add_pattern(
        r'(?P<index>\d+)\s+(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<entry_type>\w+)\s+(?P<source>[\w\s\(\)\-]+)\s+(?P<instance_id>\d+)\s+(?P<msg>.+)',
        'powershell_log'
    )

    normalizer.add_pattern(
        r'(?P<timestamp>\w{3} \d{1,2} \d{2}:\d{2}:\d{2}) (?P<hostname>\S+) (?P<service>\S+)\[(?P<pid>\d+)\]: (?P<msg>.+?)(?: from (?P<src_ip>\d+\.\d+\.\d+\.\d+))?(?: port \d+)?(?: ssh2)?',
        'server_linux'
    )

    normalizer.add_pattern(
        r"<(?P<priority>\d+)>\s*(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+(?P<program>\w+):\s*\[\s*(?P<kernel_timestamp>[\d.]+)\]\s*(?P<msg>.+)",
        'linux_log'
    )
    
    normalizer.add_pattern(
        r"<(?P<priority>\d+)>\s*(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+(?P<program>\w+)\[(?P<pid>\d+)\]:\s+(?P<subsystem>[\w_]+)\((?P<module>[\w:]+)\):\s+(?P<msg>.+)", 'linux_log')

    normalizer.add_pattern(
        r"<(?P<priority>\d+)>\s*(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+(?P<program>\w+)\[(?P<pid>\d+)\]:\s+(?P<msg>.+?)\s+from\s+(?P<src_ip>\d+\.\d+\.\d+\.\d+)","linux_log")


    event_handler = LogHandler(normalizer)
    observer = PollingObserver()
    observer.schedule(event_handler, path=log_directory, recursive=False)
    observer.start()
    print(f"Monitoreando cambios en el directorio: {log_directory}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()