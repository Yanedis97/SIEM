import uuid
import re
import time
import json
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


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

    def add_pattern(self, pattern, log_type):
        self.patterns.append((pattern, log_type))

    def normalize_line(self, line):
        for pattern, log_type in self.patterns:
            match = re.match(pattern, line)
            if match:
                log_data = match.groupdict()
                log_data['type'] = log_type

                if 'timestamp' not in log_data:
                    log_data['timestamp'] = "Desconocido"
                else:
                    try:
                        datetime.fromisoformat(log_data['timestamp'])
                    except ValueError:
                        try:
                            timestamp_str = log_data['timestamp']
                            
                            # Agregar el año actual si no está presente
                            current_year = datetime.now().year
                            timestamp_with_year = f"{current_year} {timestamp_str}"

                            log_data['timestamp'] = datetime.strptime(timestamp_with_year, "%Y %b %d %H:%M:%S").isoformat()
                        except ValueError as e:
                            print(f"Error al parsear timestamp: {e}, valor original: {timestamp_str}")
                            log_data['timestamp'] = "Desconocido"

                return log_data

        # Logs no reconocidos
        return {"raw_log": line, "type": "unrecognized", "msg": line.strip()}

    def save_logs_to_elasticsearch(self, logs):
        for log in logs:
            if 'timestamp' not in log or log['timestamp'] == "Desconocido":
                print("Timestamp faltante en log, omitiendo:", log)
                continue

            log_json = json.dumps(log)
            self.elasticsearch.index(index="logs", id=log["id"], body=log_json)
            print(">>>>Guardado: ", log_json)

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
        r'(?P<level>\w+)\s+(?P<timestamp>\d{1,2}/\d{1,2}/\d{4} \d{1,2}:\d{2}:\d{2} [ap]\. [m]+\.\w+)\s+(?P<source>[\w\s-]+)\s+(?P<event_id>\d+)\s+(?P<category>\w+)\s+"(?P<message>.+)"',
        'windows_event'
    )

    normalizer.add_pattern(
        r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[(?P<level>\w+)\] (?P<msg>.+)', 
        'hp_support_assistant'
    )

    normalizer.add_pattern(
        r'(?P<index>\d+)\s+(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<entry_type>\w+)\s+(?P<source>[\w\s\(\)\-]+)\s+(?P<instance_id>\d+)\s+(?P<message>.+)',
        'powershell_log'
    )

    event_handler = LogHandler(normalizer)
    observer = Observer()
    observer.schedule(event_handler, path=log_directory, recursive=False)
    observer.start()
    print(f"Monitoreando cambios en el directorio: {log_directory}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()