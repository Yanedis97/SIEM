import uuid
import re
import json
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
#from main import save_logs_to_elasticsearch


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

    def add_pattern(self, pattern, log_type):
        self.patterns.append((pattern, log_type))

    def normalize_line(self, line):
        for pattern, log_type in self.patterns:
            match = re.match(pattern, line)
            if match:
                log_data = match.groupdict()
                log_data['type'] = log_type
                return log_data
            
        # Manejar logs no reconocidos
        return {"raw_log": line, "type": "unrecognized", "msg": line.strip()}
    
    def save_logs_to_elasticsearch(self, logs):
        """
        Guarda los logs normalizados en Elasticsearch.
        """
        for log in logs:
            log_json = json.dumps(log)
            # Verificar si el ID del log ya existe en Elasticsearch
            existing_log = self.elasticsearch.get(index="logs", id=log["id"], ignore=[404])

            # Si el log no existe, lo guardamos
            if not existing_log['found']:    
                self.elasticsearch.index(index="logs", id=log["id"], body=log_json)

    def normalize_file(self, input_file):
        with open(input_file, "r") as f:
            lines = f.readlines()

            normalized_logs = []
            for line in lines:
                normalized_log = self.normalize_line(line)
                print(f"normalize_log: {normalized_log}")

                if normalized_log is not None:
                    # Generar un UUID único para el log
                    log_id = str(uuid.uuid4())
                    normalized_log["id"] = log_id

                    normalized_logs.append(normalized_log)

            # Guardar los logs en Elasticsearch (evitar duplicados basados en ID)
            self.save_logs_to_elasticsearch(normalized_logs)


def start_monitoring(log_directory, es):
    normalizer = LogNormalizer(es)
    # Agregar los patrones de normalización conocidos
    normalizer.add_pattern(
        r'<(?P<pri>\d+)>.*snort\[\d+\]: \[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\] (?P<msg>.+?) \{(?P<protocol>\w+)\} (?P<src_ip>\d+\.\d+\.\d+\.\d+)(?::\d+)? -> (?P<dst_ip>\d+\.\d+\.\d+\.\d+)(?::\d+)?',
        'snort'
    )

    normalizer.add_pattern(
        r'<(?P<pri>\d+)>(?P<seq>\d+): \*(?P<timestamp>\S+ \d+ \d+:\d+:\d+\.\d+): \%(?P<facility>[\w-]+)-(?P<severity>\d+)-(?P<mnemonic>[\w-]+): (?P<msg>.+)',
        'router'
    )

    normalizer.add_pattern(
        r'<(?P<pri>\d+)>.*CRON\[\d+\]: (?P<msg>.+)',
        'cron'
    )

    normalizer.add_pattern(
        r'<(?P<pri>\d+)>.*snapd\[\d+\]: (?P<msg>.+)',
        'snapd'
    )

    event_handler = LogHandler(normalizer)
    observer = Observer()
    observer.schedule(event_handler, path=log_directory, recursive=False)
    observer.start()
    print(f"Monitoreando cambios en el directorio: {log_directory}")

    #para ver la informacion que esta guardada en el elasticsearch
    # response = es.search(index="logs", body={"query": {"match_all": {}}})
    # print("Resultados de la consulta:", response)

    try:
        while True:
            pass  # Mantener el hilo activo
    except KeyboardInterrupt:
        observer.stop()
    observer.join()