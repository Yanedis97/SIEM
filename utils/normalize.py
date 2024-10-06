import json
import re
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class LogHandler(FileSystemEventHandler):
    def __init__(self, normalizer):
        self.normalizer = normalizer

    def on_modified(self, event):
        if event.src_path.endswith(".log"):
            print(f"Archivo modificado: {event.src_path}")
            self.normalizer.normalize_file(event.src_path, event.src_path.replace(".log", "_normalized.json"))

class LogNormalizer:
    def __init__(self):
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
        return None

    def normalize_file(self, input_file, output_file):
        normalized_logs = []
        with open(input_file, 'r') as infile:
            for line in infile:
                log_data = self.normalize_line(line)
                if log_data:
                    print(f"Línea normalizada: {log_data}")
                    normalized_logs.append(log_data)
        with open(output_file, 'w') as outfile:
            json.dump(normalized_logs, outfile, indent=4)
        print(f"Archivo normalizado guardado en: {output_file}")

def start_monitoring(log_directory):
    normalizer = LogNormalizer()
    # Aquí puedes agregar los patrones de normalización conocidos
    normalizer.add_pattern(r'<(?P<pri>\d+)>(?P<seq>\d+): \*(?P<timestamp>\S+ \d+ \d+:\d+:\d+\.\d+): \%(?P<facility>[\w-]+)-(?P<severity>\d+)-(?P<mnemonic>[\w-]+): (?P<msg>.+)', 'router')
    #normalizer.add_pattern(r'...')  # Puedes añadir más patrones

    event_handler = LogHandler(normalizer)
    observer = Observer()
    observer.schedule(event_handler, path=log_directory, recursive=False)
    observer.start()
    print(f"Monitoreando cambios en el directorio: {log_directory}")

    try:
        while True:
            pass  # Mantener el hilo activo
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
