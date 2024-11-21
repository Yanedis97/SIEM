-- Estructura de la base de datos para SQLite

CREATE TABLE alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  second_id TEXT NOT NULL,
  log_ids TEXT NOT NULL DEFAULT '[]',
  alert_type TEXT NOT NULL,
  message TEXT,
  source_ip TEXT,
  dest_ip TEXT,
  severity TEXT,
  context TEXT,
  alert_category INTEGER,
  status INTEGER,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE alert_status (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL
);

-- Insertamos los tres estados posibles
INSERT INTO alert_status (code,name) VALUES 
  ('active', 'Activa'), 
  ('revised', 'Revisada'), 
  ('ended','Finalizada');


CREATE TABLE alerts_categories (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  status INTEGER DEFAULT 1,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO alerts_categories (code, name, description, status) VALUES
  ('check_brute_force', 'Detección de Fuerza Bruta', 'Los ataques de fuerza bruta se detectan con un umbral de 3 a 10 intentos fallidos en 5 minutos. Recomendado para redes críticas.', 1),
  ('check_privilege_change', 'Detección de Cambios de Privilegio', 'Cambios de privilegios deben registrarse inmediatamente. Sin umbrales.', 1),
  ('check_suspicious_traffic', 'Detección de Tráfico Sospechoso', 'Tráfico anómalo con umbral de más de 1000 eventos en 10 minutos. Ajustable según el tamaño de la red.', 1),
  ('check_system_errors', 'Errores del Sistema', 'Cada error crítico debería alertar en tiempo real para respuesta rápida.', 1),
  ('check_snort_alert', 'Detección de Alertas Snort', 'Las alertas de Snort deben manejarse en tiempo real.', 1),
  ('check_time_related_events', 'Eventos Relacionados con el Tiempo', 'Detecta actividad sospechosa con más de 5 eventos de la misma IP en 5 minutos.', 1),
  ('check_apt', 'Detección de APT', 'Detecta APTs con un umbral de más de 20 eventos en 30 minutos. Ajustable según criticidad de la red.', 1),
  ('check_recon_activity', 'Detección de Actividad de Reconocimiento', 'Detecta escaneos con umbral de 3 a 5 intentos en 3 minutos.', 1),
  ('check_exploitation_attempts', 'Intentos de Explotación', 'Umbral de más de 3 intentos de explotación en 5 minutos.', 1),
  ('check_unauthorized_access', 'Detección de Acceso No Autorizado', 'Detecta intentos de acceso no autorizado con umbral de más de 5 intentos fallidos en 3 minutos.', 1),
  ('malware_activity_detection', 'Detección de Actividad de Malware', 'Identifica eventos de comportamiento de malware, como accesos anómalos a archivos de sistema.', 1),
  ('user_behavior_anomaly_detection', 'Detección de Comportamiento Anómalo de Usuario', 'Detecta cambios bruscos en el comportamiento de usuarios específicos.', 1),
  ('data_exfiltration_detection', 'Detección de Exfiltración de Datos', 'Monitorea la transferencia de grandes volúmenes de datos hacia ubicaciones externas.', 1),
  ('security_configuration_changes', 'Modificaciones en Configuración de Seguridad', 'Detecta cambios en configuraciones críticas de seguridad en tiempo real.', 1),
  ('suspicious_internal_connections', 'Detección de Conexiones Internas Sospechosas', 'Monitorea conexiones entre dispositivos internos que son inusuales.', 1),
  ('application_specific_event_monitoring', 'Monitoreo de Eventos de Aplicaciones Específicas', 'Detecta eventos de aplicaciones críticas, como bases de datos o sistemas ERP.', 1);

CREATE TABLE devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_name TEXT NOT NULL,
  ip_address TEXT,
  device_type TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE device_types (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  type_name TEXT NOT NULL,
  status INTEGER DEFAULT 1
);

CREATE TABLE log_levels (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  level_name TEXT NOT NULL,
  status INTEGER DEFAULT 1
);

CREATE TABLE roles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  role_name TEXT NOT NULL,
  status INTEGER DEFAULT 1
);

CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT DEFAULT 'viewer',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Inserción de datos iniciales para log_levels
INSERT INTO log_levels (id, level_name, status) VALUES
(1, 'Emergency', 1),
(2, 'Alert', 1),
(3, 'Critical', 1),
(4, 'Error', 1),
(5, 'Warning', 1),
(6, 'Notice', 1),
(7, 'Info', 1),
(8, 'Debug', 1);

-- Inserción de datos iniciales para roles
INSERT INTO roles (role_name, status) VALUES
('admin', 1),
('analyst', 1),
('viewer', 1);