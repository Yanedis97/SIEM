-- Estructura de la base de datos para SQLite

CREATE TABLE alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  log_id INTEGER NOT NULL,
  alert_type TEXT NOT NULL,
  severity TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

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
  role TEXT DEFAULT 'user',
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
('Admin', 1),
('Analyst', 1),
('Viewer', 1);