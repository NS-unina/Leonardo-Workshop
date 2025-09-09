CREATE TABLE protocols (
  protocol TEXT PRIMARY KEY,
  layer    TEXT NOT NULL
);

CREATE TABLE physical_layer (
  protocol TEXT NOT NULL REFERENCES protocols(protocol) ON UPDATE CASCADE ON DELETE CASCADE,
  name     TEXT NOT NULL,
  PRIMARY KEY (protocol, name)
);

CREATE TABLE weakness_physical_layer (
  vulnerability TEXT PRIMARY KEY,
  protocol      TEXT NOT NULL REFERENCES protocols(protocol) ON UPDATE CASCADE ON DELETE RESTRICT,
  zone          TEXT NOT NULL
);

CREATE TABLE attack_goals (
  id SERIAL PRIMARY KEY,
  goal_type TEXT NOT NULL,
  target TEXT NOT NULL
);

-- Seed data
INSERT INTO protocols (protocol, layer)
VALUES ('nmea0183', 'c_06_gnss_source');
VALUES ('osnma', 'c_06_gnss_source');

INSERT INTO physical_layer (protocol, name)
VALUES ('nmea0183', 'c_05_geolocation_system');
VALUES ('osnma', 'c_05_geolocation_system');

INSERT INTO weakness_physical_layer (vulnerability, protocol, zone)
VALUES ('ac7', 'nmea0183', 'coverZone');

INSERT INTO attack_goals (goal_type, target)
VALUES ('canSpoof', 'fb_03_gps_position_nmea0183');