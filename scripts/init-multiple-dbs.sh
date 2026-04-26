#!/bin/bash
# Creates the exact databases and users needed by each service.
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" << 'SQL'
-- auth service: user=auth, db=authdb
CREATE USER auth WITH PASSWORD 'secret';
CREATE DATABASE authdb OWNER auth;
GRANT ALL PRIVILEGES ON DATABASE authdb TO auth;

-- audit service also uses authdb; inherits auth privileges so
-- golang-migrate schema_migrations table is accessible to both.
CREATE USER audit WITH PASSWORD 'secret';
GRANT auth TO audit;
GRANT ALL PRIVILEGES ON DATABASE authdb TO audit;

-- trust service: user=trust, db=trustdb
CREATE USER trust WITH PASSWORD 'secret';
CREATE DATABASE trustdb OWNER trust;
GRANT ALL PRIVILEGES ON DATABASE trustdb TO trust;

-- keycloak: user=keycloak, db=keycloak
CREATE USER keycloak WITH PASSWORD 'secret';
CREATE DATABASE keycloak OWNER keycloak;
GRANT ALL PRIVILEGES ON DATABASE keycloak TO keycloak;
SQL

echo "Databases and users created successfully."
