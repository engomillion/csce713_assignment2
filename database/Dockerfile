FROM mysql:8.0

# Copy initialization script
COPY init.sql /docker-entrypoint-initdb.d/

# Copy MySQL configuration that disables SSL
COPY mysql.cnf /etc/mysql/conf.d/

EXPOSE 3306
