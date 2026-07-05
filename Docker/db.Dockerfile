FROM mysql:8.0

# Copy SQL schemas into docker initialization entrypoint
COPY database/schema.sql /docker-entrypoint-initdb.d/1_schema.sql
COPY database/seed.sql /docker-entrypoint-initdb.d/2_seed.sql

EXPOSE 3306
