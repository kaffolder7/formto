FROM postgres:16.4-alpine

# Coolify builds in a helper container; repository bind mounts are not portable
# to the runtime host. Ship fresh-database initialization with the image.
COPY backend/migrations/001_init.sql /docker-entrypoint-initdb.d/001_init.sql
