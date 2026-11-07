FROM python:3.12-alpine

WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir . \
    && adduser -D -H -u 10001 app \
    && mkdir -p /data && chown app /data

USER app

# HTTP/OAuth mode settings (ignored in the default stdio mode)
ENV FRESHDESK_MCP_DATA_DIR=/data \
    HOST=0.0.0.0 \
    PORT=8000
VOLUME ["/data"]
EXPOSE 8000

# Default: stdio (FRESHDESK_API_KEY + FRESHDESK_DOMAIN).
# Public deployment: set FRESHDESK_MCP_TRANSPORT=http (see docker-compose.example.yml).
CMD ["freshdesk-mcp"]
