# Vantage in an image of its own:
#   podman build -t vantage .
#   podman run --rm -p 8106:8106 -e DASH_TOKEN="$(openssl rand -hex 24)" vantage
# (docker works the same way; it also reads this file with -f Containerfile.)
# With no config mounted it starts on the defaults. To use your own, copy
# config.example.json to config.json, edit it and add
#   -v ./config.json:/app/config.json:ro
# History lives in the /state volume. Host stats need /sys and /proc mounted at
# /host/sys and /host/proc; compose.yaml does all of this.
FROM docker.io/library/python:3.15.0-slim-trixie

WORKDIR /app
COPY *.py index.html briefing.html config.example.json ./
COPY static ./static

# no root at run time; /state is created here so a new volume inherits the owner
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin vantage \
 && mkdir /state && chown vantage /state \
 && chmod -R a+rX /app
USER vantage

ENV PYTHONUNBUFFERED=1 \
    PORT=8106 \
    STATE_DIR=/state \
    HOST_SYS=/host/sys \
    HOST_PROC=/host/proc

VOLUME /state
EXPOSE 8106
# /api/status needs no login; it answers 503 until the first refresh is done.
# Podman keeps this only with `podman build --format docker`.
HEALTHCHECK --interval=60s --timeout=5s --start-period=30s --retries=3 \
  CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/api/status' % os.environ.get('PORT', '8106'), timeout=4)"]
CMD ["python", "/app/server.py"]
