FROM zeek/zeek:8.1 AS zeek-runtime

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    FLASK_DEBUG=0 \
    PCAP_RUN_FOLDER=/app/Backend/pcap_runs \
    ZEEK_BIN=/usr/local/zeek/bin/zeek \
    PATH="/usr/local/zeek/bin:${PATH}" \
    LD_LIBRARY_PATH="/usr/local/zeek/lib:${LD_LIBRARY_PATH}"

WORKDIR /app

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential \
        default-libmysqlclient-dev \
        libicu76 \
        libnode115 \
        libnorm1t64 \
        libpgm-5.3-0t64 \
        libsodium23 \
        libzmq5 \
        pkg-config \
        tshark \
    && rm -rf /var/lib/apt/lists/*

COPY --from=zeek-runtime /usr/local/zeek /usr/local/zeek
RUN command -v zeek && zeek --version

COPY Backend/requirements.txt /app/Backend/requirements.txt
RUN pip install --upgrade pip \
    && pip install -r /app/Backend/requirements.txt

COPY . /app

RUN mkdir -p /app/Backend/instance /app/Backend/logs /app/Backend/model /app/Backend/pcap_runs /app/upload

WORKDIR /app/Backend

EXPOSE 5000

CMD ["python", "run_server_no_reload.py"]
