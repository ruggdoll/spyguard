FROM python:3.12-slim

# tshark (dumpcap) and nmcli are needed for actual capture; they won't work
# inside Docker without host networking + privileges, but the app still starts.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libudev-dev \
    && rm -rf /var/lib/apt/lists/*

COPY assets/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY docker/capture-api/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8000
ENTRYPOINT ["/entrypoint.sh"]
