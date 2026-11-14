# DanishRecon - headless image with the external tools baked in.
#
#   docker build -t danishrecon .
#   docker run --rm -v "$PWD/out:/data" danishrecon scan example.com --i-am-authorized
#   docker run --rm -v "$PWD/samples:/data" danishrecon malware /data
#
# Reports land in the mounted folder under results/. Authorized targets only.

FROM golang:bookworm AS tools
ENV CGO_ENABLED=0
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
 && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
 && go install github.com/projectdiscovery/katana/cmd/katana@latest \
 && go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

FROM python:3.11-slim-bookworm
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    EXPLOITDB_PATH=/opt/exploitdb \
    NIKTO_PATH=/opt/nikto/program/nikto.pl \
    HOME=/home/scanner

RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap perl libnet-ssleay-perl libio-socket-ssl-perl libxml-writer-perl libjson-perl \
        dnsutils curl ca-certificates git tshark \
 && rm -rf /var/lib/apt/lists/*

COPY --from=tools /go/bin/nuclei /go/bin/httpx /go/bin/katana /go/bin/subfinder /usr/local/bin/

# Optional extras - a failed download never breaks the build (the engine falls back).
RUN curl -fsSL -o /tmp/rustscan.deb https://github.com/bee-san/RustScan/releases/download/2.1.1/rustscan_2.1.1_amd64.deb && dpkg -i /tmp/rustscan.deb; rm -f /tmp/rustscan.deb; true
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto || true
RUN mkdir -p /opt/exploitdb \
 && (curl -fsSL -o /opt/exploitdb/files_exploits.csv \
      https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv || true)

WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir ".[web,malware]"

RUN useradd --create-home --home-dir /home/scanner scanner \
 && mkdir -p /data && chown -R scanner:scanner /data /home/scanner
USER scanner
RUN nuclei -update-templates -silent || true

WORKDIR /data
VOLUME ["/data"]
ENTRYPOINT ["danishrecon"]
CMD ["scan", "--help"]
