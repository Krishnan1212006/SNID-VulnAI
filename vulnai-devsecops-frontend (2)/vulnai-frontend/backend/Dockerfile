# VulnAI DevSecOps - FastAPI Backend
FROM hackllc/nikto:2.6.1 AS nikto

FROM python:3.12-slim

WORKDIR /app
ENV VULNAI_APP_ROOT=/app \
	SCAN_RESULTS_DIR=/app/scan-results \
	VULNAI_WORDLIST_PATH=/app/wordlist/common.txt

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install joblib scikit-learn
RUN apt-get update && apt-get install -y --no-install-recommends nmap gobuster sqlmap perl \
	libnet-ssleay-perl libjson-perl libio-socket-ssl-perl libxml-writer-perl libxml-libxml-perl \
	&& rm -rf /var/lib/apt/lists/*
RUN python -m venv /opt/wapiti \
	&& /opt/wapiti/bin/pip install --no-cache-dir "wapiti3==3.2.10" \
	&& ln -s /opt/wapiti/bin/wapiti /usr/local/bin/wapiti
COPY --from=nikto /opt/nikto /opt/nikto
RUN ln -s /opt/nikto/nikto.pl /usr/local/bin/nikto
RUN mkdir -p /app/scan-results /app/wordlist

COPY . .

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
