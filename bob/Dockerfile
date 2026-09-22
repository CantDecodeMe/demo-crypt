# Bob — servicio interno del canje Diffie-Hellman
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# Puerto interno 5000: NO se publica al host; solo es alcanzable
# desde la red Docker "services" (Alice y el túnel de Cloudflare).
EXPOSE 5000

CMD ["python", "app.py"]
