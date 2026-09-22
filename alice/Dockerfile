# Alice — servicio público del canje Diffie-Hellman (punto de entrada web)
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY templates/ templates/

# Puerto interno 5000: publicado vía Cloudflare Tunnel (no al host).
EXPOSE 5000

CMD ["python", "app.py"]
