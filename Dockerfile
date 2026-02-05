FROM python:3.11-slim

WORKDIR /app

COPY webhook.py .

EXPOSE 5001

CMD ["python", "webhook.py"]

