FROM python:3.11-slim

WORKDIR /app

# Copy the webhook application
COPY webhook.py .

# Expose the port
EXPOSE 5001

# Run the webhook server
CMD ["python", "webhook.py"]

