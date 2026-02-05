FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy the webhook script
COPY webhook.py .

# Expose the default port
EXPOSE 8080

# Run the webhook server
CMD ["python", "webhook.py"]

