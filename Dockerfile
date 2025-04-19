FROM python:3.9-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=10000

# Set working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose the port
EXPOSE 10000

# Run the application with Gunicorn
CMD gunicorn attendance_api:app --worker-class eventlet --workers 1 --bind 0.0.0.0:$PORT --preload --timeout 120 --log-level info
