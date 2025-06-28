# Use Alpine Linux for minimal footprint
FROM python:3.12-alpine

# Install security updates
RUN apk update && apk upgrade --no-cache

# Create non-root user for running the application
RUN addgroup -g 1000 -S openvpn-fp && \
    adduser -u 1000 -S openvpn-fp -G openvpn-fp

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY openvpn-fingerprint.py .
COPY efficieny-test.py .

# Change ownership of the application directory
RUN chown -R openvpn-fp:openvpn-fp /app

# Switch to non-root user
USER openvpn-fp

# Default command
ENTRYPOINT ["python", "openvpn-fingerprint.py"]

# Default arguments (can be overridden)
CMD ["--help"]
