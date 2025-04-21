from flask import Flask
import time
import random
import os
import threading
from prometheus_client import start_http_server, Counter, Gauge

app = Flask(__name__)

# Create some metrics
REQUEST_COUNT = Counter('app_request_count', 'Total number of requests')
MEMORY_USAGE = Gauge('app_memory_mb', 'Memory usage in MB')

# Function to simulate memory usage
def update_memory_metrics():
    while True:
        # Simulate memory usage between 10-100MB
        memory_mb = 10 + random.random() * 90
        MEMORY_USAGE.set(memory_mb)
        time.sleep(5)

# Start metrics updating thread
metrics_thread = threading.Thread(target=update_memory_metrics, daemon=True)
metrics_thread.start()

@app.route('/')
def home():
    REQUEST_COUNT.inc()
    # Simulate some I/O with overlayfs
    with open('/tmp/test.txt', 'w') as f:
        f.write('This is a test file to trigger overlayfs operations')
    
    with open('/tmp/test.txt', 'r') as f:
        content = f.read()
    
    return f"Hello from example app! Floatie is monitoring this container."

@app.route('/heavy')
def heavy():
    REQUEST_COUNT.inc()
    # Create a bigger file to stress overlayfs
    with open('/tmp/large.txt', 'w') as f:
        for i in range(1000):
            f.write(f'Line {i}: This is a larger file to stress overlayfs operations\n')
    
    # Read it back
    with open('/tmp/large.txt', 'r') as f:
        # Read line by line to simulate slow reading
        lines = 0
        for line in f:
            lines += 1
    
    return f"Heavy operation completed. Read {lines} lines."

if __name__ == '__main__':
    # Start Prometheus metrics server on port 8000 (Floatie uses 9090)
    start_http_server(8000)
    app.run(host='0.0.0.0', port=8080)