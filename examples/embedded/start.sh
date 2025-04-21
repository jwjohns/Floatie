#!/bin/bash

# Start Floatie in the background
floatie --pid-ns-inum=0 --max-map-entries=1024 &

# Start your application
python /app/app.py