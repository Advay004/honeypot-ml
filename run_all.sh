#!/bin/bash
echo "Starting FastAPI Backend..."
source honeyvenv/bin/activate
kill -9 $(lsof -t -i:8002) 2>/dev/null
uvicorn main:app --port 8002 &
BACKEND_PID=$!

echo "Starting Streamlit Frontend..."
streamlit run app.py &
FRONTEND_PID=$!

echo "Both systems are running!"
echo "Backend PID: $BACKEND_PID"
echo "Frontend PID: $FRONTEND_PID"
echo "Press Ctrl+C to stop both."

wait
