#!/bin/bash
while true; do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    http://localhost:11434/api/tags)
  if [ "$STATUS" != "200" ]; then
    echo "[$(date)] Ollama down (HTTP $STATUS), restarting..."
    OLLAMA_HOST=0.0.0.0 /usr/local/bin/ollama serve &
    sleep 5
  else
    echo "[$(date)] Ollama OK — gemma4:latest ready"
  fi
  sleep 30
done
