# Kavach backend (FastAPI + kill-chain pipeline)
FROM python:3.12-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1 LLM_REPLAY_ONLY=true
COPY requirements.txt ./requirements.txt
COPY backend/requirements.txt ./backend-requirements.txt
RUN pip install --no-cache-dir -r requirements.txt -r backend-requirements.txt
COPY backend ./backend
COPY config ./config
COPY data/ground_truth ./data/ground_truth
EXPOSE 8000
# First start: build the kill-chain run if it does not exist yet, then serve the API.
CMD ["sh", "-c", "cd backend && (test -f data/killchain/runs/firex/incidents.json || python -m killchain.cli run) && cd .. && uvicorn backend.main:app --host 0.0.0.0 --port 8000"]
