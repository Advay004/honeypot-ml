# main.py
"""
FastAPI server:
 - POST /predict -> classify list of logs (same as before)
 - POST /ingest_cowrie -> accept Cowrie JSON events (list or newline-delimited JSON)
    Each Cowrie event is expected to be a dict and should contain one of:
      - 'input': the command string (Cowrie's recorded input)
      - 'message' or 'message': sometimes Cowrie stores different fields
      - 'session': etc. (we try to be flexible)
    Returns a list of classification results and appends to data/ingested_cowrie.jsonl
"""

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from typing import List, Optional
from classifier import classify_log
import json, os

app = FastAPI(title="Honeypot Log Classifier (Enhanced)")

class LogEntry(BaseModel):
    id: Optional[str] = None
    log: str

class PredictRequest(BaseModel):
    entries: List[LogEntry]

@app.post("/predict")
async def predict_logs(payload: PredictRequest):
    results = []
    for e in payload.entries:
        if not e.log or not e.log.strip():
            raise HTTPException(status_code=400, detail="Empty log provided")
        res = classify_log(e.log)
        results.append({
            "id": e.id,
            "log": e.log,
            "label": res["label"],
            "confidence": res["confidence"],
            "summary": res["suggestion"].get("summary", ""),
            "recommendations": res["suggestion"].get("recommendations", []),
            "expert_summary": res["suggestion"].get("expert_summary", ""),
            "expert_recommendations": res["suggestion"].get("expert_recommendations", []),
            "source": res.get("source")
        })
    return {"results": results}
@app.post("/classify")
async def classify_single(payload: dict):
    log = payload.get("log")
    if not log:
        raise HTTPException(400, "Missing 'log'")
    res = classify_log(log)
    return {
        "attack_type": res["label"],
        "summary": res["suggestion"].get("summary", ""),
        "recommendations": res["suggestion"].get("recommendations", []),
        "expert_summary": res["suggestion"].get("expert_summary", ""),
        "expert_recommendations": res["suggestion"].get("expert_recommendations", [])
    }

# Cowrie ingestion endpoint
INGEST_PATH = "data/ingested_cowrie.jsonl"
os.makedirs("data", exist_ok=True)
@app.post("/ingest/cowrie")
async def ingest_cowrie_alias(request: Request):
    return await ingest_cowrie(request)

@app.post("/ingest_cowrie")
async def ingest_cowrie(request: Request):
    """
    Accepts:
      - JSON list of cowrie events (application/json)
      - newline-delimited JSON (text/plain) in the request body
    For each event, tries to extract a command string and classify it.
    Returns classification results and appends raw events + classification to a jsonl file.
    """
    body = await request.body()
    if not body:
        raise HTTPException(status_code=400, detail="Empty body")

    results = []
    raw_events = []

    # try parse as JSON
    try:
        parsed = await request.json()
    except Exception:
        parsed = None

    events = []
    if parsed and isinstance(parsed, list):
        events = parsed
    elif parsed and isinstance(parsed, dict):
        events = [parsed]
    else:
        # try newline-delimited JSON
        try:
            text = body.decode('utf-8')
            lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
            for ln in lines:
                try:
                    events.append(json.loads(ln))
                except Exception:
                    # if it's plain text command, wrap it
                    events.append({"input": ln})
        except Exception:
            raise HTTPException(status_code=400, detail="Could not parse body as JSON or NDJSON")

    for ev in events:
        eventid = ev.get("eventid", "unknown")

        # Cowrie ONLY records attacker commands here
        if eventid == "cowrie.command.input":
            cmd = ev.get("input", "").strip()
        else:
            cmd = None

        if not cmd:
            res = {
                "label": "non-command",
                "confidence": 0.0,
                "suggestion": {
                    "summary": "Cowrie event does not contain an attacker command",
                    "recommendations": [],
                    "expert_summary": "Ignored due to insufficient payload context.",
                    "expert_recommendations": []
                }
            }
        else:
            res = classify_log(cmd)

        out = {
            "eventid": eventid,
            "attack_type": res["label"],
            "extracted_command": cmd or "<non-command-event>",
            "confidence": res["confidence"],
            "summary": res["suggestion"].get("summary", ""),
            "recommendations": res["suggestion"].get("recommendations", []),
            "expert_summary": res["suggestion"].get("expert_summary", ""),
            "expert_recommendations": res["suggestion"].get("expert_recommendations", [])
        }

        results.append(out)

        # persist to file
        try:
            with open(INGEST_PATH, "a") as fh:
                fh.write(json.dumps(out) + "\n")
        except Exception as e:
            print("Failed to write ingest file:", e)


    return {"count": len(results), "results": results}
    