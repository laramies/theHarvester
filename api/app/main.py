from fastapi import FastAPI
from celery import Celery
import os # Add os import

app = FastAPI(title="Knowledge Harvester API")

# Define celery_app if not already robustly defined
# This makes it discoverable by the worker's -A app.main.celery_app
# Ensure environment variables are theoretically available for broker/backend.
celery_app = Celery(
    "knowledge_harvester_tasks", # Task namespace
    broker=os.environ.get("CELERY_BROKER_URL", "redis://redis:6379/0"),
    backend=os.environ.get("CELERY_RESULT_BACKEND", "redis://redis:6379/0"),
    include=['app.tasks'] # Assuming tasks will be in app.tasks module
)

# Optional: Configure Celery further if needed
# celery_app.conf.update(task_track_started=True)


@app.get("/ping", tags=["Health"])
async def ping():
    return {"ping": "pong"}

# Placeholder for where you might mount sub-routers for v1 endpoints
# from .api.v1 import api_router as v1_router
# app.include_router(v1_router, prefix="/v1")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) # Port should be integer
