# controllers/log_controller.py
from fastapi import APIRouter, HTTPException
from app.services import log_service

router = APIRouter()

# Obtener todos los logs
@router.get("/")
def get_all_logs():
    try:
        logs = log_service.get_all_logs()
        return logs
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
