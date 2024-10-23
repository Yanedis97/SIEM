from fastapi import APIRouter, HTTPException, Query
from app.services import alert_service

router = APIRouter()

# Obtener todas las alertas guardadas con paginación
@router.get("/all")
def get_all_alerts(page: int = Query(1, ge=1), size: int = Query(10, ge=1)):
    try:
        alerts = alert_service.get_all_alerts(page=page, size=size)
        return alerts
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Obtener una alerta en tiempo real
@router.get("/realtime")
def get_realtime_alert():
    try:
        alert = alert_service.get_realtime_alert()
        return alert
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
