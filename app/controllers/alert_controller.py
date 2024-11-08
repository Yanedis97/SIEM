from fastapi import APIRouter, HTTPException, Query
from app.services import alert_service

router = APIRouter()


@router.get("/all")
def get_all_alerts(page: int = Query(1, ge=1), size: int = Query(10, ge=1)):
    try:
        alerts = alert_service.get_all_alerts(page=page, size=size)
        return alerts
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/active")
def get_active_alerts(page: int = Query(1, ge=1), size: int = Query(10, ge=1)):
    try:
        active_alerts = alert_service.get_active_alerts(page=page, size=size)
        return active_alerts
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/update-status/{alert_id}")
def update_alert_status(alert_id: str, status: str):
    try:
        updated_alert = alert_service.update_alert_status(alert_id=alert_id, status=status)
        if not updated_alert:
            raise HTTPException(status_code=404, detail="Alerta no encontrada.")
        return updated_alert
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
