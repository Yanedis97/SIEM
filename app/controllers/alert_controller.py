from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel
from app.services import alert_service
from sqlalchemy.orm import Session
from database.db_connection import get_db

router = APIRouter()

# Modelo para obtener alertas con paginación
class GetAlertsRequest(BaseModel):
    page: int = Query(1, ge=1)
    size: int = Query(10, ge=10)

# Modelo para actualizar el estado de una alerta
class UpdateAlertRequest(BaseModel):
    id: int
    status: int

# Endpoint para obtener todas las alertas
@router.get("/all")
def get_all_alerts(request: GetAlertsRequest, db: Session = Depends(get_db)):
    try:
        alerts = alert_service.get_all_alerts(db=db, page=request.page, size=request.size)
        if len(alerts) == 0:
            raise HTTPException(status_code=404, detail="No se encontraron datos.")
        else:
            return alerts
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Endpoint para obtener alertas activas
@router.get("/active")
def get_active_alerts(request: GetAlertsRequest, db: Session = Depends(get_db)):
    try:
        active_alerts = alert_service.get_active_alerts(db=db, page=request.page, size=request.size)
        if len(active_alerts) == 0:
            raise HTTPException(status_code=404, detail="No se encontraron datos.")
        else:
            return active_alerts
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Endpoint para actualizar el estado de una alerta
@router.put("/update-status/{alert_id}")
def update_alert_status(alert_id: int, request: UpdateAlertRequest, db: Session = Depends(get_db)):
    try:
        updated_alert = alert_service.update_alert_status(db=db, alert_id=alert_id, status=request.status)
        if not updated_alert:
            raise HTTPException(status_code=404, detail="Alerta no encontrada.")
        return updated_alert
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))