from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel
from app.services import alert_service
from sqlalchemy.orm import Session
from database.db_connection import get_db
import math
from openpyxl import Workbook
from fastapi.responses import StreamingResponse
from io import BytesIO

router = APIRouter()

# Modelo para obtener alertas con paginación
class GetAlertsResponse(BaseModel):
    id: int
    second_id: str
    log_ids: str
    message: str
    source_ip: str
    dest_ip: str
    severity: str
    category: dict
    context: str
    status: int
    created_at: str


class GetActiveAlertsResponse(BaseModel):
    id: int
    second_id: str
    log_ids: str
    message: str
    source_ip: str
    dest_ip: str
    severity: str
    context: str
    status: int
    created_at: str

# Modelo para actualizar el estado de una alerta
class UpdateAlertRequest(BaseModel):
    status: int

# Endpoint para obtener todas las alertas
@router.get("/all")
def get_all_alerts(
    page: int = Query(1, ge=1),
    size: int = Query(10, ge=10),
    db: Session = Depends(get_db)
):
    try:
        alerts, total_alerts = alert_service.get_all_alerts(db=db, page=page, size=size)
        if len(alerts) == 0:
            raise HTTPException(status_code=404, detail="No se encontraron datos.")
        
        alerts_data = [
            GetAlertsResponse(
                id=alert.id,
                second_id=alert.second_id,
                log_ids=alert.log_ids,
                message=alert.message,
                source_ip=alert.source_ip,
                dest_ip=alert.dest_ip,
                severity=alert.severity,
                category={"name":alert.name, "description":alert.description},
                context=alert.context,
                status=alert.status,
                created_at=alert.created_at.isoformat()
            ) for alert in alerts
        ]

        total_pages = math.ceil(total_alerts / size)
        
        return {
            "detail": "Alertas obtenidas exitosamente",
            "data": alerts_data,
            "pagination": {
                "page": page,
                "size": size,
                "total_alerts": total_alerts,
                "total_pages": total_pages
            }
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Endpoint para obtener alertas activas
@router.get("/active")
def get_active_alerts(
    db: Session = Depends(get_db)
    ):
    
    try:
        active_alerts = alert_service.get_active_alerts(db=db)
        if len(active_alerts) == 0:
            raise HTTPException(status_code=404, detail="No se encontraron datos.")
        
        alerts_data = [
            GetActiveAlertsResponse(
                id=alert.id,
                second_id=alert.second_id,
                log_ids=alert.log_ids,
                message=alert.message,
                source_ip=alert.source_ip,
                dest_ip=alert.dest_ip,
                severity=alert.severity,
                context=alert.context,
                status=alert.status,
                created_at=alert.created_at.isoformat()
            ) for alert in active_alerts
        ]

        return {
            "detail": "Alertas obtenidas exitosamente",
            "data": alerts_data
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Endpoint para actualizar el estado de una alerta
@router.put("/update-status/{alert_id}")
def update_alert_status(alert_id: int, request: UpdateAlertRequest, db: Session = Depends(get_db)):
    try:
        updated_alert = alert_service.update_alert_status(db=db, alert_id=alert_id, status=request.status)
        if not updated_alert:
            raise HTTPException(status_code=404, detail="Alerta no encontrada.")
        
        return {
            "detail": "Estado de la alerta actualizado exitosamente",
            "data": {
                "id": updated_alert.id,
                "second_id": updated_alert.second_id,
                "log_ids": updated_alert.log_ids,
                "alert_type": updated_alert.alert_type,
                "message": updated_alert.message,
                "source_ip": updated_alert.source_ip,
                "dest_ip": updated_alert.dest_ip,
                "severity": updated_alert.severity,
                "context": updated_alert.context,
                "status": updated_alert.status,
                "created_at": updated_alert.created_at.isoformat()
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    

@router.get("/download-alerts")
def download_alerts(db: Session = Depends(get_db)):
    try:
        # Obtiene todas las alertas sin paginación
        alerts, _  = alert_service.get_all_alerts(db=db, page=1, size=1000)
        
        # Crear el archivo Excel en memoria
        output = BytesIO()
        workbook = Workbook()
        sheet = workbook.active
        sheet.title = "Alerts"

        # Encabezados
        headers = ["ID", "Second ID", "Log IDs", "Message", "Source IP", "Dest IP", "Severity", "Context", "Category", "Status", "Created At"]
        sheet.append(headers)

        # Agregar los datos de las alertas
        for alert in alerts:
            sheet.append([
                alert.id,
                alert.second_id,
                alert.log_ids,
                alert.message,
                alert.source_ip,
                alert.dest_ip,
                alert.severity,
                alert.context,
                alert.name,
                alert.status,
                alert.created_at.isoformat()
            ])

        # Guardar el archivo Excel en el buffer de memoria
        workbook.save(output)
        output.seek(0)

        # Preparar la respuesta con el archivo Excel
        headers = {
            "Content-Disposition": "attachment; filename=alerts_list.xlsx",
            "Content-Type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        }
        return StreamingResponse(output, headers=headers)

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))