from fastapi import APIRouter, HTTPException, Depends
from typing import Optional
from pydantic import BaseModel
from app.services import alert_service
from sqlalchemy.orm import Session
from database.db_connection import get_db
import math
import csv
from fastapi.responses import StreamingResponse
from io import StringIO

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

class GetAlertsTypesResponse(BaseModel):
    id: int
    code: str
    name: str
    severity: str
    description: str

# Modelo para actualizar el estado de una alerta
class UpdateAlertRequest(BaseModel):
    status: int

class AlertsRequest(BaseModel):
    page: int = 1
    size: int = 10
    alert_type: Optional[int] = None 
    severity: Optional[int] = None 

# Endpoint para obtener todas las alertas
@router.post("/all")
def get_all_alerts(
    request: AlertsRequest,
    db: Session = Depends(get_db)
    ):
    
    try:
        size = request.size
        page = request.page

        alerts, total_alerts = alert_service.get_all_alerts(request, db=db)
        if len(alerts) == 0:
            raise HTTPException(status_code=404, detail="No se encontraron datos.")
        
        alerts_data = [
            GetAlertsResponse(
                id=alert.id,
                second_id=alert.second_id,
                log_ids=alert.log_ids,
                message=alert.message,
                source_ip=alert.source_ip if alert.source_ip else "Desconocido",
                dest_ip=alert.dest_ip if alert.dest_ip else "Desconocido",
                severity= "Peligro" if alert.severity == 1 else "Advertencia",
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
                source_ip=alert.source_ip if alert.source_ip else "Desconocido",
                dest_ip=alert.dest_ip if alert.dest_ip else "Desconocido",
                severity="Peligro" if alert.severity == 1 else "Advertencia",
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
    
@router.get("/types")
def get_alerts_types(
    db: Session = Depends(get_db)
    ):
    
    try:
        alerts_types = alert_service.get_alerts_types(db=db)
        if len(alerts_types) == 0:
            raise HTTPException(status_code=404, detail="No se encontraron datos.")
        
        alerts_data = [
            GetAlertsTypesResponse(
                id=alert.id,
                code=alert.code,
                name=alert.name,
                severity="Peligro" if alert.severity == 1 else "Advertencia",
                description=alert.description
            ) for alert in alerts_types
        ]

        return {
            "detail": "Tipos de alertas obtenidas exitosamente",
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
        alerts = alert_service.download_alerts(db)
        
        # Crear el archivo Excel en memoria
        output = StringIO()
        writer = csv.writer(output)

        # Encabezados
        headers = ["ID", "Second ID", "Log IDs", "Message", "Source IP", "Dest IP", "Severity", "Context", "Category", "Status", "Created At"]

        # Agregar los datos de las alertas
        for alert in alerts:
            writer.writerow([
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
        output.seek(0)

        # Preparar la respuesta con el archivo Excel
        headers = {
            "Content-Disposition": "attachment; filename=alerts_list.csv",
            "Content-Type": "text/csv"
        }
        return StreamingResponse(output, headers=headers)

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    

@router.get("/by-date")
def alerts_by_date(
    db: Session = Depends(get_db)
):
    """
    Endpoint para obtener alertas agrupadas por fecha en formato listo para gráficos.
    """
    try:
        data = alert_service.get_alerts_by_date(db)
        if not data:
            raise HTTPException(status_code=404, detail="No se encontraron alertas para graficar.")
        
        return {
            "detail": "Datos obtenidos exitosamente",
            "data": data
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    

@router.get("/by-category")
def alerts_by_category(
    db: Session = Depends(get_db)
):
    """
    Endpoint para obtener alertas agrupadas por categoría en formato listo para gráficos.
    """
    try:
        data = alert_service.get_alerts_by_category(db)
        if not data:
            raise HTTPException(status_code=404, detail="No se encontraron alertas para graficar.")
        
        return {
            "detail": "Datos obtenidos exitosamente",
            "data": data
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))