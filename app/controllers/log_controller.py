from fastapi import APIRouter, HTTPException, Query
from app.services import log_service

router = APIRouter()

# Obtener logs con paginación
@router.get("/all")
def get_all_logs(page: int = Query(1, ge=1), size: int = Query(10, ge=1, le=100)):
    """
    Endpoint para obtener logs con paginación.
    Parámetros:
        - page: número de página (por defecto 1).
        - size: cantidad de logs por página (por defecto 10, máximo 100).
    """
    try:
        logs = log_service.get_all_logs(page=page, size=size)
        return logs
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
