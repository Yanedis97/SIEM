from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from database.db_connection import get_db
from app.services import health_service
# Temporal: reutiliza el cliente ya creado. Se reemplaza cuando ES sea dependencia inyectable.
from app.services.log_service import es

router = APIRouter()


@router.get("/health")
def health(db: Session = Depends(get_db)):
    result = health_service.get_health(db, es)
    status_code = 200 if result["status"] == "ok" else 503
    return JSONResponse(status_code=status_code, content=result)