from sqlalchemy.orm import Session
from app.models.alerts import Alerts
from app.models.alerts_status import AlertsStatus

# Obtener todas las alertas con paginación
def get_all_alerts(db: Session, page: int = 1, size: int = 10):
    try:
        start_from = (page - 1) * size
        alerts = db.query(Alerts).order_by(Alerts.created_at.desc()).offset(start_from).limit(size).all()
        
        total_alerts = db.query(Alerts).count()
        return alerts, total_alerts
    except Exception as e:
        raise e

# Obtener alertas activas con paginación
def get_active_alerts(db: Session, page: int = 1, size: int = 10):
    try:
        start_from = (page - 1) * size
        active_alerts = db.query(Alerts).filter(Alerts.status == 1).order_by(Alerts.created_at.desc()).offset(start_from).limit(size).all()
        
        total_alerts = db.query(Alerts).count()
        return active_alerts, total_alerts
    except Exception as e:
        raise e

# Actualizar el estado de una alerta
def update_alert_status(db: Session, alert_id: int, status: int):
    try:
        alert = db.query(Alerts).filter(Alerts.id == alert_id).first()
        
        if alert:
            alert.status = status
            db.commit()  
            db.refresh(alert) 
            return alert
        else:
            return None
    except Exception as e:
        raise e