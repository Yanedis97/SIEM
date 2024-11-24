from sqlalchemy import func
from sqlalchemy.orm import Session
from app.models.alerts import Alerts
from app.models.alerts_categories import AlertsCategory

def build_alerts_query(request, db: Session):
    """Construir la consulta de alertas con los filtros proporcionados"""
    query = db.query(
            Alerts.id,
            Alerts.second_id,
            Alerts.log_ids,
            Alerts.message,
            Alerts.source_ip,
            Alerts.dest_ip,
            AlertsCategory.severity,
            Alerts.context,
            AlertsCategory.name,
            AlertsCategory.description,
            Alerts.status,
            Alerts.created_at
        ).join(
            AlertsCategory, Alerts.alert_category == AlertsCategory.id
        )

    # Aplicar filtros dinámicos a la consulta
    if request.alert_type:
        query = query.filter(AlertsCategory.id == request.alert_type)

    if request.severity:
        query = query.filter(AlertsCategory.severity == request.severity)

    return query

def get_all_alerts(request, db: Session):
    try:
        # Construir la consulta base con filtros
        alerts_query = build_alerts_query(request, db)

        # Paginación
        start_from = (request.page - 1) * request.size
        alerts = alerts_query.order_by(Alerts.created_at.desc()) \
                             .offset(start_from) \
                             .limit(request.size) \
                             .all()

        # Obtener el conteo total aplicando los mismos filtros
        total_alerts_query = build_alerts_query(request, db)
        total_alerts = total_alerts_query.count()

        return alerts, total_alerts
    except Exception as e:
        raise e


# Obtener alertas activas con paginación
def get_active_alerts(db: Session):
    try:
        active_alerts = db.query(Alerts).filter(Alerts.status == 1).order_by(Alerts.created_at.desc()).all()
        
        return active_alerts
    except Exception as e:
        raise e
    
# Obtener los tipos de alerts
def get_alerts_types(db: Session):
    try:
        alerts_types = db.query(AlertsCategory).filter(AlertsCategory.status == 1).order_by(AlertsCategory.created_at.desc()).all()
        
        return alerts_types
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
    

def get_alerts_by_date(db: Session):
    """
    Servicio para obtener la cantidad de alertas agrupadas por fecha.
    """
    try:
        # Consulta que agrupa alertas por fecha y cuenta la cantidad
        alerts_by_date_query = (
            db.query(
                func.date(Alerts.created_at).label("date"),
                func.count(Alerts.id).label("count")
            )
            .group_by(func.date(Alerts.created_at))
            .order_by(func.date(Alerts.created_at).asc())
        )

        # Procesar resultados en una lista de dict
        results = [{"date": result.date.isoformat(), "count": result.count} for result in alerts_by_date_query]

        return results
    except Exception as e:
        raise e
    

def get_alerts_by_category(db: Session):
    """
    Servicio para obtener el número de alertas agrupadas por categoría.
    """
    try:
        # Consulta que cuenta las alertas por categoría
        alerts_by_category_query = (
            db.query(
                AlertsCategory.name.label("category"),
                func.count(Alerts.id).label("count")
            )
            .join(Alerts, Alerts.alert_category == AlertsCategory.id)
            .group_by(AlertsCategory.name)
            .order_by(func.count(Alerts.id).desc())
        )

        # Procesar resultados en una lista de dict
        results = [{"category": result.category, "count": result.count} for result in alerts_by_category_query]

        return results
    except Exception as e:
        raise e
