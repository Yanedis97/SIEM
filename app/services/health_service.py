import logging
from sqlalchemy import text

logger = logging.getLogger(__name__)


def check_mysql(db) -> bool:
    try:
        db.execute(text("SELECT 1"))
        return True
    except Exception as e:
        logger.warning("Health check: MySQL no responde: %s", e)
        return False


def check_elasticsearch(es) -> bool:
    try:
        return bool(es.options(request_timeout=2).ping())
    except Exception as e:
        logger.warning("Health check: Elasticsearch no responde: %s", e)
        return False


def get_health(db, es) -> dict:
    checks = {
        "api": "ok",
        "mysql": "ok" if check_mysql(db) else "error",
        "elasticsearch": "ok" if check_elasticsearch(es) else "error",
    }
    status = "ok" if all(v == "ok" for v in checks.values()) else "degraded"
    return {"status": status, "checks": checks}