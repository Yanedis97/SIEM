from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # MySQL
    database_url: str = "mysql+pymysql://root@localhost/my_siem"

    # Elasticsearch
    es_host: str = "https://localhost:9200"
    es_user: str = "elastic"
    es_password: str = "elastic"

    # Monitoreo de logs
    log_watch_dir: str = "C:\\logs"

    # Solo para database/seed_admin.py (sin default a propósito)
    admin_email: str | None = None
    admin_username: str = "admin"
    admin_password: str | None = None

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()