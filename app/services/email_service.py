import pandas as pd
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime, timedelta
import schedule
import time
from app.models.alerts import Alerts
from app.models.users import Users
from sqlalchemy.orm import Session
from database.db_connection import get_db

def send_daily_alerts_report(db: Session, smtp_server: str, smtp_port: int, sender_email: str, sender_password: str):
    try:
        # Obtener la fecha de hoy
        today = datetime.now().date()
        tomorrow = today + timedelta(days=1)
        
        # Consultar las alertas del día
        alerts = db.query(Alerts).filter(Alerts.timestamp >= today, Alerts.timestamp < tomorrow).all()
        
        # Crear un DataFrame con las alertas
        alerts_data = [
            {
                "ID": alert.id,
                "Mensaje": alert.message,
                "Dispositivo": alert.device,
                "Fecha y hora": alert.timestamp
            }
            for alert in alerts
        ]
        df = pd.DataFrame(alerts_data)
        
        # Guardar el DataFrame como un archivo Excel
        excel_file = "daily_alerts_report.xlsx"
        df.to_excel(excel_file, index=False)
        
        # Obtener los correos de los administradores
        admins = db.query(Users).filter(Users.role == "admin").all()
        admin_emails = [admin.email for admin in admins]
        
        if not admin_emails:
            print("No hay administradores para enviar el correo.")
            return False
        
        # Configurar el correo
        subject = "Reporte diario de alertas"
        body = "Adjunto encontrarás el reporte diario de alertas generadas en el sistema."
        message = MIMEMultipart()
        message["From"] = sender_email
        message["Subject"] = subject
        
        # Agregar cuerpo del mensaje
        message.attach(MIMEText(body, "plain"))
        
        # Adjuntar el archivo Excel
        with open(excel_file, "rb") as attachment:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(attachment.read())
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", f"attachment; filename={excel_file}")
        message.attach(part)
        
        # Enviar el correo a cada administrador
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            
            for email in admin_emails:
                message["To"] = email
                server.sendmail(sender_email, email, message.as_string())
        
        print("Correo enviado exitosamente a los administradores.")
        return True
    
    except Exception as e:
        print(f"Error al enviar el correo: {e}")
        raise e

def schedule_daily_report(smtp_server: str, smtp_port: int, sender_email: str, sender_password: str):
    # Programar la tarea diaria a las 6 PM
    schedule.every().day.at("18:00").do(
    send_daily_alerts_report,
    db=get_db(),
    smtp_server=smtp_server,
    smtp_port=smtp_port,
    sender_email=sender_email,
    sender_password=sender_password
    )

    print("Programación iniciada. El correo se enviará todos los días a las 6 PM.")
    while True:
        schedule.run_pending()
        time.sleep(1)