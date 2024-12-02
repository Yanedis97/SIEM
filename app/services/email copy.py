import pandas as pd
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime
import os
import schedule
import time

# Simulación de la clase Alerts
class Alerts:
    def __init__(self, id, message, device, timestamp):
        self.id = id
        self.message = message
        self.device = device
        self.timestamp = timestamp

# Simulación de la clase Users
class Users:
    def __init__(self, email, role):
        self.email = email
        self.role = role

def send_email_report(smtp_server, smtp_port, sender_email, sender_password):
    try:
        # Obtener la fecha actual
        today = datetime.now().date()

        # Simulación de las alertas
        alerts = [
            Alerts(1, "Mensaje de alerta", "Dispositivo X", datetime.now()),
            Alerts(2, "Otra alerta", "Dispositivo Y", datetime.now())
        ]

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

        # Simulación de los correos de los administradores
        admins = [
            Users("sistemas71@red5g.co", "admin")
        ]
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
        # Eliminar el archivo temporal después de enviarlo
        os.remove(excel_file)
        return True

    except Exception as e:
        print(f"Error al enviar el correo: {e}")
        return False

def schedule_daily_report(smtp_server, smtp_port, sender_email, sender_password):
    # Programar la tarea diaria a las 6 PM
    schedule.every().day.at("13:02").do(send_email_report, smtp_server, smtp_port, sender_email, sender_password)

    print("Programación iniciada. El correo se enviará todos los días a las 6 PM.")
    while True:
        schedule.run_pending()
        time.sleep(1)

def main():
    # Configura los parámetros del correo
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    sender_email = "monitoreoyalertassistema@gmail.com"  # Cambia por tu correo
    sender_password = "yune fiuf vmri vrcz"  # Cambia por tu contraseña o contraseña de aplicación

    # Llamar a la función para iniciar la programación
    schedule_daily_report(smtp_server, smtp_port, sender_email, sender_password)

if __name__ == "__main__":
    main()
