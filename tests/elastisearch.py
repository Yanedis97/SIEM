def test_system(es, server_ip):
    # Probar conexión a Elasticsearch
    if es.ping():
        print("Conexión a Elasticsearch verificada.")
    else:
        print("Error al conectarse a Elasticsearch.")

    # Verificar que NXLog está enviando logs al servidor syslog
    # Puedes hacer esto leyendo un log de prueba
    try:
        with open("C:/logs/network.log", "r") as log_file:
            logs = log_file.readlines()
            if logs:
                print("Logs recibidos correctamente desde NXLog.")
            else:
                print("No se están recibiendo logs.")
    except Exception as e:
        print(f"Error al verificar logs: {e}")
