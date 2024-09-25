import tkinter as tk
from tkinter import messagebox
from es_connector import ElasticsearchConnector

class MainWindow:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("SIEM Dashboard")
        self.create_widgets()

    def create_widgets(self):
        btn_fetch_logs = tk.Button(self.root, text="Fetch Logs", command=self.fetch_logs)
        btn_fetch_logs.pack(pady=20)

    def fetch_logs(self):
        es = ElasticsearchConnector()
        logs = es.get_logs()
        logs_str = "\n".join([str(log) for log in logs])
        messagebox.showinfo("Logs", logs_str)

    def run(self):
        self.root.mainloop()
