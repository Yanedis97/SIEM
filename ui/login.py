# login_gui.py
import tkinter as tk
from tkinter import messagebox
from sqlalchemy.orm import Session
from database import SessionLocal
from auth import authenticate_user

class LoginApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Login")
        self.create_widgets()

    def create_widgets(self):
        tk.Label(self.root, text="Username").grid(row=0, column=0, padx=10, pady=10)
        tk.Label(self.root, text="Password").grid(row=1, column=0, padx=10, pady=10)

        self.username_entry = tk.Entry(self.root)
        self.password_entry = tk.Entry(self.root, show='*')

        self.username_entry.grid(row=0, column=1, padx=10, pady=10)
        self.password_entry.grid(row=1, column=1, padx=10, pady=10)

        self.login_button = tk.Button(self.root, text="Login", command=self.login)
        self.login_button.grid(row=2, column=0, columnspan=2, pady=10)

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        db: Session = SessionLocal()
        user = authenticate_user(db, username, password)

        if user:
            messagebox.showinfo("Login Success", f"Welcome, {user.username}!")
            self.root.destroy()  # Cierra la ventana de login
        else:
            messagebox.showerror("Login Error", "Invalid username or password")

if __name__ == "__main__":
    root = tk.Tk()
    app = LoginApp(root)
    root.mainloop()
