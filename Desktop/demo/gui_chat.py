import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog
import subprocess
import threading
import sys
import os
import signal
import time

class SecureChatGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat")
        self.root.geometry("600x500")
        
        self.client_process = None
        self.server_process = None
        self.running = False
        
        self.create_widgets()
        self.check_executables()

    def check_executables(self):
        self.server_exe = "build/server.exe" if os.name == 'nt' else "build/server"
        self.client_exe = "build/client.exe" if os.name == 'nt' else "build/client"
        
        if not os.path.exists(self.client_exe):
            messagebox.showerror("Error", "Executables not found. Please run build.sh first.")
            self.root.destroy()
            
    def create_widgets(self):
        # Connection Frame
        conn_frame = tk.Frame(self.root)
        conn_frame.pack(pady=10, fill=tk.X, padx=10)
        
        tk.Label(conn_frame, text="Server IP:").pack(side=tk.LEFT)
        self.ip_entry = tk.Entry(conn_frame, width=15)
        self.ip_entry.insert(0, "127.0.0.1")
        self.ip_entry.pack(side=tk.LEFT, padx=5)
        
        tk.Label(conn_frame, text="Port:").pack(side=tk.LEFT)
        self.port_entry = tk.Entry(conn_frame, width=6)
        self.port_entry.insert(0, "8080")
        self.port_entry.pack(side=tk.LEFT, padx=5)
        
        self.connect_btn = tk.Button(conn_frame, text="Connect", command=self.connect)
        self.connect_btn.pack(side=tk.LEFT, padx=5)

        tk.Label(conn_frame, text="Username:").pack(side=tk.LEFT, padx=5)
        self.username_entry = tk.Entry(conn_frame, width=15)
        self.username_entry.insert(0, "User")
        self.username_entry.pack(side=tk.LEFT, padx=5)
        
        self.host_var = tk.BooleanVar()
        self.host_check = tk.Checkbutton(conn_frame, text="Host Server", variable=self.host_var)
        self.host_check.pack(side=tk.LEFT, padx=5)
        
        # Chat Area
        self.chat_area = scrolledtext.ScrolledText(self.root, state='disabled', height=20)
        self.chat_area.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)
        self.chat_area.tag_config('user', foreground='blue')
        self.chat_area.tag_config('server', foreground='green')
        self.chat_area.tag_config('error', foreground='red')
        
        # Input Area
        input_frame = tk.Frame(self.root)
        input_frame.pack(pady=10, fill=tk.X, padx=10)
        
        
        tk.Label(input_frame, text="To User:").pack(side=tk.LEFT)
        self.target_entry = tk.Entry(input_frame, width=10)
        self.target_entry.pack(side=tk.LEFT, padx=5)
        
        self.msg_entry = tk.Entry(input_frame)
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.msg_entry.bind('<Return>', self.send_message)
        
        self.send_btn = tk.Button(input_frame, text="Send", command=self.send_message, state='disabled')
        self.send_btn.pack(side=tk.LEFT, padx=5)
        
        self.rotate_btn = tk.Button(input_frame, text="Rotate Key", command=self.rotate_key, state='disabled')
        self.rotate_btn.pack(side=tk.LEFT, padx=5)

    def log(self, message, tag=None):
        self.chat_area.configure(state='normal')
        self.chat_area.insert(tk.END, message + "\n", tag)
        self.chat_area.see(tk.END)
        self.chat_area.configure(state='disabled')

    def connect(self):
        ip = self.ip_entry.get()
        port = self.port_entry.get()
        username = self.username_entry.get()
        
        if not username:
            messagebox.showerror("Error", "Username is required")
            return
        if self.host_var.get():
            self.start_server(port)
            # Give server a moment to start
            time.sleep(1)
            
        self.start_client(ip, port, username)
        
    def start_server(self, port):
        try:
            self.server_process = subprocess.Popen(
                [self.server_exe, port],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            self.log(f"Server started on port {port}", 'server')
            threading.Thread(target=self.monitor_process, args=(self.server_process, "SERVER"), daemon=True).start()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start server: {e}")

    def start_client(self, ip, port, username):
        try:
            self.client_process = subprocess.Popen(
                [self.client_exe, ip, port, username],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            self.running = True
            self.connect_btn.config(state='disabled')
            self.send_btn.config(state='normal')
            self.rotate_btn.config(state='normal')
            self.msg_entry.focus()
            
            threading.Thread(target=self.read_client_output, daemon=True).start()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start client: {e}")

    def read_client_output(self):
        while self.running and self.client_process.poll() is None:
            line = self.client_process.stdout.readline()
            if not line:
                break
            line = line.strip()
            
            if "[CHAT]" in line:
                # Format: [CHAT] Client X: Message
                msg = line.replace("[CHAT]", "").strip()
                self.log(msg, 'user')
            elif "Key rotation successful" in line:
                self.log("System: Key rotation successful", 'server')
            elif "Connected to server" in line:
                self.log(f"System: Connected to {self.ip_entry.get()}", 'server')
            else:
                # Debug info
                print(f"Client Output: {line}")
                
        self.running = False
        self.root.after(0, self.on_disconnect)

    def monitor_process(self, process, name):
        while process.poll() is None:
            line = process.stdout.readline()
            if line:
                print(f"[{name}] {line.strip()}")

    def send_message(self, event=None):
        if not self.running: return
        
        msg = self.msg_entry.get()
        target = self.target_entry.get().strip()
        
        if target:
            # Format as direct message: @target message
            full_msg = f"@{target} {msg}"
            display_msg = f"[Whisper to {target}] {msg}"
        else:
            full_msg = msg
            display_msg = f"Me: {msg}"
            
        if msg:
            try:
                self.client_process.stdin.write(full_msg + "\n")
                self.client_process.stdin.flush()
                self.log(display_msg, 'user')
                self.msg_entry.delete(0, tk.END)
            except Exception as e:
                self.log(f"Error sending message: {e}", 'error')

    def rotate_key(self):
        if not self.running: return
        
        try:
            self.client_process.stdin.write("rotate\n")
            self.client_process.stdin.flush()
        except Exception as e:
            self.log(f"Error requesting rotation: {e}", 'error')

    def on_disconnect(self):
        self.connect_btn.config(state='normal')
        self.send_btn.config(state='disabled')
        self.rotate_btn.config(state='disabled')
        self.log("Disconnected from server", 'error')

    def on_closing(self):
        self.running = False
        if self.client_process:
            self.client_process.terminate()
        if self.server_process:
            self.server_process.terminate()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureChatGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()
