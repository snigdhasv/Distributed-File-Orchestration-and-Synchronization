import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import socket
import os
from cryptography.fernet import Fernet
import threading
import ssl
import time
from queue import Queue
import hashlib

class ModernFileClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("File Transfer Client")
        self.root.geometry("600x400")
        
        # Connection variables
        self.client = None
        self.username = None
        self.connected = False
        
        # Load encryption key
        with open("encryption_key.key", "rb") as key_file:
            self.encryption_key = key_file.read()
        self.cipher = Fernet(self.encryption_key)
        
        self.ssl_context = self.setup_ssl_context()
        self.transfer_queue = Queue()
        self.transfer_thread = None
        
        self.setup_gui()
        
    def setup_ssl_context(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # For self-signed certificates
        return context
        
    def setup_gui(self):
        # Login Frame
        self.login_frame = ttk.LabelFrame(self.root, text="Login", padding="10")
        self.login_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(self.login_frame, text="Username:").grid(row=0, column=0, padx=5, pady=5)
        self.username_entry = ttk.Entry(self.login_frame)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(self.login_frame, text="Password:").grid(row=1, column=0, padx=5, pady=5)
        self.password_entry = ttk.Entry(self.login_frame, show="*")
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)
        
        self.connect_btn = ttk.Button(self.login_frame, text="Connect", command=self.connect)
        self.connect_btn.grid(row=2, column=0, columnspan=2, pady=10)
        
        # File Operations Frame
        self.operations_frame = ttk.LabelFrame(self.root, text="File Operations", padding="10")
        self.operations_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Buttons Frame
        self.buttons_frame = ttk.Frame(self.operations_frame)
        self.buttons_frame.pack(fill="x", pady=5)
        
        ttk.Button(self.buttons_frame, text="Upload", command=self.upload_file).pack(side="left", padx=5)
        ttk.Button(self.buttons_frame, text="Download", command=self.download_file).pack(side="left", padx=5)
        ttk.Button(self.buttons_frame, text="Delete", command=self.delete_file).pack(side="left", padx=5)
        ttk.Button(self.buttons_frame, text="View", command=self.view_file).pack(side="left", padx=5)
        ttk.Button(self.buttons_frame, text="Refresh List", command=self.refresh_list).pack(side="left", padx=5)
        
        # File List
        self.file_list = tk.Listbox(self.operations_frame, height=10)
        self.file_list.pack(fill="both", expand=True, pady=5)
        
        # Status Bar
        self.status_var = tk.StringVar()
        self.status_var.set("Not connected")
        self.status_bar = ttk.Label(self.root, textvariable=self.status_var, relief="sunken")
        self.status_bar.pack(fill="x", side="bottom", padx=5, pady=5)
        
        # Disable operations frame initially
        self.operations_frame.pack_forget()
        
    def connect(self):
        try:
            raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client = self.ssl_context.wrap_socket(raw_socket)
            self.client.connect(('127.0.0.1', 8080))
            
            # Start transfer thread
            self.transfer_thread = threading.Thread(target=self.process_transfer_queue, daemon=True)
            self.transfer_thread.start()
            
            # Handle authentication
            self.client.recv(1024)  # Connection established message
            self.client.recv(1024)  # Username prompt
            
            username = self.username_entry.get()
            self.client.sendall(username.encode())
            
            self.client.recv(1024)  # Password prompt
            password = self.password_entry.get()
            self.client.sendall(password.encode())
            
            response = self.client.recv(1024).decode()
            
            if "Authentication successful" in response:
                self.connected = True
                self.username = username
                self.status_var.set(f"Connected as {username}")
                self.login_frame.pack_forget()
                self.operations_frame.pack(fill="both", expand=True, padx=10, pady=5)
                self.refresh_list()
            else:
                messagebox.showerror("Error", "Authentication failed")
                self.client.close()
                
        except Exception as e:
            messagebox.showerror("Error", f"Connection failed: {str(e)}")
            
    def process_transfer_queue(self):
        while True:
            if not self.connected:
                break
                
            try:
                task = self.transfer_queue.get(timeout=1)
                if task['type'] == 'upload':
                    self._handle_upload(task)
                elif task['type'] == 'download':
                    self._handle_download(task)
            except Queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Transfer error: {e}")
                
    def _handle_upload(self, task):
        filename = task['filename']
        file_path = task['path']
        
        try:
            # Calculate file hash
            file_hash = self.calculate_file_hash(file_path)
            
            # Send upload command with hash
            self.client.sendall(f"UPLOAD {filename} {file_hash}".encode())
            
            if self.client.recv(1024) == b"ACK":
                with open(file_path, 'rb') as f:
                    while (data := f.read(8192)):  # Increased buffer size
                        self.client.sendall(data)
                self.client.sendall(b"EOF")
                
                # Verify upload
                response = self.client.recv(1024).decode()
                if "SUCCESS" in response:
                    self.show_status(f"Upload complete: {filename}")
                else:
                    self.show_status(f"Upload failed: {filename}")
        except Exception as e:
            self.show_status(f"Upload error: {str(e)}")
            
    def calculate_file_hash(self, file_path):
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
        
    def show_status(self, message):
        self.status_var.set(message)
        self.root.update_idletasks()
        
    def refresh_list(self):
        if not self.connected:
            return
            
        self.client.sendall(b"LIST")
        response = self.client.recv(1024).decode()
        
        self.file_list.delete(0, tk.END)
        if response != "The server directory is empty.":
            for file in response.split('\n'):
                self.file_list.insert(tk.END, file)
                
    def upload_file(self):
        if not self.connected:
            return
            
        filename = filedialog.askopenfilename()
        if filename:
            try:
                self.client.sendall(f"UPLOAD {os.path.basename(filename)}".encode())
                if self.client.recv(1024) == b"ACK":
                    # Read entire file content
                    with open(filename, 'rb') as f:
                        file_data = f.read()
                    
                    # Send file data in chunks
                    chunk_size = 1024
                    for i in range(0, len(file_data), chunk_size):
                        chunk = file_data[i:i + chunk_size]
                        self.client.sendall(chunk)
                    
                    self.client.sendall(b"EOF")
                    
                    response = self.client.recv(1024)
                    if response == b"SUCCESS":
                        messagebox.showinfo("Success", "File uploaded successfully")
                        self.refresh_list()
                    else:
                        messagebox.showerror("Error", "Upload failed")
                        
            except Exception as e:
                messagebox.showerror("Error", f"Upload failed: {str(e)}")
                
    def download_file(self):
        if not self.connected or not self.file_list.curselection():
            return
            
        filename = self.file_list.get(self.file_list.curselection())
        save_path = filedialog.asksaveasfilename(initialfile=filename)
        
        if save_path:
            try:
                self.client.sendall(f"DOWNLOAD {filename}".encode())
                with open(save_path, 'wb') as f:
                    while True:
                        data = self.client.recv(1024)
                        if data == b"EOF":
                            break
                        if data.startswith(b"ERROR"):
                            raise Exception(data.decode())
                        f.write(data)
                messagebox.showinfo("Success", "File downloaded successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Download failed: {str(e)}")
                
    def delete_file(self):
        if not self.connected or not self.file_list.curselection():
            return
            
        filename = self.file_list.get(self.file_list.curselection())
        if messagebox.askyesno("Confirm", f"Delete {filename}?"):
            try:
                self.client.sendall(f"DELETE {filename}".encode())
                response = self.client.recv(1024).decode()
                messagebox.showinfo("Result", response)
                self.refresh_list()
            except Exception as e:
                messagebox.showerror("Error", f"Delete failed: {str(e)}")
                
    def view_file(self):
        if not self.connected or not self.file_list.curselection():
            return
            
        filename = self.file_list.get(self.file_list.curselection())
        try:
            self.client.sendall(f"VIEW {filename}".encode())
            preview_data = self.client.recv(1024)
            
            # Create preview window
            preview_window = tk.Toplevel(self.root)
            preview_window.title(f"Preview: {filename}")
            preview_window.geometry("600x400")
            
            # Add padding around the window
            container = ttk.Frame(preview_window, padding="10")
            container.pack(fill="both", expand=True)
            
            # Header
            ttk.Label(container, 
                     text=f"File Preview: {filename}", 
                     font=('Helvetica', 12, 'bold')).pack(pady=(0, 10))
            
            # Text widget with scrollbar
            text_frame = ttk.Frame(container)
            text_frame.pack(fill="both", expand=True)
            
            scrollbar = ttk.Scrollbar(text_frame)
            scrollbar.pack(side="right", fill="y")
            
            text_widget = tk.Text(text_frame, 
                                wrap=tk.WORD,
                                font=('Courier', 10),
                                padx=10,
                                pady=10)
            text_widget.pack(side="left", fill="both", expand=True)
            
            # Connect scrollbar
            text_widget.config(yscrollcommand=scrollbar.set)
            scrollbar.config(command=text_widget.yview)
            
            # Insert content
            if preview_data.startswith(b"ERROR"):
                text_widget.insert("1.0", preview_data.decode())
                text_widget.config(foreground="red")
            else:
                try:
                    text_content = preview_data.decode(errors='ignore')
                    text_widget.insert("1.0", text_content)
                except Exception as e:
                    text_widget.insert("1.0", f"Error displaying content: {str(e)}")
                    text_widget.config(foreground="red")
            
            text_widget.config(state="disabled")
            
            # Close button
            ttk.Button(container, 
                      text="Close", 
                      command=preview_window.destroy).pack(pady=10)
            
        except Exception as e:
            messagebox.showerror("Error", f"View failed: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = ModernFileClientGUI(root)
    root.mainloop()