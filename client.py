import socket
import threading
import json
import struct
import time
import hashlib
import logging
import base64
import tkinter as tk
from tkinter import messagebox, filedialog, scrolledtext
from tkinter import ttk

from encryption import encrypt_message, decrypt_message

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

SERVER_HOST = '127.0.0.1'
SERVER_PORT = 12345

#networking helper funcions
def send_json(sock, data_dict):
    message_str = json.dumps(data_dict)
    message_bytes = message_str.encode('utf-8')
    length_prefix = struct.pack('>I', len(message_bytes))
    sock.sendall(length_prefix + message_bytes)

def recv_json(sock):
    raw_len = sock.recv(4)
    if not raw_len:
        return None
    msg_len = struct.unpack('>I', raw_len)[0]
    chunks = []
    received = 0
    while received < msg_len:
        chunk = sock.recv(msg_len - received)
        if not chunk:
            return None
        chunks.append(chunk)
        received += len(chunk)
    data_str = b''.join(chunks).decode('utf-8')
    return json.loads(data_str)



#GUI 
#Define the colors
BG_DARK = "#333333"         #login screen
BG_LIGHT = "#ffffff"        #chat screen
MSG_BG_SENT = "#ADD8E6"     #message bubble
MSG_BG_RECEIVED = "#f8f8f8"  #received message bubble
BUTTON_COLOUR = "#0066cc"    #button background
ONLINE_COLOUR = "#4CAF50"    #online users
OFFLINE_COLOUR = "#F44336"   #offline users

class ClientApp:
    def __init__(self, master):
        #initialize the GUI
        self.master = master
        master.title("LU-Connect Login")
        master.geometry("400x300")
        master.configure(bg=BG_DARK)

        #ttk style for the login window
        self.style = ttk.Style()
        self.style.theme_use("clam")
        self.style.configure("TLabel", background=BG_DARK, foreground=BG_LIGHT, font=("Segoe UI", 10))
        self.style.configure("Header.TLabel", background=BG_DARK, foreground=BG_LIGHT, font=("Segoe UI", 18, "bold"))
        self.style.configure("TFrame", background=BG_DARK)
        self.style.configure("TButton", background=BUTTON_COLOUR, foreground="#ffffff", font=("Segoe UI", 10), padding=5)

        #Title label
        self.title_label = ttk.Label(master, text="Welcome to LU-Connect", style="Header.TLabel")
        self.title_label.pack(pady=20)

        #Waiting updates label
        self.waiting_label = ttk.Label(master, text="", style="TLabel")
        self.waiting_label.pack(pady=5)

        #Login frame for username and password
        self.login_frame = ttk.Frame(master)
        self.login_frame.pack(pady=10, padx=20, fill="x")

        ttk.Label(self.login_frame, text="Username:").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.username_entry = ttk.Entry(self.login_frame, width=25)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(self.login_frame, text="Password:").grid(row=1, column=0, sticky="e", padx=5, pady=5)
        self.password_entry = ttk.Entry(self.login_frame, show="*", width=25)
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)

        #Buttons frame for Login and Sign Up
        self.button_frame = ttk.Frame(master)
        self.button_frame.pack(pady=15)

        self.login_button = ttk.Button(self.button_frame, text="Login", command=self.login)
        self.login_button.grid(row=0, column=0, padx=10)

        self.signup_button = ttk.Button(self.button_frame, text="Sign Up", command=self.signup)
        self.signup_button.grid(row=0, column=1, padx=10)

        self.socket = None
        self.muted = False
        self.username = None

    def connect_to_server(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((SERVER_HOST, SERVER_PORT))
            self.listener_thread = threading.Thread(target=self.listen_server, daemon=True)
            self.listener_thread.start()
        except Exception as e:
            messagebox.showerror("Connection Error", f"Failed to connect to server: {e}")
            logging.error("Connection error: %s", e)
    #read and process messages from server
    def listen_server(self):
        while True:
            try:
                message = recv_json(self.socket)
                if not message:
                    break
                msg_type = message.get("type")
                if msg_type == "waiting":
                    time_wait = message.get("time")
                    self.waiting_label.config(text=f"Waiting time: {time_wait} seconds")
                elif msg_type == "connected":
                    self.waiting_label.config(text="Connected to server")
                elif msg_type == "signup":
                    status = message.get("status")
                    if status == "success":
                        messagebox.showinfo("Sign Up", "Sign up successful, please log in.")
                    else:
                        error = message.get("error", "Error")
                        messagebox.showerror("Sign Up Failed", error)
                elif msg_type == "login":
                    status = message.get("status")
                    if status == "success":
                        self.open_chat_window()
                    else:
                        error = message.get("error", "Error")
                        messagebox.showerror("Login Failed", error)
                elif msg_type == "get_users":
                    all_users = message.get("all_users", [])
                    online_users = message.get("online_users", [])
                    self.update_user_list(all_users, online_users)
                elif msg_type == "message":
                    sender = message.get("from")
                    content_enc = message.get("content")
                    timestamp = message.get("timestamp")
                    try:
                        content = decrypt_message(content_enc)
                    except Exception:
                        content = "[Decryption Error]"
                    if hasattr(self, 'chat_text'):
                        self.chat_text.config(state="normal")
                        self.chat_text.insert(tk.END, f"{content}\n", "other_msg")
                        self.chat_text.insert(tk.END, f"{timestamp} - {sender}\n\n", ("timestamp", "other_msg"))
                        self.chat_text.config(state="disabled")
                        self.chat_text.see(tk.END)
                    if not self.muted:
                        self.master.bell()
                elif msg_type == "file":
                    sender = message.get("from")
                    filename = message.get("filename")
                    filedata_enc = message.get("filedata")
                    timestamp = message.get("timestamp")
                    try:
                        filedata_b64 = decrypt_message(filedata_enc)
                        filedata = base64.b64decode(filedata_b64)
                        with open(f"received_{filename}", "wb") as f:
                            f.write(filedata)
                    except Exception as e:
                        logging.error("File decryption/saving error: %s", e)
                        filename = "Error processing file"
                    if hasattr(self, 'chat_text'):
                        self.chat_text.config(state="normal")
                        self.chat_text.insert(tk.END, f"[File Received] {filename}\n", "other_msg")
                        self.chat_text.insert(tk.END, f"{timestamp} - {sender}\n\n", ("timestamp", "other_msg"))
                        self.chat_text.config(state="disabled")
                        self.chat_text.see(tk.END)
                    if not self.muted:
                        self.master.bell()
                else:
                    logging.warning("Unknown message type received: %s", msg_type)
            except Exception as e:
                logging.error("Error in listener: %s", e)
                break
    #connect to server and request sign up
    def signup(self):
        self.connect_to_server()
        username = self.username_entry.get()
        password = self.password_entry.get()
        pwd_hash = hashlib.sha256(password.encode()).hexdigest()
        signup_msg = {"type": "signup", "username": username, "password_hash": pwd_hash}
        try:
            send_json(self.socket, signup_msg)
        except Exception as e:
            logging.error("Error during signup request: %s", e)
    #Connect to server and request login
    def login(self):
        self.connect_to_server()
        self.username = self.username_entry.get()
        password = self.password_entry.get()
        pwd_hash = hashlib.sha256(password.encode()).hexdigest()
        login_msg = {"type": "login", "username": self.username, "password_hash": pwd_hash}
        try:
            send_json(self.socket, login_msg)
        except Exception as e:
            logging.error("Error during login request: %s", e)

    def open_chat_window(self):
        self.chat_window = tk.Toplevel(self.master)
        self.chat_window.title(f"LU-Connect - {self.username}")
        self.chat_window.geometry("600x500")
        self.chat_window.configure(bg=BG_LIGHT)

        #Top frame with header
        top_frame = ttk.Frame(self.chat_window)
        top_frame.pack(fill="x", pady=10)
        self.style.configure("Chat.TFrame", background=BG_LIGHT)
        self.style.configure("Chat.TLabel", background=BG_LIGHT, foreground=BG_DARK, font=("Segoe UI", 16, "bold"))
        header = ttk.Label(top_frame, text=f"Chat Room - {self.username}", style="Chat.TLabel")
        header.pack()

        #Main frame holds the user list and chat area
        main_frame = ttk.Frame(self.chat_window, style="Chat.TFrame")
        main_frame.pack(fill="both", expand=True, padx=10, pady=5)

        #Left frame for the user list
        left_frame = ttk.Frame(main_frame, style="Chat.TFrame")
        left_frame.pack(side="left", fill="y", padx=(0, 5))
        label_users = ttk.Label(left_frame, text="Registered Users", style="Chat.TLabel")
        label_users.pack(pady=5)
        self.user_listbox = tk.Listbox(left_frame, width=20, height=15, bg=BG_LIGHT, fg=BG_DARK)
        self.user_listbox.pack(fill="y")

        #Right frame for the chat text area
        right_frame = ttk.Frame(main_frame, style="Chat.TFrame")
        right_frame.pack(side="right", fill="both", expand=True)
        self.chat_text = scrolledtext.ScrolledText(right_frame, state="disabled", wrap="word",
                                                    font=("Segoe UI", 10), bg=BG_LIGHT, fg=BG_DARK)
        self.chat_text.pack(fill="both", expand=True)


        self.chat_text.tag_config("my_msg", background=MSG_BG_SENT, foreground=BG_DARK,
                                  justify="right", spacing3=5, lmargin1=50, rmargin=10)
        self.chat_text.tag_config("other_msg", background=MSG_BG_RECEIVED, foreground=BG_DARK,
                                  justify="left", spacing3=5, lmargin1=10, rmargin=50)
        self.chat_text.tag_config("timestamp", foreground=BG_DARK, font=("Segoe UI", 8, "italic"))

        #Bottom frame for message entry and control buttons
        bottom_frame = ttk.Frame(self.chat_window, style="Chat.TFrame")
        bottom_frame.pack(fill="x", padx=10, pady=10)
        self.msg_entry = ttk.Entry(bottom_frame, width=40)
        self.msg_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        self.msg_entry.bind("<Return>", lambda event: self.send_message())
        self.send_button = ttk.Button(bottom_frame, text="Send", command=self.send_message)
        self.send_button.pack(side="left", padx=5)
        self.file_button = ttk.Button(bottom_frame, text="Send File", command=self.send_file)
        self.file_button.pack(side="left", padx=5)
        self.mute_button = ttk.Button(bottom_frame, text="Mute", command=self.toggle_mute)
        self.mute_button.pack(side="left", padx=5)

        try:
            send_json(self.socket, {"type": "get_users"})
        except Exception as e:
            logging.error("Error requesting user list: %s", e)
        self.auto_refresh()

    def auto_refresh(self):
        #refresh user list
        try:
            send_json(self.socket, {"type": "get_users"})
        except Exception as e:
            logging.error("Error sending get_users request: %s", e)
        if self.chat_window:
            self.chat_window.after(5000, self.auto_refresh)
    #update users with online and offline colours
    def update_user_list(self, all_users, online_users):
        self.user_listbox.delete(0, tk.END)
        for user in all_users:
            if user == self.username:
                continue
            if user in online_users:
                symbol = "● "
                color = ONLINE_COLOUR
            else:
                symbol = "○ "
                color = OFFLINE_COLOUR
            final_text = symbol + user
            self.user_listbox.insert(tk.END, final_text)
            pos = self.user_listbox.size() - 1
            self.user_listbox.itemconfig(pos, fg=color)
    #send message to user
    def send_message(self):
        selection = self.user_listbox.curselection()
        if not selection:
            messagebox.showerror("Error", "Select a user to send a message.")
            return
        selected_text = self.user_listbox.get(selection[0])
        target = selected_text.split(maxsplit=1)[-1].strip()
        content = self.msg_entry.get()
        if not content:
            return
        try:
            encrypted_content = encrypt_message(content)
        except Exception as e:
            logging.error("Error encrypting message: %s", e)
            return
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        msg = {
            "type": "message",
            "from": self.username,
            "to": target,
            "content": encrypted_content,
            "timestamp": timestamp
        }
        try:
            send_json(self.socket, msg)
        except Exception as e:
            logging.error("Error sending message: %s", e)
        self.chat_text.config(state="normal")
        self.chat_text.insert(tk.END, f"{content}\n", "my_msg")
        self.chat_text.insert(tk.END, f"{timestamp} - Me\n\n", ("timestamp", "my_msg"))
        self.chat_text.config(state="disabled")
        self.chat_text.see(tk.END)
        self.msg_entry.delete(0, tk.END)
    #send file to selected user
    def send_file(self):
        selection = self.user_listbox.curselection()
        if not selection:
            messagebox.showerror("Error", "Select a user to send a file.")
            return
        selected_text = self.user_listbox.get(selection[0])
        target = selected_text.split(maxsplit=1)[-1].strip()
        filepath = filedialog.askopenfilename()
        if not filepath:
            return
        if not filepath.lower().endswith((".docx", ".pdf", ".jpeg", ".jpg", ".png")):
            messagebox.showerror("Error", "File type not allowed")
            return
        try:
            with open(filepath, "rb") as f:
                filedata = f.read()
            filedata_b64 = base64.b64encode(filedata).decode("utf-8")
            encrypted_filedata = encrypt_message(filedata_b64)
        except Exception as e:
            logging.error("Error processing file for sending: %s", e)
            messagebox.showerror("File Error", "Could not process the file.")
            return
        filename = filepath.split("/")[-1]
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        msg = {
            "type": "file",
            "from": self.username,
            "to": target,
            "filename": filename,
            "filedata": encrypted_filedata,
            "timestamp": timestamp
        }
        try:
            send_json(self.socket, msg)
        except Exception as e:
            logging.error("Error sending file message: %s", e)
        self.chat_text.config(state="normal")
        self.chat_text.insert(tk.END, f"[File Sent] {filename}\n", "my_msg")
        self.chat_text.insert(tk.END, f"{timestamp} - Me\n\n", ("timestamp", "my_msg"))
        self.chat_text.config(state="disabled")
        self.chat_text.see(tk.END)
    #sound for notification(can be muted)
    def toggle_mute(self):
        self.muted = not self.muted
        self.mute_button.config(text="Unmute" if self.muted else "Mute")

if __name__ == "__main__":
    root = tk.Tk()
    app = ClientApp(root)
    root.mainloop()
