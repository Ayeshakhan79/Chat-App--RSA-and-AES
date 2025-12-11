import customtkinter as ctk
import socket
import threading
import json
from tkinter import Toplevel, Button
from cryptography.hazmat.primitives import serialization
from  mainfile2 import (
    generate_keys,
    serialize_public_key,
    generate_aes_key,
    aes_encrypt,
    aes_decrypt,
    rsa_encrypt,
    rsa_decrypt
)

HOST = '127.0.0.1'
PORT = 65432

# ===== Generate RSA keys and session AES key =====
private_key, public_key = generate_keys()
session_aes_key = generate_aes_key()


class ChatClient(ctk.CTk):
    def __init__(self):
        super().__init__()

        # ===== Appearance & window =====
        ctk.set_appearance_mode("light")  # Light mode
        ctk.set_default_color_theme("dark-blue")  # Orange-friendly button theme
        self.title("ChatBot")
        self.geometry("350x650")  # Phone-style vertical layout
        self.configure(fg_color="#f5f5f5")

        # ===== Header =====
        self.header = ctk.CTkLabel(
            self,
            text="🤖 ChatBot",
            font=("Helvetica", 20, "bold"),
            text_color="#d35400"  # Orange header
        )
        self.header.pack(pady=(15, 10))

        # ===== Scrollable chat area =====
        self.chat_frame = ctk.CTkScrollableFrame(
            self,
            width=320, height=460,
            fg_color="#ffffff",
            border_width=0
        )
        self.chat_frame.pack(pady=(0, 10))
        self.chat_frame.grid_columnconfigure(0, weight=1)
        self.chat_frame.grid_columnconfigure(1, weight=1)
        self.message_widgets = []

        # ===== Bottom input frame =====
        self.bottom_frame = ctk.CTkFrame(self, fg_color="#f0f0f0")
        self.bottom_frame.pack(fill='x', padx=10, pady=10)

        self.msg_entry = ctk.CTkEntry(
            self.bottom_frame,
            width=220,
            placeholder_text="Type a message...",
            fg_color="#ffffff",
            text_color="#2c3e50",
            placeholder_text_color="#888888",
            border_width=0,
            corner_radius=10
        )
        self.msg_entry.pack(side='left', padx=(10, 5), pady=10, ipady=5)

        # ===== Emoji button =====
        self.emoji_button = ctk.CTkButton(
            self.bottom_frame,
            text="😀",
            command=self.open_emoji_picker,
            width=40,
            fg_color="#f39c12",
            hover_color="#e67e22",
            corner_radius=8
        )
        self.emoji_button.pack(side='left', padx=5, pady=10)

        # ===== Send button =====
        self.send_button = ctk.CTkButton(
            self.bottom_frame,
            text="Send",
            command=self.send_message,
            fg_color="#f39c12",
            hover_color="#e67e22",
            text_color="#ffffff",
            corner_radius=10
        )
        self.send_button.pack(side='left', padx=5, pady=10)

        # ===== Socket setup =====
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((HOST, PORT))
        serialized_pub = serialize_public_key(public_key)
        self.client_socket.send(serialized_pub.encode())

        self.clients_public_keys = {}
        self.aes_keys = {}  # AES key per client

        # ===== Receive thread =====
        self.running = True
        threading.Thread(target=self.receive_messages, daemon=True).start()

    # ===== Send message =====
    def send_message(self):
        message = self.msg_entry.get().strip()
        if not message:
            return

        for addr, aes_key in self.aes_keys.items():
            try:
                encrypted_msg = aes_encrypt(message, aes_key)
                self.client_socket.send(encrypted_msg)
                self.add_message_bubble(message, sender='me')
            except Exception as e:
                self.add_message_bubble(f"Error sending to {addr}: {e}", sender='system')

        self.msg_entry.delete(0, 'end')

    # ===== Receive messages =====
    def receive_messages(self):
        while self.running:
            try:
                data = self.client_socket.recv(8192)
                if not data:
                    break

                try:
                    # Try decrypting with AES
                    decrypted_msg = aes_decrypt(data, session_aes_key)
                    self.add_message_bubble(decrypted_msg, sender='other')
                except Exception:
                    try:
                        # If not AES, assume it's public keys JSON
                        keys_dict = json.loads(data.decode())
                        self.update_clients_public_keys(keys_dict)
                    except:
                        pass
            except Exception as e:
                self.add_message_bubble(f"Error: {e}", sender='system')
                self.running = False
                break

    # ===== Update clients' public keys =====
    def update_clients_public_keys(self, keys_dict):
        self.clients_public_keys.clear()
        for addr, key_str in keys_dict.items():
            if addr != str(self.client_socket.getsockname()):
                pub_key = serialization.load_pem_public_key(key_str.encode())
                self.clients_public_keys[addr] = pub_key
                # Encrypt session AES key for this client
                encrypted_aes_key = rsa_encrypt(pub_key, session_aes_key)
                self.client_socket.send(encrypted_aes_key)
                self.aes_keys[addr] = session_aes_key

        self.add_message_bubble("[Updated keys list]", sender='system')

    # ===== Chat bubble display =====
    def add_message_bubble(self, text, sender='other'):
        if sender == 'me':
            color = "#f39c12"
            anchor = 'e'
            column = 1
            text_color = "#ffffff"
        elif sender == 'other':
            color = "#ecf0f1"
            anchor = 'w'
            column = 0
            text_color = "#2c3e50"
        else:
            color = "#bdc3c7"
            anchor = 'center'
            column = 0
            text_color = "#2c3e50"

        bubble = ctk.CTkFrame(self.chat_frame, fg_color=color, corner_radius=12)
        label = ctk.CTkLabel(bubble, text=text, text_color=text_color,
                             font=("Helvetica", 13), wraplength=250, justify='left')
        label.pack(padx=10, pady=5)

        bubble.grid(row=len(self.message_widgets), column=column, sticky=anchor, padx=10, pady=5)
        self.message_widgets.append(bubble)
        self.chat_frame.update_idletasks()
        self.chat_frame._parent_canvas.yview_moveto(1.0)

    # ===== Emoji picker =====
    def open_emoji_picker(self):
        picker = Toplevel(self)
        picker.title("Select Emoji")
        picker.geometry("300x100")
        emojis = ["😀", "😂", "😍", "🤖", "❤️", "👍", "💬", "🔥", "😎", "🥳"]
        for e in emojis:
            btn = Button(picker, text=e, font=("Helvetica", 20),
                         command=lambda emoji=e: self.insert_emoji(emoji))
            btn.pack(side='left', padx=5, pady=5)

    def insert_emoji(self, emoji):
        current = self.msg_entry.get()
        self.msg_entry.delete(0, 'end')
        self.msg_entry.insert(0, current + emoji)

    # ===== Close client =====
    def on_closing(self):
        self.running = False
        self.client_socket.close()
        self.destroy()


if __name__ == "__main__":
    app = ChatClient()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()