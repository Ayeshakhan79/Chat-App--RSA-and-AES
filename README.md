# Chat-App-RSA-and-AES
A secure, hybrid AES+RSA chat application with a modern GUI built using CustomTkinter.

---

**It features:**

-End-to-end AES-encrypted chat messages.
-RSA key exchange for secure AES session keys.
-Emoji support 😍.
-Light theme with orange accents.
-Phone-style chat layout.

---

**Features**

1. Hybrid Encryption: Messages are encrypted with AES; AES keys are exchanged securely using RSA.
2. Real-time Chat: Client-server communication via Python sockets.
3. User-friendly GUI: Scrollable chat window, message bubbles, and emoji picker.
4. Phone-style design: Compact window suitable for a mobile-like interface.
5. Light Mode Theme: Professional light background with orange accent colors.

---

**Usage**

1. Start the Server
python server.py

2. Start the Client
python client.py

Each client generates RSA keys and an AES session key.
Clients exchange public keys to securely share AES keys.
All messages are AES-encrypted before being sent to the server.

**Security Notes**

Uses AES-256-CBC for message encryption.
AES session keys are exchanged securely using RSA-2048.
Each client has its own RSA key pair.
Messages are encrypted end-to-end, the server only forwards encrypted data.

<img width="823" height="425" alt="image" src="https://github.com/user-attachments/assets/80fb752a-b8b5-4557-b26e-a95a64781ae1" />

