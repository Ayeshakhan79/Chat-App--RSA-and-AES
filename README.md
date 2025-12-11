# CryptoTalk - Chat App
A secure, hybrid AES+RSA chat application with a modern GUI built using CustomTkinter.

---

**Features**

1. Hybrid Encryption: Messages are encrypted with AES; AES keys are exchanged securely using RSA.
2. Real-time Chat: Client-server communication via Python sockets.
3. User-friendly GUI: Scrollable chat window, message bubbles, and emoji picker.
4. Phone-style design: Compact window suitable for a mobile-like interface.
5. Light Mode Theme: Professional light background with orange accent colors.

---

**Cryptography Algorithms Used**

1. AES (Advanced Encryption Standard) – Symmetric Encryption:

Used to encrypt the actual message.
Fast and efficient for large amounts of data.
Mode: CBC (Cipher Block Chaining)
Padding: PKCS7 to ensure the message fits the AES block size.

2. RSA (Rivest–Shamir–Adleman) – Asymmetric Encryption

Used to encrypt the AES key for secure transmission.
Ensures that only the receiver with the private key can decrypt the AES key.
Key Size: 2048 bits

3. OAEP (Optimal Asymmetric Encryption Padding)

A secure padding scheme used with RSA encryption.
Protects RSA from certain cryptographic attacks.

4. SHA-256 (Secure Hash Algorithm)

Used inside OAEP for padding in RSA encryption.
Ensures the padding is secure and prevents patterns that attackers could exploit.
Base64 Encoding
Converts encrypted bytes into a string-safe format for storage or transmission.

---

**How They Work Together**

AES encrypts the message → produces a ciphertext.
RSA + OAEP + SHA-256 encrypts the AES key → produces a secure key that can be safely shared.
Receiver decrypts the AES key using RSA private key, then decrypts the message using AES.

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

