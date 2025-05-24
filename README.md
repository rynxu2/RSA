# Secure File Transfer


### Introduction
A secure file transfer system with digital signatures, allowing users to create/join rooms and share files securely. Built with Flask and SQLite, supporting RSA encryption and SHA256 hash verification.

### Key Features
- 🔐 User authentication (register/login)
- 🔑 Individual public/private key pairs per user
- 🚪 Create and join password-protected rooms
- 📤 File uploads with automatic digital signatures
- ✅ File integrity and source verification
- 🔄 Real-time updates with Socket.IO
- 🎨 Modern, user-friendly interface

### Installation
1. Clone repository and install dependencies:
```bash
git clone <repository-url>
cd RSA
pip install -r requirements.txt
```

2. Run server:
```bash
python app.py
```

### Usage
1. Register a new account or login
2. Create a new room or join existing room with ID and password
3. Upload files - they'll be automatically signed with your private key
4. To verify files, click "Verify" and input sender's public key
5. Copy sender's public key using "Public Key" button next to each file

### Security
- Passwords are hashed using SHA256
- Files are signed using 2048-bit RSA private keys
- Verification based on file's SHA256 hash
- Password-protected rooms
- Encrypted session handling

### Dependencies
- Flask
- Flask-SocketIO
- Flask-SQLAlchemy
- cryptography
- Werkzeug
- SQLite3

### Development
Made with ❤️ using Python and modern web technologies.
