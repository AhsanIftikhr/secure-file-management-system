# Secure File Management System

A Secure File Management System developed for the Information Security course using modern cryptographic techniques including AES encryption, RSA encryption, PKI, SHA-256 hashing, and Digital Signatures. The system provides secure file upload, encryption/decryption, certificate management, integrity verification, and audit logging using Flask and MySQL.

---

## Features

- Secure User Authentication
- AES File Encryption & Decryption
- RSA-Based Key Encryption
- SHA-256 Hash Generation & Verification
- PKI (Public Key Infrastructure)
- Digital Certificates
- Digital Signatures
- Certificate Revocation System
- Secure File Upload & Download
- Audit Logging & Activity Tracking

---

## Technologies Used

- Python
- Flask
- MySQL
- Cryptography Library
- HTML/CSS
- Bootstrap

---

## Project Structure

```bash
secure-file-management-system/
│
├── app.py
├── controllers/
├── models/
├── templates/
├── static/
├── scripts/
├── uploads/
└── requirements.txt
```

---

## Security Workflow

1. User uploads file
2. SHA-256 hash is generated
3. File is encrypted using AES
4. AES key is encrypted using RSA
5. Digital Signature is generated
6. Metadata is securely stored in database

---

## Installation & Setup

### 1. Clone Repository

```bash
git clone https://github.com/your-username/secure-file-management-system.git
cd secure-file-management-system
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Setup Database

Import the SQL file from:

```bash
scripts/setup_database.sql
```

Create a MySQL database and update database credentials in the project configuration if needed.

### 4. Run Application

```bash
python app.py
```

---

## Learning Outcomes

This project demonstrates practical implementation of:

- Symmetric Encryption (AES)
- Asymmetric Encryption (RSA)
- Public Key Infrastructure (PKI)
- Digital Signatures
- Cryptographic Hash Functions
- Secure Authentication
- Integrity Verification
- Secure File Handling

---

## Future Improvements

- Cloud Storage Integration
- Multi-Factor Authentication
- Role-Based Access Control
- Secure File Sharing
- Email Verification
- Real-Time Threat Monitoring

---

## Authors

Ahsan Iftikhar
03467575460
ahsan.iftikhar.7953@gmail.com
FAST NUCES

---
