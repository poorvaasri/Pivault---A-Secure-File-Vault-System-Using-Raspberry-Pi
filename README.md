# Pivault---A-Secure-File-Vault-System-Using-Raspberry-Pi

Aim:
The aim of this project is to develop a secure, user-friendly file vault system named PiVault that allows users to encrypt, decrypt, and manage confidential files safely using a password-protected interface. The system is designed to work efficiently on a Raspberry Pi, making it ideal for low-cost personal or portable security solutions.

Overview:
PiVault is a desktop-based application built using Python that provides secure file storage through encryption. It utilizes Fernet symmetric encryption from the cryptography library to protect sensitive files. A GUI developed using Tkinter and ttkthemes makes the system easy to use, even for non-technical users.

When a user uploads a file, it is encrypted and stored inside a dedicated vault folder. Simultaneously, the original file is overwritten with dummy content to prevent unauthorized recovery. For every encryption or decryption activity, a log entry is created with a timestamp, providing transparency and traceability of actions. The system is protected with a password authentication mechanism, where the password is securely hashed and verified during login.

The user interface features options to:

Upload and encrypt a file

View contents of the vault

Decrypt and restore a file to a specified location

View a detailed log of activities

Logout and exit the application

All functionalities are designed to run seamlessly on a Raspberry Pi, ensuring low resource usage while maintaining security.

Conclusion:
PiVault provides a lightweight yet powerful solution for file security on Raspberry Pi systems. It combines encryption, authentication, and logging into a single tool, making it ideal for personal data protection. Future improvements can include biometric login, cloud backup integration, and multi-user support, expanding its utility for both personal and small organizational use.


