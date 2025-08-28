🔐 Cryptographic Tool (Caesar, ROT13, Atbash, MD5)

This is a GUI-based Cryptography Utility built with Python’s Tkinter.
It allows users to encrypt, decrypt, and hash text/files with multiple classical cryptography techniques.

📂 Project Structure

📁 your-project-folder/
├── crypto_tool.py # Main GUI application (encryption/decryption tool)
├── requirements.txt # Python dependencies
├── run_crypto_tool.bat # Batch script for launching on Windows
└── README.md # Documentation

⚙️ Requirements

Python 3.8+ recommended

Dependencies listed in requirements.txt

tk
hashlib


(Tkinter and hashlib are included with Python standard library, so no external installs needed — but requirements.txt is provided for completeness.)

🖥️ How to Run
✅ On Windows

Open PowerShell / CMD, navigate to your project folder:

cd "C:\path\to\your\project"


(Optional) Create virtual environment:

python -m venv .env
.\.env\Scripts\activate


Install dependencies:

pip install -r requirements.txt


Run the tool:

python crypto_tool.py


Or simply double-click run_crypto_tool.bat.

✅ On Linux / Kali

Open Terminal, navigate to your project folder:

cd /path/to/your/project


(Optional) Create virtual environment:

python3 -m venv .env
source .env/bin/activate


Install dependencies:

pip install -r requirements.txt


Run the tool:

python3 crypto_tool.py

🔍 Features

Caesar Cipher → Encrypt/Decrypt with user-defined shift (1–25)

ROT13 → Quick text scrambling (reversible)

Atbash Cipher → Simple substitution (A ↔ Z, B ↔ Y, etc.)

MD5 Hashing →

Hash any text input

Upload a file and calculate MD5 checksum

🛠 Extras

Dark theme GUI with styled widgets

Clipboard copy button for output

File selection support for MD5

Status bar with real-time updates

Keyboard shortcuts:

F5 → Process

Esc → Clear fields

📊 Output

Encrypted / Decrypted text shown in Output Box

MD5 Hash result for text or file

Copy button to quickly save results

🛠 Troubleshooting

If GUI doesn’t open, make sure you are running with Python 3.8+.

On Linux, you may need to install Tkinter separately:

sudo apt-get install python3-tk


MD5 Hash is one-way (cannot decrypt).
