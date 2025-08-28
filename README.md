# 🔐 Cryptographic Tool (Caesar, ROT13, Atbash, MD5)

This is a **GUI-based Cryptography Utility** built with Python’s **Tkinter**.  
It allows users to **encrypt, decrypt, and hash text/files** with multiple classical cryptography techniques.


## 📂 Project Structure

📁 your-project-folder/  
├── crypto_tool.py         # Main GUI application (encryption/decryption tool)  
├── requirements.txt       # Python dependencies  
├── run_crypto_tool.bat    # Batch script for launching on Windows  
└── README.md              # Documentation  

---

## ⚙️ Requirements

Python version: **Python 3.8+ recommended**

Dependencies listed in `requirements.txt`:

```text
tkinter   # GUI framework (usually bundled with Python)
hashlib   # Standard library for hashing
```

*(Note: `tkinter` may need to be installed separately on Linux.)*

---

## 🖥️ How to Run

### ✅ On **Windows**:

1. Open **PowerShell / CMD** and navigate to your project folder:

   ```powershell
   cd "C:\path\to\your\project"
   ```

2. Create a virtual environment (optional but recommended):

   ```powershell
   python -m venv .env
   .\.env\Scripts\activate
   ```

3. Install dependencies:

   ```powershell
   pip install -r requirements.txt
   ```

4. Run the tool:

   ```powershell
   python crypto_tool.py
   ```

   Or double-click **`run_crypto_tool.bat`**.

---

### ✅ On **Kali Linux / Ubuntu**:

1. Open Terminal and navigate to your project folder:

   ```bash
   cd /path/to/your/project
   ```

2. (Optional) Create virtual environment:

   ```bash
   python3 -m venv .env
   source .env/bin/activate
   ```

3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Run the tool:

   ```bash
   python3 crypto_tool.py
   ```

---

## 📊 Output

The GUI provides:

* **Encrypted/Decrypted text** (Caesar, ROT13, Atbash)  
* **MD5 Hash results** for text or files  
* Copy button to save output to clipboard  

---

## 🔍 Features

* **Caesar Cipher** → Encrypt/Decrypt with shift (1–25)  
* **ROT13 Cipher** → Quick reversible text scrambling  
* **Atbash Cipher** → Simple substitution (A ↔ Z, B ↔ Y, etc.)  
* **MD5 Hashing** → Text hashing + File checksum calculation  
* **Dark Theme GUI** with modern design  
* **Clipboard Copy Button** for output  
* **Status Bar** for real-time progress  
* **Keyboard Shortcuts**:  
  - `F5` → Process  
  - `Esc` → Clear fields  

---

## 🛠 Troubleshooting

* If GUI doesn’t launch, ensure you’re running **Python 3.8+**.  
* On Linux, you may need to install Tkinter manually:  

  ```bash
  sudo apt-get install python3-tk
  ```  

* **MD5 is one-way** → cannot decrypt hashed values.  
