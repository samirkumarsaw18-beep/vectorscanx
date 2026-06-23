# 🛡️ VectorScanX - Advanced Malware Detection Tool

VectorScanX is a Python-based malware detection tool that scans files using **YARA rules**, **SHA-256 hash verification**, and a simple graphical user interface (GUI). It helps users identify malicious files quickly and securely while providing an easy-to-use experience.

---

## 📌 Features

- 🔍 Scan files for malware
- 🛡️ Malware detection using YARA rules
- 🔐 SHA-256 hash verification
- 📁 Quarantine suspicious files
- 📊 Scan result reporting
- 🖥️ User-friendly GUI built with Tkinter
- ⚡ Fast and lightweight scanning

---

## 🛠️ Technologies Used

- Python 3.x
- Tkinter
- YARA
- hashlib
- JSON
- PyInstaller

---

## 📂 Project Structure

```
VectorScanX/
│── dist/
│── quarantine/
│── rules/
│── reports/
│── vectorscanx.py
│── test_gui.py
│── hash_checker.py
│── config.json
│── requirements.txt
│── README.md
```

---

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/samirkumarsaw18-beep/vectorscanx.git
```

### 2. Navigate to the Project

```bash
cd vectorscanx
```

### 3. Create a Virtual Environment (Recommended)

Windows

```bash
python -m venv venv
venv\Scripts\activate
```

Linux/macOS

```bash
python3 -m venv venv
source venv/bin/activate
```

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

---

# ▶️ Running the Application

Run the main application using:

```bash
python vectorscanx.py
```

or

```bash
python test_gui.py
```

(depending on your main entry file)

---

# 📦 Building the Executable

To generate a Windows executable:

```bash
pyinstaller --onefile --windowed vectorscanx.py
```

The executable will be generated inside the **dist/** folder.

---

# 🌐 Deployment

## GitHub Repository

Push your project to GitHub:

```bash
git init
git add .
git commit -m "Initial Commit"
git branch -M main
git remote add origin https://github.com/samirkumarsaw18-beep/vectorscanx.git
git push -u origin main
```

---

## GitHub Pages

This project is a **Python desktop application**, so GitHub Pages **cannot run the application**.

GitHub Pages can only host static files such as:

- HTML
- CSS
- JavaScript

You can use GitHub Pages to host:

- Project documentation
- Screenshots
- User Guide
- Download links

---

## Releasing the Application

To distribute the application:

1. Build the executable using PyInstaller.
2. Go to your GitHub repository.
3. Click **Releases**.
4. Create a new release.
5. Upload the executable from the **dist/** folder.

Users can then download and run the application without installing Python.


---

# 📈 Future Enhancements

- AI-based malware detection
- Cloud malware database
- Real-time protection
- Automatic signature updates
- Multi-threaded scanning
- Detailed PDF reports

---

# 🤝 Contributing

Contributions are welcome.

1. Fork the repository.
2. Create a new branch.

```bash
git checkout -b feature-name
```

3. Commit your changes.

```bash
git commit -m "Add new feature"
```

4. Push to GitHub.

```bash
git push origin feature-name
```

5. Open a Pull Request.

---

# 📄 License

This project is developed for educational and learning purposes.

---

# 👨‍💻 Developer

**Samir Kumar Saw**

MCA Student | Python Developer | Cybersecurity Enthusiast

GitHub:
https://github.com/samirkumarsaw18-beep

Project:
https://github.com/samirkumarsaw18-beep/vectorscanx

Live Demo:
https://samirkumarsaw18-beep.github.io/vectorscanx/

---

⭐ If you found this project useful, don't forget to star the repository!
