# WindowsRepairTool
Download Here: https://github.com/reyjanolino/WindowsRepairTool/releases


# 🛠️ Windows Repair Tool

A powerful, all-in-one Windows maintenance toolkit written in PowerShell with a user-friendly WinForms GUI. Designed to streamline system repair, network diagnostics, registry management, app updates, and more — all in one portable script.

---

## 📋 Features

### 🔧 System Repair
- Re-register core system apps (Windows Store, Settings, etc.)
- Run SFC and DISM scans
- Reset Windows Update components
- Create and restore System Restore points
- Backup and restore BCD

### 🌐 Network Tools
- Flush DNS, reset Winsock, release/renew IP
- Configure Encrypted DNS (DoH)
- Diagnose internet connectivity
- Clear proxy settings

### 🗂️ Registry Manager
- Backup and restore full registry
- Auto-backup registry with timestamped files (enable RegBack)
- Import/export `.reg` files
- Integrated into the GUI with log output

### 📦 App Management
- Detect upgradable apps via Winget (even if not originally installed via Winget)
- Selectively upgrade outdated applications
- Handle source sync issues and common Winget errors

### 📊 System Info Viewer
- Display hardware information (CPU, RAM, GPU, etc.)
- Windows version and system uptime

---

## 🖼️ GUI Overview

The tool uses WinForms to provide a tab-based layout, including:

- **System Repair**
- **Network Tools**
- **Registry Manager**
- **Extras**
- **System Info**

---

## 📁 Installation

> No installation required — just run the script as Administrator.

### ✅ Prerequisites
- Windows 10 or 11
- PowerShell 5.1+
- Administrator privileges

### ▶️ How to Run

download the .exe file and run as administrator
