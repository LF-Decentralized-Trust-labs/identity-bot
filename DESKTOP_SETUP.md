# Identity Agent - Desktop Setup Guide

## Windows Setup (Required for Desktop Testing)

The Windows builds do not include an embedded Python runtime, which keeps build time and download size down. You must install Python and its dependencies on your system manually.

### System Requirements

- **Python**: 3.10 or later (3.12+ recommended)
- **pip**: Package installer for Python
- **Flask**: Web framework for the KERI driver
- **KERI**: WebOfTrust KERI library v1.1.17
- **libsodium**: Bundled in the app — no action needed

### Setup Instructions

#### 1. Install Python

Download and install from [python.org](https://www.python.org/downloads/) (Windows 64-bit installer for x86_64)

**Important**: During installation, check the box **"Add Python to PATH"**

Verify installation:
```powershell
python --version
pip --version
```

Should show Python 3.10+ and pip version.

#### 2. Install Required Packages

```powershell
pip install flask keri==1.1.17
```

Verify installation:
```powershell
pip list | findstr /i flask
pip list | findstr /i keri
```

Both should show installed. Note: use `/i` flag for case-insensitive search — Flask appears as "Flask" (capital F) in pip list.

#### 3. Verify Python Location

The Identity Agent will automatically find Python via the system PATH. To verify:
```powershell
where python
```

Should output something like: `C:\Users\YourUsername\AppData\Local\Programs\Python\Python312\python.exe`

#### 4. Run Identity Agent

Unzip the `identity-agent-windows-x64.zip` produced by the Windows build to any location and run:
```
.\identity-agent-windows-x64-v6\identity_agent_ui.exe
```

The app will automatically locate Python and its dependencies from your PATH.

### Troubleshooting

**Error: "Python not found"**
- Verify Python is in your PATH: `python --version` in PowerShell
- If not found, reinstall Python with "Add Python to PATH" checked
- Restart your computer after installation

**Error: "flask not found" or "keri not found"**
```powershell
pip install flask keri==1.1.17 --upgrade
```

**Error: "libsodium not found"**
- Usually auto-installed with `keri` package
- If needed manually: `pip install libsodium`

### Build Time Savings

By not embedding Python in the Windows build:
- **Build time reduced**: ~13 minutes → ~6 minutes (50% faster)
- **ZIP size reduced**: ~800-1000MB → ~200-300MB
- **Unzip time reduced**: ~4 minutes → ~30 seconds
- **Your system**: Requires Python installation (one-time setup)

---

## macOS / Linux Setup

For macOS and Linux desktop builds, Python and dependencies are automatically included in the archive (embedded runtime not yet optimized).

Verify your system Python for manual testing:
```bash
python3 --version
pip3 install flask keri==1.1.17
```
