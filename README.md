# Power Platform Quick Assessment Tool

Open Source Risk Assessment Tool for Power Platform

With citizen developers' widespread adoption of Microsoft Power Platform, security teams are challenged to evaluate the
risks and vulnerabilities created by these business users.

To assess your risk exposure, Kanopy Security developed "Power Platform Quick Assessment Tool", a lightweight, open-source assessment tool that you can
easily run locally/on-premise.  
Its purpose is to provide a quick and informative view of your Power Platform
environments - development and production - and help you understand the size of your attack surface and prominent
security issues.  
Receive an easily shareable report with stats on your environments, components, and connectors and insights into
vulnerabilities.

If you need help with this tool, please contact us at support@kanopysecurity.com.


## Requirements

- Python 3.9 or later - only needed if you don't use the [Quick start](#quick-start) below.
- A web browser on the same machine - the tool opens a Microsoft sign-in page to authenticate.

The following Power Platform privileges are required for the tool to run:  
- Power Platform administrator (or a global administrator).
- Explicit "system administrator" privileges for each of the environments that are scanned.

## Quick start

The easiest way to run the tool is with [uv](https://docs.astral.sh/uv/). You don't need Python installed:
uv uses a compatible Python if you have one, and downloads one if you don't.

### Windows

Open **PowerShell** and install uv (already have uv? You can skip this step):
```powershell
winget install --id=astral-sh.uv -e
```
<details>
<summary>No winget? Use the official installer instead</summary>

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```
</details>

Close PowerShell, open a new one, and run the tool:
```powershell
uvx power-platform-security-assessment@latest
```

### macOS

Open **Terminal** and install uv (already have uv? You can skip this step):
```bash
brew install uv
```
<details>
<summary>No Homebrew? Use the official installer instead</summary>

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```
</details>

Close Terminal, open a new one, and run the tool:
```bash
uvx power-platform-security-assessment@latest
```

### Linux

Install uv (already have uv? You can skip this step), then run the tool:
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
# open a new terminal, then:
uvx power-platform-security-assessment@latest
```

A browser window opens where you pick the Microsoft account to use. When the scan finishes, the report is saved
as `power_platform_scan_report.html` in the folder you ran the command from.

> `@latest` makes sure you run the newest version, even if you ran the tool before.

## Other ways to install

If you prefer not to use uv, or your organization doesn't allow it, you can install the tool with pipx or pip
(requires Python 3.9 or later). If your Python is older, install a current version from
[python.org](https://www.python.org/downloads/).

> On Windows, if `python` is not found, use `py` instead (e.g. `py -m venv venv`).

### Using pipx
pipx installs the package in an isolated environment and makes it available globally (works on all platforms).

First, install pipx following the [official installation guide](https://github.com/pypa/pipx?tab=readme-ov-file#install-pipx),
including the `pipx ensurepath` step, then open a new terminal.

Then install the tool:
```bash
pipx install power-platform-security-assessment
```

### Using uv
```bash
# Create virtual environment
uv venv

# Install the package
uv pip install power-platform-security-assessment
```

### Using pip
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
source venv/bin/activate      # macOS/Linux
venv\Scripts\activate         # Windows (Command Prompt)
venv\Scripts\Activate.ps1     # Windows (PowerShell)

# Install the package
pip install power-platform-security-assessment
```

## Usage

### If installed with pipx
Run the security assessment tool directly:
```bash
power-platform-security-assessment
```

### If installed with pip or uv
First activate your virtual environment, then run the tool:

```bash
# If installed with uv
source .venv/bin/activate      # macOS/Linux
.venv\Scripts\activate         # Windows (Command Prompt)
.venv\Scripts\Activate.ps1     # Windows (PowerShell)

# If installed with pip
source venv/bin/activate       # macOS/Linux
venv\Scripts\activate          # Windows (Command Prompt)
venv\Scripts\Activate.ps1      # Windows (PowerShell)

# Run the tool
power-platform-security-assessment
```

The tool opens a browser window where you pick (or sign in to) the Microsoft account to use, scans your environments,
and saves the report as `power_platform_scan_report.html` in the current directory.

## Available Arguments

- `--debug`: Enables debug mode with additional logging.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.