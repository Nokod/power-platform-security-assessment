# Power Platform Quick Assessment Tool

Open Source Risk Assessment Tool for Power Platform

With citizen developers' widespread adoption of Microsoft Power Platform, security teams are challenged to evaluate the
risks and vulnerabilities created by these business users.

To assess your risk exposure, Nokod developed "Power Platform Quick Assessment Tool", a lightweight, open-source assessment tool that you can
easily run locally/on-premise.  
Its purpose is to provide a quick and informative view of your Power Platform
environments - development and production - and help you understand the size of your attack surface and prominent
security issues.  
Receive an easily shareable report with stats on your environments, components, and connectors and insights into
vulnerabilities.

If you need help with this tool, please contact us at support@nokodsecurity.com.


## Requirements

The following Power Platform privileges are required for the tool to run:  
- Power Platform administrator (or a global administrator).
- Explicit "system administrator" privileges for each of the environments that are scanned.

## Installation

You can install the package using pipx (recommended), pip, or [uv](https://docs.astral.sh/uv/).

### Using pipx (recommended)
pipx installs the package in an isolated environment and makes it available globally (works on all platforms).

First, install pipx following the [official installation guide](https://github.com/pypa/pipx?tab=readme-ov-file#install-pipx).

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
source venv/bin/activate   # macOS/Linux
venv\Scripts\activate      # Windows

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
source .venv/bin/activate   # macOS/Linux
.venv\Scripts\activate      # Windows

# If installed with pip
source venv/bin/activate    # macOS/Linux
venv\Scripts\activate       # Windows

# Run the tool
power-platform-security-assessment
```

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.