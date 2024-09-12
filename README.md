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

To install the package, run the following command:

```bash
pip install power-platform-security-assessment
```

## Usage

Run the security assessment tool:
```sh
power-platform-security-assessment 
```

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.