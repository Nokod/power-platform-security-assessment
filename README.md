# PowerProbe

Open Source Risk Assessment Tool for Power Platform

With citizen developers' widespread adoption of Microsoft Power Platform, security teams are challenged to evaluate the
risks and vulnerabilities created by these business users.

To assess your risk exposure, Nokod developed "PowerProbe", a lightweight, open-source assessment tool that you can
easily run locally/on-premise.
Its purpose is to provide a quick and informative view of your Power Platform
environments - development and production - and help you understand the size of your attack surface and prominent
security issues.
Receive an easily shareable report with stats on your environments, components, and connectors and insights into
vulnerabilities.

If you need help with this tool, please contact us at support@nokodsecurity.com.


## Features

- **Token Acquisition**: Uses Microsoft Authentication Library (MSAL) to acquire access tokens.
- **Environment Fetching**: Retrieves environment details from the Power Platform.
- **Security Assessment**: Runs security assessments on the fetched environments.
- **Report Generation**: Generates a report with the security assessment results. The report is saved in the current working directory.

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

## Contributing

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Make your changes.
4. Commit your changes (`git commit -m 'Add some feature'`).
5. Push to the branch (`git push origin feature-branch`).
6. Open a pull request.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.