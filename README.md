# Power Platform Security Assessment Tool

An open source application that can be used locally to extract information from your Power Platform tenant and display compelling stats that hint at the size of the attack surface and severity of the threat.

## Features

- **Token Acquisition**: Uses Microsoft Authentication Library (MSAL) to acquire access tokens.
- **Environment Fetching**: Retrieves environment details from the Power Platform.
- **Security Assessment**: Runs security assessments on the fetched environments.

## Installation

To install the package, run the following command:

```bash
python3 -m pip install power-platform-security-assessment
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