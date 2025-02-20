# Email Security Detector

A Chrome extension that helps detect potential phishing attempts and security risks in emails. This extension works with Gmail and Outlook, providing real-time analysis of email content for potential security threats.

## Features

-  Real-time email analysis
-  Phishing attempt detection
-  Fast, client-side processing (no external APIs)
-  Support for Gmail and Outlook
-  Privacy-focused (all analysis happens locally)
-  Risk score calculation
-  Detailed security warnings

## Installation

1. Clone this repository:
```bash
git clone https://github.com/DhruvKapadia00/email-security-detector.git
```

2. Open Chrome and navigate to `chrome://extensions/`
3. Enable "Developer mode" in the top right
4. Click "Load unpacked" and select the extension directory

## How It Works

The extension analyzes emails using various heuristics to detect potential security risks:

- Suspicious sender domains
- Phishing attempt indicators
- Malicious link detection
- Security warning analysis
- Spam trigger detection
- Urgent language patterns
- Personal information requests

## Usage

1. Open an email in Gmail or Outlook
2. Click the extension icon in your Chrome toolbar
3. Click "Analyze Email" to scan for potential threats
4. Review the risk score and detailed warnings

## Screenshots

### Low Risk Email Analysis
![Low Risk Analysis](screenshots/low.png)

### High Risk Email Analysis
![High Risk Analysis](screenshots/high.png)

## Development

### Prerequisites
- Google Chrome
- Basic understanding of JavaScript and Chrome Extension development

### Project Structure
```
email-security-detector/
├── manifest.json
├── popup.html
├── popup.js
├── popup.css
├── content.js
├── icons/
└── modules/
    ├── EmailExtractor.js
    └── PhishingHeuristics.js
```

### Local Development
1. Make changes to the code
2. Go to `chrome://extensions/`
3. Click the refresh icon on your extension
4. Test the changes

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

Dhruv Kapadia - [GitHub](https://github.com/DhruvKapadia00)
