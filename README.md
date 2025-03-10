# 🔐 Email Security Tool

> A Python application for detecting spam and phishing attempts in emails using machine learning and rule-based analysis.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Python Version](https://img.shields.io/badge/python-3.6%2B-blue)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
![Last Commit](https://img.shields.io/github/last-commit/yourusername/email-security-tool)

<p align="center">
  <img src="screenshots/app_screenshot.png" alt="Email Security Tool Screenshot" width="600">
</p>

## ✨ Features

- 🔍 **Spam Detection** - Identify unwanted bulk emails using ML and content analysis
- 🛡️ **Phishing Detection** - Detect fraudulent emails attempting to steal sensitive information
- 🧠 **Model Training** - Train custom detection models with your own datasets
- 📧 **Email Analysis** - Load and analyze .eml files or paste email content directly
- 📊 **Detailed Reports** - Get comprehensive security analysis with confidence scores

## 📋 Table of Contents

- [Installation](#-installation)
- [Usage](#-usage)
- [How It Works](#-how-it-works)
- [Technical Details](#-technical-details)
- [Contributing](#-contributing)
- [Future Enhancements](#-future-enhancements)
- [License](#-license)

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/email-security-tool.git
cd email-security-tool

# Install required packages
pip install -r requirements.txt

# Run the application
python main.py
```

### Requirements

```
pandas>=1.1.0
scikit-learn>=0.24.0
numpy>=1.19.0
```

## 💻 Usage

### Spam Detection

<details>
<summary>Click to expand instructions</summary>

1. Navigate to the "Spam Detection" tab
2. Enter or paste email content, or load an .eml file
3. Click "Check Email" to analyze
4. View results including classification and suspicious indicators

</details>

### Phishing Detection

<details>
<summary>Click to expand instructions</summary>

1. Navigate to the "Phishing Detection" tab
2. Enter or paste email content, or load an .eml file
3. Click "Check Email" to analyze
4. Review detailed analysis of URLs, forms, and other phishing indicators

</details>

### Model Training

<details>
<summary>Click to expand instructions</summary>

1. Navigate to the "Model Training" tab
2. Select built-in datasets or provide your own custom CSV files
3. Click "Train Spam Model" or "Train Phishing Model"
4. View training results and model performance metrics

</details>

## 🔎 How It Works

The application combines multiple detection techniques:

| Technique | Description |
|-----------|-------------|
| **Machine Learning** | Uses TF-IDF vectorization and Naive Bayes classification |
| **URL Analysis** | Examines links for suspicious characteristics |
| **Form Detection** | Identifies potential credential harvesting forms |
| **Pattern Recognition** | Detects common phishing and spam patterns |
| **Domain Verification** | Checks if linked domains actually exist |

## 🔧 Technical Details

- Built with Python and tkinter for cross-platform compatibility
- Uses scikit-learn for machine learning components
- Implements multithreading for responsive UI during model training
- Persists trained models for reuse across sessions
- Includes example datasets for immediate use

## 👥 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

See the [CONTRIBUTING.md](CONTRIBUTING.md) file for more details.

## 🔮 Future Enhancements

- [ ] Email client integration
- [ ] Additional ML models (deep learning)
- [ ] Real-time threat intelligence integration
- [ ] Expanded rule sets for detection
- [ ] Improved visualization of results

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [scikit-learn](https://scikit-learn.org/) for machine learning components
- [pandas](https://pandas.pydata.org/) for data handling
- [tkinter](https://docs.python.org/3/library/tkinter.html) for the GUI

---

<p align="center">
  Made with ❤️ for email security
  <br>
  © 2025 Your Name
</p>
