# AEye: AI-Powered Insights and Payload Suggestions for Burp Suite

AEye is a Burp Suite extension that integrates OpenAI's GPT model to analyze HTTP requests and responses, providing insights and payload suggestions. It helps penetration testers and security researchers streamline their workflow by leveraging AI to identify potential vulnerabilities and suggest targeted tests.

![AEye img](https://github.com/Trivulzianus/AEye/blob/master/AEye.png)

Note: AEye uses OpenAI's gpt-4o-mini by default. On a time-benefit measure, I've determined this to be the most useful. REMEMBER! These LLM tools take a while to respond.

---

## Features
- Analyze HTTP requests and responses using OpenAI's GPT models.
- Generate security insights and testing recommendations.
- Seamlessly integrates with Burp Suite's Repeater and Proxy tools.
- User-friendly interface within Burp Suite.
- Customizable OpenAI API key.

---

## Installation

### Prerequisites
1. **Jython**
   - Download the standalone Jython JAR file from the [Jython website](https://www.jython.org/).
   - Install it on your system following the provided instructions.

2. **OpenAI API Key**
   - Obtain an API key from [OpenAI](https://platform.openai.com/signup/).

### Steps
1. **Set Up Jython in Burp Suite**
   - Open Burp Suite and navigate to `Extender > Options`.
   - Under the **Python Environment** section, click **Select file** and locate the `jython-standalone-x.x.x.jar` file you downloaded.

2. **Download the AEye Script**
   - Clone this repository or download the `AEye.py` file.

3. **Load the Extension in Burp Suite**
   - Go to `Extender > Extensions` in Burp Suite.
   - Click **Add**.
   - Set the **Extension Type** to `Python`.
   - Browse to and select the `AEye.py` file.

4. **Verify Installation**
   - Once loaded, the extension will appear as a new tab labeled "AEye".
   - Check the logs or text area in the AEye tab to ensure it's functioning correctly.

---

## Usage

1. **Open the AEye Tab**
   - The extension provides a panel within Burp Suite where analysis results are displayed.

2. **Analyze Traffic**
   - Use Burp's Proxy or Repeater tools to send requests.
   - AEye will automatically process responses and provide insights.

3. **View Results**
   - Check the AEye tab for analysis results, suggested tests, or payloads.

4. **Configure API Key**
   - Replace the `self.openai_api_key` value in the `AEye.py` file with your actual OpenAI API key.

---

## Development and Contribution

### Repository Structure
- `AEye.py`: Main extension script.
- `README.md`: Documentation for the project.

### Running Locally
If you want to test or modify the extension:
1. Ensure Jython is installed and configured in Burp Suite.
2. Edit the `AEye.py` file as needed.
3. Reload the extension in Burp Suite to apply changes.

### Contributing
Contributions are welcome! Feel free to fork the repository, make improvements, and submit a pull request.

---

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.

---

## Disclaimer
AEye is a tool to assist security professionals. Use it responsibly and only on systems you have permission to test. The developer is not responsible for misuse or unintended consequences.

