🛡️ AI Phishing Message Detector

About the Project

AI Phishing Message Detector is a cybersecurity project built using Python, Streamlit, and the Groq API. It helps users identify potentially dangerous emails and SMS messages.

Users can paste a message and receive a risk score, suspicious signs, an explanation of possible risks, and safety tips.

Features

- Analyze emails and SMS messages
- Calculate a phishing risk score out of 100
- Identify suspicious words, links, and urgent requests
- Explain possible phishing risks
- Provide safety tips
- Use AI through the Groq API
- Include a rule-based fallback if AI analysis fails
- Simple and beginner-friendly interface

Technologies Used

- Python
- Streamlit
- Groq API
- GitHub
- Streamlit Community Cloud

Project Files

- "app.py" — Main application code
- "requirements.txt" — Required Python libraries
- "README.md" — Project documentation

How to Run the Project

1. Install Python

Install Python from https://www.python.org/

2. Install Required Libraries

Open a terminal in the project folder and run:

pip install -r requirements.txt

3. Configure the Groq API Key

Get an API key from https://console.groq.com/

Set your API key as an environment variable or configure it in Streamlit Secrets.

Never share your API key publicly.

4. Run the Application

Run this command in the terminal:

streamlit run app.py

The application will open in your browser.

Deployment

This project can be deployed using Streamlit Community Cloud.

Website: https://share.streamlit.io/

Select your GitHub repository, choose "app.py" as the main file, and add your "GROQ_API_KEY" in the app's Secrets settings.

How It Works

1. The user pastes an email or SMS message.
2. The application analyzes the message using the Groq API when available.
3. A risk score and risk level are displayed.
4. The application identifies suspicious signs.
5. Safety tips help users make safer decisions.
6. If AI analysis fails, a basic rule-based detector provides a fallback result.

Important Note

This project is intended for educational and cybersecurity awareness purposes. A low risk score does not guarantee that a message is safe. Always verify suspicious messages through official channels.

Author

Cybersecurity Student

License

This project is available for educational and learning purposes.
