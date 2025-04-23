🛡️ Secure Data Encryption System
A user-friendly and secure web application built with Streamlit that allows users to store and retrieve encrypted data using Fernet encryption and SHA-256 hashing. This system is ideal for managing sensitive notes or credentials with a lightweight authentication mechanism.

🔧 Features
🔐 User Authentication: Simple login with username and password.

📝 Data Encryption & Storage: Encrypt sensitive data using a custom passkey.

🔍 Secure Retrieval: Decrypt stored data using the correct passkey.

🔄 Session Management: Tracks login state, attempts, and session-stored data.

🧠 Memory Efficient: All data is stored in st.session_state (temporary and volatile).

📦 Tech Stack
Streamlit – Interactive UI and deployment

cryptography – Fernet encryption

hashlib – SHA-256 hashing

uuid – For generating unique data keys (not used yet but available)

base64 – Encoding binary data to text format

🚀 How to Run
Clone the repository:

bash
Copy
Edit
git clone https://github.com/yourusername/secure-data-encryption-app.git
cd secure-data-encryption-app
Install dependencies:

bash
Copy
Edit
pip install streamlit cryptography
Run the application:

bash
Copy
Edit
streamlit run app.py
🔐 Default Login

Username	Password
admin	password
✅ You can modify the credentials in the login_page() function for production use.

💡 How It Works
Data is encrypted with a Fernet key derived from the user-provided passkey.

The passkey is hashed with SHA-256 and stored alongside the encrypted content for validation.

During retrieval, the app verifies the hashed passkey and attempts decryption.

Three consecutive failed attempts will log the user out for added security.

📁 Project Structure
bash
Copy
Edit
secure-data-encryption-app/
│
├── app.py           # Main Streamlit application
├── README.md        # Documentation
└── requirements.txt # Dependencies (optional)
🧪 Sample Use Cases
Storing encrypted API keys or passwords

Personal secure notes manager

Learning tool for encryption and Streamlit-based apps

🛠️ Future Improvements
Persistent storage using a secure database

Role-based access control

Improved UI/UX and animations

Customizable login credentials

📝 License
This project is open-source and available under the MIT License.