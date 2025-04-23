import streamlit as st
import hashlib
import time
import uuid
from cryptography.fernet import Fernet
import base64

# Initialize session state variables if they don't exist
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}

if 'login_attempts' not in st.session_state:
    st.session_state.login_attempts = 0

if 'is_authenticated' not in st.session_state:
    st.session_state.is_authenticated = False

if 'current_page' not in st.session_state:
    st.session_state.current_page = "home"

if 'encryption_keys' not in st.session_state:
    st.session_state.encryption_keys = {}

def generate_key_from_passkey(passkey):
    """Generate a Fernet key from a passkey string"""
    # Create a hash of the passkey
    key_hash = hashlib.sha256(passkey.encode()).digest()
    # Convert to base64 encoded string that Fernet can use
    key = base64.urlsafe_b64encode(key_hash[:32])
    return key

def hash_passkey(passkey):
    """Hash a passkey using SHA-256"""
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(data, passkey):
    """Encrypt data using Fernet encryption"""
    # Generate key from passkey
    key = generate_key_from_passkey(passkey)
    # Create Fernet cipher
    cipher = Fernet(key)
    # Encrypt data
    encrypted_data = cipher.encrypt(data.encode())
    return encrypted_data

def decrypt_data(encrypted_data, passkey):
    """Decrypt data using Fernet encryption"""
    try:
        # Generate key from passkey
        key = generate_key_from_passkey(passkey)
        # Create Fernet cipher
        cipher = Fernet(key)
        # Decrypt data
        decrypted_data = cipher.decrypt(encrypted_data).decode()
        return decrypted_data
    except Exception as e:
        return None

def reset_auth():
    """Reset authentication state"""
    st.session_state.login_attempts = 0
    st.session_state.is_authenticated = False
    st.session_state.current_page = "login"

def navigate_to(page):
    """Navigate to a specific page"""
    st.session_state.current_page = page

def login_page():
    """Display login page"""
    st.title("🔐 Secure Data System - Login")
    
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submit = st.form_submit_button("Login")
        
        if submit:
            # Simple authentication (in a real app, this would be more robust)
            if username == "admin" and password == "password":
                st.session_state.is_authenticated = True
                st.session_state.login_attempts = 0
                st.session_state.current_page = "home"
                st.rerun()
            else:
                st.error("Invalid credentials. Please try again.")

def home_page():
    """Display home page"""
    st.title("🛡️ Secure Data Encryption System")
    
    st.write("Welcome to the secure data storage and retrieval system.")
    
    col1, col2 = st.columns(2)
    
    with col1:
        if st.button("📝 Store New Data", use_container_width=True):
            navigate_to("insert_data")
            st.rerun()
    
    with col2:
        if st.button("🔍 Retrieve Data", use_container_width=True):
            navigate_to("retrieve_data")
            st.rerun()
    
    # Display stored data keys (not content)
    if st.session_state.stored_data:
        st.subheader("Stored Data Entries")
        for key in st.session_state.stored_data.keys():
            st.write(f"- {key}")
    else:
        st.info("No data has been stored yet.")
    
    # Logout button
    if st.button("Logout"):
        reset_auth()
        st.rerun()

def insert_data_page():
    """Display insert data page"""
    st.title("📝 Store New Data")
    
    with st.form("insert_data_form"):
        data_name = st.text_input("Data Name (identifier)")
        data_content = st.text_area("Data Content")
        passkey = st.text_input("Encryption Passkey", type="password")
        
        submit = st.form_submit_button("Encrypt and Store")
        
        if submit:
            if not data_name or not data_content or not passkey:
                st.error("All fields are required.")
            else:
                # Encrypt the data
                encrypted_data = encrypt_data(data_content, passkey)
                hashed_passkey = hash_passkey(passkey)
                
                # Store the encrypted data with hashed passkey
                st.session_state.stored_data[data_name] = {
                    "encrypted_text": encrypted_data,
                    "passkey": hashed_passkey
                }
                
                st.success(f"Data '{data_name}' has been securely stored!")
    
    if st.button("Back to Home"):
        navigate_to("home")
        st.rerun()

def retrieve_data_page():
    """Display retrieve data page"""
    st.title("🔍 Retrieve Data")
    
    if not st.session_state.stored_data:
        st.warning("No data has been stored yet.")
        if st.button("Back to Home"):
            navigate_to("home")
            st.rerun()
        return
    
    # Select data to retrieve
    data_options = list(st.session_state.stored_data.keys())
    selected_data = st.selectbox("Select data to retrieve", data_options)
    
    with st.form("retrieve_data_form"):
        passkey = st.text_input("Enter Passkey", type="password")
        submit = st.form_submit_button("Decrypt and View")
        
        if submit:
            # Verify passkey
            hashed_input = hash_passkey(passkey)
            stored_hash = st.session_state.stored_data[selected_data]["passkey"]
            
            if hashed_input == stored_hash:
                # Decrypt data
                encrypted_data = st.session_state.stored_data[selected_data]["encrypted_text"]
                decrypted_data = decrypt_data(encrypted_data, passkey)
                
                if decrypted_data:
                    st.success("Data successfully decrypted!")
                    st.text_area("Decrypted Content", decrypted_data, height=200)
                    # Reset attempt counter on successful decryption
                    st.session_state.login_attempts = 0
                else:
                    st.error("Decryption failed! Incorrect passkey.")
                    st.session_state.login_attempts += 1
            else:
                st.error("Incorrect passkey!")
                st.session_state.login_attempts += 1
            
            # Check if max attempts reached
            if st.session_state.login_attempts >= 3:
                st.error("Maximum attempts reached. Please re-authenticate.")
                reset_auth()
                st.rerun()
            elif st.session_state.login_attempts > 0:
                st.warning(f"Failed attempts: {st.session_state.login_attempts}/3")
    
    if st.button("Back to Home"):
        navigate_to("home")
        st.rerun()

# Main app logic
def main():
    # Apply basic styling
    st.set_page_config(
        page_title="Secure Data Encryption System", 
        page_icon="🛡️",
        layout="centered"
    )
    
    # Check authentication state
    if not st.session_state.is_authenticated:
        login_page()
        return
    
    # Navigation based on current page
    if st.session_state.current_page == "home":
        home_page()
    elif st.session_state.current_page == "insert_data":
        insert_data_page()
    elif st.session_state.current_page == "retrieve_data":
        retrieve_data_page()
    elif st.session_state.current_page == "login":
        login_page()

if __name__ == "__main__":
    main()