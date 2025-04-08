import streamlit as st
import hashlib
import uuid
import time
from cryptography.fernet import Fernet

# 🔐 Key Generation and Encryption Setup
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# 💾 In-memory Storage
users_data = {}         
failed_attempts = {}     

# 🔁 Session State Initialization
if "current_user" not in st.session_state:
    st.session_state.current_user = None
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = None

# 🧠 Utility Functions
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text, passkey):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(user, passkey):
    if user not in users_data:
        return None

    user_info = users_data[user]
    hashed = hash_passkey(passkey)

    if hashed == user_info["passkey"]:
        failed_attempts[user] = 0
        return cipher.decrypt(user_info["encrypted_text"].encode()).decode()
    else:
        failed_attempts[user] = failed_attempts.get(user, 0) + 1
        if failed_attempts[user] >= 3:
            st.session_state.lockout_time = time.time() + 30
        return None

# 🧭 Navigation
st.title("🔐 Secure Data Encryption ")

menu = ["🏠 Home", "📝 Sign Up", "🔑 Login", "📥 Store Data", "📤 Retrieve Data"]
choice = st.sidebar.selectbox("📌 Menu", menu)

# 🏠 Home
if choice == "🏠 Home":
    st.subheader("🔐 Welcome to Secure Data Encryption!")
    st.markdown("Store and retrieve encrypted data with your unique passkey 🔑")
    if st.session_state.current_user:
        st.success(f"✅ Logged in as: **{st.session_state.current_user}**")
    else:
        st.info("🔓 You are not logged in.")

# 📝 Sign Up
elif choice == "📝 Sign Up":
    st.subheader("📝 Create a Secure Account")
    username = st.text_input("👤 Username")
    passkey = st.text_input("🔑 Passkey", type="password")
    confirm = st.text_input("🔁 Confirm Passkey", type="password")

    if st.button("🚀 Sign Up"):
        if not username or not passkey:
            st.warning("⚠️ Please fill all fields.")
        elif passkey != confirm:
            st.error("❌ Passkeys do not match!")
        elif username in users_data:
            st.error("❌ Username already exists!")
        else:
            users_data[username] = {
                "passkey": hash_passkey(passkey),
                "encrypted_text": ""
            }
            failed_attempts[username] = 0
            st.success("🎉 Account created! You can now log in.")

# 🔑 Login
elif choice == "🔑 Login":
    st.subheader("🔐 Log In to Your Account")
    username = st.text_input("👤 Username")
    passkey = st.text_input("🔑 Passkey", type="password")

    if st.button("🔓 Log In"):
        if username in users_data and hash_passkey(passkey) == users_data[username]["passkey"]:
            st.session_state.current_user = username
            failed_attempts[username] = 0
            st.success(f"✅ Welcome back, {username}!")
        else:
            st.error("❌ Invalid credentials!")

# 📥 Store Data
elif choice == "📥 Store Data":
    if st.session_state.current_user:
        st.subheader("📥 Store Your Secret")
        data = st.text_area("📝 Enter the data to encrypt:")
        passkey = st.text_input("🔐 Your Passkey", type="password")

        if st.button("🔒 Encrypt & Store"):
            if data and passkey:
                encrypted = encrypt_data(data, passkey)
                users_data[st.session_state.current_user] = {
                    "encrypted_text": encrypted,
                    "passkey": hash_passkey(passkey)
                }
                st.success("🔐 Data securely stored!")
            else:
                st.warning("⚠️ Fill in all fields.")
    else:
        st.warning("🔓 Please log in to store data.")

# 📤 Retrieve Data
elif choice == "📤 Retrieve Data":
    if st.session_state.current_user:
        st.subheader("📤 Retrieve Your Secret")
        
        if st.session_state.lockout_time and time.time() < st.session_state.lockout_time:
            wait_time = int(st.session_state.lockout_time - time.time())
            st.error(f"⏳ Too many failed attempts. Try again in {wait_time} seconds.")
        else:
            passkey = st.text_input("🔑 Enter your Passkey", type="password")
            if st.button("🔓 Decrypt"):
                decrypted = decrypt_data(st.session_state.current_user, passkey)
                if decrypted:
                    st.success(f"🗝️ Decrypted Data: {decrypted}")
                else:
                    attempts = failed_attempts.get(st.session_state.current_user, 0)
                    st.error(f"❌ Incorrect passkey! Attempts left: {3 - attempts}")
    else:
        st.warning("🔓 Please log in to retrieve data.")
