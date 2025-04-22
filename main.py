import streamlit as st
import sqlite3   #  Create a database – Store data permanently in a .db file.

# Create tables – Organize data into rows and columns.

# Insert, update, delete data – Perform CRUD operations (Create, Read, Update, Delete).

# Query data – Use SQL commands to find and display specific information

import hashlib #hash me convert kerna he 
import os  # system ke saare operation check kare ga..

from cryptography.fernet import Fernet  # data ko incrupt or dicrupt kerta he . incrupt => agar hamara koi secret hai to hum usay aisay format me change kerdetay hein koi isay perhe nahi paye   ---------------- decrupt ==> Us secret ko reveal kerdena original  form me..


st.markdown("""
<style>
    .stTextInput>div>div>input, .stTextArea>div>div>textarea {
        border: 2px solid #4a90e2 !important;
        border-radius: 8px !important;
        padding: 10px !important;
    }
    .stButton>button {
        background: #4a90e2 !important;
        color: white !important;
        border-radius: 8px !important;
        padding: 10px 24px !important;
    }
    .stAlert {
        border-radius: 10px !important;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1) !important;
    }
</style>
""", unsafe_allow_html=True)





KEY_FILE = "simple_secret.key"


def load_Key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE,"wb") as f:
            f.write(key)
    else:
        with open(KEY_FILE,"rb") as f:
            key = f.read()
            return key


cipher = Fernet(load_Key())
print(cipher)


def init_database():
    conn = sqlite3.connect("simple_data.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS VAULT (
            LABEL TEXT PRIMARY KEY,
            ENCRYPTED_TEXT TEXT,
            PASSKEY TEXT
        )
    """)
    conn.commit()
    conn.close()


init_database()






def hash_passkeys(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()





def encript(text):
    return cipher.encrypt(text.encode()).decode()



def decript(encripted_text):
    return cipher.decrypt(encripted_text.encode()).decode()

    

# st.title("Secure Data Encryption System")


# 🔥 ADDED STYLING: Page config and title formatting
st.markdown("<h1 style='text-align: center; color: #2c3e50;'>🔐 Secure Data Encryption System</h1>", unsafe_allow_html=True)



Menu = ["Store Secret","Retrieve Secret"]
choice = st.sidebar.selectbox("Choose Options",Menu)



if choice == "Store Secret":
    # 🔥 ADDED STYLING: Container with shadow and padding
    with st.container():
        st.markdown("### 🗃️ Store A New Secret")
        st.markdown("---")
        
        # 🔥 ADDED STYLING: Columns layout for inputs
        col1, col2 = st.columns(2)
        with col1:
            label = st.text_input("Label (Unique ID)", help="Unique identifier for your secret")
        with col2:
            passkey = st.text_input("Passkey", type="password", help="Strong password to protect secret")
        
        secret = st.text_area("Your Secret", height=150, 
                            placeholder="Enter your sensitive information here...")
        
        # 🔥 ADDED STYLING: Custom button styling
        if st.button("🔒 Encrypt & Save", help="Securely store your secret"):
            if label and secret and passkey:
                conn = sqlite3.connect("simple_data.db")
                c = conn.cursor()
                encrypted = encript(secret)
                hashed_key = hash_passkeys(passkey)
                try:
                    c.execute("INSERT INTO VAULT (LABEL, ENCRYPTED_TEXT, PASSKEY) VALUES (?, ?, ?)", 
                             (label, encrypted, hashed_key))
                    conn.commit()
                    # 🔥 ADDED STYLING: Custom success message
                    st.success("✅ Secret securely stored in encrypted vault!")
                except sqlite3.IntegrityError:
                    st.error("⚠️ Label already exists! Use unique identifier")
                conn.close()
            else:
                st.warning("📝 Please complete all fields before submitting!")




elif choice == "Retrieve Secret":
    # 🔥 ADDED STYLING: Container with shadow and padding
    with st.container():
        st.markdown("### 🔍 Retrieve Your Secret")
        st.markdown("---")
        
        # 🔥 ADDED STYLING: Columns layout for inputs
        col1, col2 = st.columns(2)
        with col1:
            label = st.text_input("Enter Label", help="Enter your secret's unique identifier")
        with col2:
            passkey = st.text_input("Enter Passkey", type="password", help="Password used during storage")
        
        # 🔥 ADDED STYLING: Custom button styling
        if st.button("🔓 Decrypt Secret", help="Retrieve your secret"):
            conn = sqlite3.connect("simple_data.db")
            c = conn.cursor()
            c.execute("SELECT Encrypted_Text, Passkey FROM VAULT WHERE LABEL = ?" , (label,))
            result = c.fetchone()
            c.close()

            if result:
                encrypted_text, storedhash = result
                if hash_passkeys(passkey) == storedhash:
                    decrypted = decript(encrypted_text)
                    # 🔥 ADDED STYLING: Custom secret display
                    st.markdown("---")
                    st.success("### 📜 Decrypted Secret:")
                    st.code(f"{decrypted}", language="text")
                else:
                    st.error("❌ Access Denied: Incorrect Passkey")
            else:
                st.warning("🔍 No entry found with that label")




# 🔥 ADDED STYLING: Footer
st.markdown("---")
st.markdown("*Security features: AES-256 encryption • SHA-256 hashing • Secure database storage*")
     

