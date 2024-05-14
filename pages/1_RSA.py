import streamlit as st
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.padding import PKCS7

# Page Title
st.title("RSA Cipher")

# Radio Buttons for Encryption/Decryption
mode = st.radio("Mode", ("Encrypt", "Decrypt"))

# Text Areas for Message and Key Input
message_input = st.text_area("Enter Message:", key="message_input")
key_input = st.text_area("Enter Public/Private Key:", key="key_input")

# Function to generate RSA key pair
def generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

# Button to generate new keys
if st.button("Generate New Keys"):
    private_key, public_key = generate_rsa_keypair()

    # Display keys in text areas
    st.text_area("Private Key:", private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8"), key="private_key")

    st.text_area("Public Key:", public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8"), key="public_key")

# Function to encrypt/decrypt message
def process_message(message, key, mode):
    if mode == "Encrypt":
        public_key = serialization.load_pem_public_key(key.encode())
        ciphertext = public_key.encrypt( message.encode(), PKCS7(128).padder()  # Add padding for security
        )
        return ciphertext
    elif mode == "Decrypt":
        private_key = serialization.load_pem_private_key(
            key.encode(), password=None
        )
        plaintext = private_key.decrypt(
            message,
            PKCS7(128).unpadder()  # Remove padding
        )
        return plaintext.decode()

# When the "Process" button is clicked
if st.button("Process"):
    result = process_message(message_input, key_input, mode)
    if result:
        # Display the result
        st.text_area(f"{mode}ed Message:", result, key="result")
    else:
        # Handle invalid keys or messages
        st.error("Invalid key or message. Please check your input.")
