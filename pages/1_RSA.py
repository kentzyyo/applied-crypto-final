import streamlit as st
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric import padding

def generate_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # Common public exponent
        key_size=2048  # Key size in bits
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_message(message, public_key):
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None  # Optional label
        )
    )
    return ciphertext

def decrypt_message(ciphertext, private_key):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=SHA256()),
            algorithm=SHA256(),
            label=None
        )
    )
    return plaintext.decode()

st.title("RSA Encryption/Decryption")

option = st.radio("Choose an action:", ["Generate Keys", "Encrypt", "Decrypt"])

if option == "Generate Keys":
    if st.button("Generate"):
        private_key, public_key = generate_keypair()

        st.subheader("Private Key (Keep Secret!)")
        st.code(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

        st.subheader("Public Key")
        st.code(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

elif option == "Encrypt":
    message = st.text_area("Enter message to encrypt:")
    public_key_pem = st.text_area("Paste public key:")

    if st.button("Encrypt") and message and public_key_pem:
        try:
            public_key = serialization.load_pem_public_key(public_key_pem.encode())
            ciphertext = encrypt_message(message, public_key)
            st.subheader("Ciphertext")
            st.code(ciphertext.hex()) 
        except Exception as e:
            st.error(f"Error loading public key or encrypting: {e}")

elif option == "Decrypt":
    ciphertext_hex = st.text_area("Enter ciphertext (hex):")
    private_key_pem = st.text_area("Paste private key:")

    if st.button("Decrypt") and ciphertext_hex and private_key_pem:
        try:
            private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
            ciphertext = bytes.fromhex(ciphertext_hex)
            plaintext = decrypt_message(ciphertext, private_key)
            st.subheader("Decrypted Message")
            st.write(plaintext)
        except Exception as e:
            st.error(f"Error loading private key or decrypting: {e}")
