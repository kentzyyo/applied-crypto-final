import streamlit as st
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
from io import BytesIO
import os

def aes_encrypt(message, key):
    backend = default_backend()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()
    ct = encryptor.update(padded_message) + encryptor.finalize()
    return base64.b64encode(iv).decode('utf-8'), base64.b64encode(ct).decode('utf-8')

def aes_decrypt(iv, ciphertext, key):
    try:
        backend = default_backend()
        iv = base64.b64decode(iv)
        ct = base64.b64decode(ciphertext)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()
        padded_message = decryptor.update(ct) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        pt = unpadder.update(padded_message) + unpadder.finalize()
        return pt.decode('utf-8')
    except Exception as e:
        st.error(f"An error occurred during decryption: {e}")
        return None

def main():
    st.title("AES Block Cipher")

    st.markdown(
        """
        The Advanced Encryption Standard (AES) is a symmetric encryption algorithm widely used across the globe to secure sensitive data. AES operates on fixed block sizes of data and supports key sizes of 128, 192, or 256 bits.
        """
    )

    st.write("""
    ## Instructions:
    - Ensure your key is exactly 32 characters long for AES-256.
    - For decryption, you'll need the IV (Initialization Vector) used during encryption.
    - Only text files (.txt) and PDF files (.pdf) are supported for file encryption and decryption.
    """)

    mode = st.radio("Select Mode", ("Encrypt Text", "Decrypt Text", "Encrypt File", "Decrypt File"))

    key = st.text_input("Enter Key (32 characters for AES-256)", type="password")
    if len(key) != 32:
        st.warning("Key length must be 32 characters for AES-256.")

    if mode in ["Encrypt Text", "Decrypt Text"]:
        text = st.text_area("Enter Text to Process")
        if st.button(f"{mode}"):
            if not key or len(key) != 32:
                st.error("Please enter a valid 32-character key.")
            else:
                key_bytes = key.encode()
                if mode == "Encrypt Text":
                    if not text:
                        st.error("Please enter text to encrypt.")
                    else:
                        iv, encrypted_text = aes_encrypt(text, key_bytes)
                        st.text_area("IV (Initialization Vector):", value=iv, height=100)
                        st.text_area("Encrypted Text:", value=encrypted_text, height=200)
                else:
                    iv_input = st.text_area("Enter IV (Initialization Vector) for Decryption")
                    if not text or not iv_input:
                        st.error("Please enter text and IV to decrypt.")
                    else:
                        decrypted_text = aes_decrypt(iv_input, text, key_bytes)
                        if decrypted_text:
                            st.text_area("Decrypted Text:", value=decrypted_text, height=200)
    
    elif mode in ["Encrypt File", "Decrypt File"]:
        file = st.file_uploader("Upload File", type=["txt", "pdf"])
        if st.button(f"{mode}"):
            if not key or len(key) != 32:
                st.error("Please enter a valid 32-character key.")
            elif not file:
                st.error("Please upload a file.")
            else:
                file_contents = file.read()
                key_bytes = key.encode()
                if mode == "Encrypt File":
                    iv, encrypted_file_contents = aes_encrypt(file_contents.decode(), key_bytes)
                    encrypted_file_base64 = base64.b64encode(encrypted_file_contents.encode()).decode('utf-8')
                    st.download_button(
                        label="Download Encrypted File",
                        data=BytesIO(encrypted_file_base64.encode()),
                        file_name="encrypted_file.txt",
                        mime="text/plain"
                    )
                    st.text_area("IV (Initialization Vector):", value=iv, height=100)
                else:
                    iv_input = st.text_area("Enter IV (Initialization Vector) for Decryption")
                    if not iv_input:
                        st.error("Please enter the IV for decryption.")
                    else:
                        decrypted_file_contents = aes_decrypt(iv_input, file_contents.decode(), key_bytes)
                        if decrypted_file_contents:
                            st.text_area("Decrypted File Contents:", value=decrypted_file_contents, height=200)

if __name__ == "__main__":
    main()
