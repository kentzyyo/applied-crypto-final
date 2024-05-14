import streamlit as st
from io import BytesIO

def xor_cipher(data, key):
    """Encrypts or decrypts data using XOR with the given key."""
    key_bytes = key.encode()
    return bytes(a ^ b for a, b in zip(data, key_bytes * (len(data) // len(key_bytes) + 1)))

def display_binary_representation(data, label):
    """Displays binary representation of data along with characters."""
    st.write(f"**{label}:**", data)
    for byte in data:
        st.write(f"   Byte: {format(byte, '08b')} | Char: {chr(byte) if 32 <= byte <= 126 else '?'}")

st.title("XOR Cipher Tool")

input_type = st.radio("Input Type:", ["Text", "File"])

key = st.text_input("Encryption Key:", type="password")

if input_type == "Text":
    input_text = st.text_area("Input Text:", "")
    if st.button("Encrypt/Decrypt"):
        if key:
            result = xor_cipher(input_text.encode(), key)
            col1, col2 = st.columns(2)
            with col1:
                st.subheader("Input Text")
                display_binary_representation(input_text.encode(), "Plaintext")
                display_binary_representation(key.encode(), "Key")
                st.success(f"**Encrypted Ciphertext (Hex):** {result.hex()}")  # Highlighted Encrypted Ciphertext
            with col2:
                st.subheader("Result")
                display_binary_representation(result, "Ciphertext")
                try:
                    decrypted_text = xor_cipher(result, key).decode()
                    st.success(f"**Decrypted Plaintext:** {decrypted_text}")  # Highlighted Decrypted Plaintext
                except UnicodeDecodeError:
                    st.write("**Decrypted Plaintext:** Unable to decode result as plaintext.")
        else:
            st.warning("Please enter an encryption key.")

elif input_type == "File":
    uploaded_file = st.file_uploader("Upload File", type=["txt"])
    if uploaded_file:
        file_bytes = uploaded_file.read()
        if st.button("Encrypt/Decrypt"):
            if key:
                result = xor_cipher(file_bytes, key)
                col1, col2 = st.columns(2)
                with col1:
                    st.subheader("Input File")
                    st.write("Size:", len(file_bytes), "bytes")
                with col2:
                    st.subheader("Result")
                    st.write("Size:", len(result), "bytes")
                    st.success(f"**Encrypted Ciphertext (Hex):** {result.hex()}")  # Highlighted Encrypted Ciphertext
                    decrypted_file_content = xor_cipher(result, key)
                    st.download_button(
                        label="Download Result",
                        data=BytesIO(decrypted_file_content),
                        file_name="result.txt",
                    )
            else:
                st.warning("Please enter an encryption key.")
