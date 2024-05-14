import streamlit as st
from io import BytesIO

def xor_cipher(data, key):
    """Encrypts or decrypts data using the XOR cipher with the given key."""
    key = key.encode()
    return bytes(a ^ b for a, b in zip(data, key * (len(data) // len(key) + 1)))

st.title("XOR Cipher Tool")

input_type = st.radio("Input Type:", ["Text", "File"])

key = st.text_input("Encryption Key:", type="password")

if input_type == "Text":
    input_text = st.text_area("Input Text:", "")
    if st.button("Encrypt/Decrypt"):
        if key:
            result = xor_cipher(input_text.encode(), key).decode()
            st.text_area("Result:", result)
        else:
            st.warning("Please enter an encryption key.")

elif input_type == "File":
    uploaded_file = st.file_uploader("Upload File", type=["txt"])
    if uploaded_file:
        file_bytes = uploaded_file.read()
        if st.button("Encrypt/Decrypt"):
            if key:
                result = xor_cipher(file_bytes, key)
                st.download_button(
                    label="Download Result",
                    data=BytesIO(result),
                    file_name="result.txt",
                )
            else:
                st.warning("Please enter an encryption key.")
