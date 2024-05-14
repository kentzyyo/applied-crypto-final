import streamlit as st
from io import BytesIO

def xor_cipher(data, key):
    """Encrypts or decrypts data using XOR with the given key."""
    # Convert the key to bytes
    key_bytes = key.encode()
    # Perform XOR between each byte of data and the repeated key bytes
    return bytes(a ^ b for a, b in zip(data, key_bytes * (len(data) // len(key_bytes) + 1)))

def display_binary_representation(data, label):
    """Displays binary representation of data along with characters."""
    # Display the label and raw data
    st.write(f"**{label}:**", data)
    # Loop through each byte in the data to display its binary format and character representation
    for byte in data:
        st.write(f"   Byte: {format(byte, '08b')} | Char: {chr(byte) if 32 <= byte <= 126 else '?'}")

# Title of the Streamlit app
st.title("XOR Cipher Tool")
st.markdown(
        """
        XOR Encryption is an encryption method used to encrypt data and is hard to crack by brute-force method, i.e generating random encryption keys to match with the correct one. 
    """
    )

# Radio button for selecting input type (Text or File)
input_type = st.radio("Input Type:", ["Text", "File"])

# Password input for encryption key
key = st.text_input("Encryption Key:", type="password")

if input_type == "Text":
    # Text area for input text
    input_text = st.text_area("Input Text:", "")
    if st.button("Encrypt/Decrypt"):
        if key:
            # Encrypt or decrypt the input text using the provided key
            result = xor_cipher(input_text.encode(), key)
            col1, col2 = st.columns(2)
            with col1:
                st.subheader("Input Text")
                # Display binary representation of plaintext and key
                display_binary_representation(input_text.encode(), "Plaintext")
                display_binary_representation(key.encode(), "Key")
                # Display the encrypted ciphertext in hexadecimal format with a green highlight
                st.success(f"**Encrypted Ciphertext (Hex):** {result.hex()}")
            with col2:
                st.subheader("Result")
                # Display binary representation of the ciphertext
                display_binary_representation(result, "Ciphertext")
                try:
                    # Try to decrypt the ciphertext back to plaintext
                    decrypted_text = xor_cipher(result, key).decode()
                    # Display the decrypted plaintext with a green highlight
                    st.success(f"**Decrypted Plaintext:** {decrypted_text}")
                except UnicodeDecodeError:
                    # Handle decoding errors gracefully
                    st.write("**Decrypted Plaintext:** Unable to decode result as plaintext.")
        else:
            # Warning message if no encryption key is provided
            st.warning("Please enter an encryption key.")

elif input_type == "File":
    # File uploader for text files
    uploaded_file = st.file_uploader("Upload File", type=["txt"])
    if uploaded_file:
        # Read the uploaded file bytes
        file_bytes = uploaded_file.read()
        if st.button("Encrypt/Decrypt"):
            if key:
                # Encrypt or decrypt the file bytes using the provided key
                result = xor_cipher(file_bytes, key)
                col1, col2 = st.columns(2)
                with col1:
                    st.subheader("Input File")
                    # Display the size of the uploaded file
                    st.write("Size:", len(file_bytes), "bytes")
                with col2:
                    st.subheader("Result")
                    # Display the size of the result and the encrypted ciphertext in hexadecimal format with a green highlight
                    st.write("Size:", len(result), "bytes")
                    st.success(f"**Encrypted Ciphertext (Hex):** {result.hex()}")
                    # Decrypt the result back to plaintext
                    decrypted_file_content = xor_cipher(result, key)
                    # Provide a download button for the decrypted plaintext file
                    st.download_button(
                        label="Download Result",
                        data=BytesIO(decrypted_file_content),
                        file_name="result.txt",
                    )
            else:
                # Warning message if no encryption key is provided
                st.warning("Please enter an encryption key.")
