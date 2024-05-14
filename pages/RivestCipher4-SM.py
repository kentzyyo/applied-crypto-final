import streamlit as st
from Crypto.Cipher import ARC4
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64
from io import BytesIO

# Function to encrypt a message using RC4 with a given key
def rc4_encrypt(message, key):
    cipher = ARC4.new(key)  # Create a new RC4 cipher object with the key
    ciphertext = cipher.encrypt(message)  # Encrypt the message
    return ciphertext

# Function to decrypt a ciphertext using RC4 with a given key
def rc4_decrypt(ciphertext, key):
    cipher = ARC4.new(key)  # Create a new RC4 cipher object with the key
    decrypted_message = cipher.decrypt(ciphertext)  # Decrypt the ciphertext
    return decrypted_message

# Main function to run the Streamlit app
def main():
    st.title("RC4 Encryption App")  # Set the title of the Streamlit app
    st.markdown(
        """
        RC4 means Rivest Cipher 4 invented by Ron Rivest in 1987 for RSA Security. It is a Stream Ciphers which operates on a stream of data byte by byte. RC4 stream cipher is one of the most widely used stream ciphers because of its simplicity and speed of operation. It is a variable key-size stream cipher with byte-oriented operations. It uses either 64 bit or 128-bit key sizes. It is generally used in applications such as Secure Socket Layer (SSL), Transport Layer Security (TLS), and also used in IEEE 802.11 wireless LAN std. 
    """
    )

    # Sidebar options for mode selection and key input
    mode = st.sidebar.radio("Mode", ("Encrypt Text", "Decrypt Text", "Encrypt File", "Decrypt File"))

    key = st.sidebar.text_input("Enter Key", type="password")  # Key input field
    iv = st.sidebar.text_input("Enter IV (Initialization Vector)", type="password")  # IV input field
    salt = st.sidebar.text_input("Enter Salt", type="password")  # Salt input field

    if mode in ["Encrypt Text", "Decrypt Text"]:
        text = st.text_area("Enter Text to Process")  # Text input field
        if st.button(mode):
            if not key:
                st.error("Please enter a key")  # Error if key is not entered
            else:
                # Derive the key using PBKDF2 with the provided salt
                derived_key = PBKDF2(key, salt.encode(), dkLen=16, count=1000000)
                if mode == "Encrypt Text":
                    if not text:
                        st.error("Please enter text to encrypt")  # Error if text is not entered
                    else:
                        # Encrypt the text and encode it in base64
                        encrypted_text = rc4_encrypt(text.encode(), derived_key)
                        encrypted_text_base64 = base64.b64encode(encrypted_text).decode('utf-8')
                        st.text_area("Processed Text", value=encrypted_text_base64, height=200)
                else:
                    if not text:
                        st.error("Please enter text to decrypt")  # Error if text is not entered
                    else:
                        try:
                            # Decode the base64-encoded encrypted text
                            encrypted_text_bytes = base64.b64decode(text)
                        except base64.binascii.Error as e:
                            st.error("Invalid base64 encoded string. Please check the input and try again.")
                        else:
                            # Decrypt the text and display it
                            decrypted_text = rc4_decrypt(encrypted_text_bytes, derived_key)
                            st.text_area("Processed Text", value=decrypted_text.decode(), height=200)
    
    elif mode in ["Encrypt File"]:
        file = st.file_uploader("Upload File", type=["txt", "pdf"])  # File uploader for text or PDF files
        if st.button(mode):
            if not key:
                st.error("Please enter a key")  # Error if key is not entered
            elif not file:
                st.error("Please upload a file")  # Error if file is not uploaded
            else:
                file_contents = file.read()  # Read the contents of the uploaded file
                derived_key = PBKDF2(key, salt.encode(), dkLen=16, count=1000000)  # Derive the key
                if mode == "Encrypt File":
                    # Encrypt the file contents and encode in base64
                    encrypted_file_contents = rc4_encrypt(file_contents, derived_key)
                    encrypted_file_contents_base64 = base64.b64encode(encrypted_file_contents).decode('utf-8')
                    # Provide a download button for the encrypted file
                    st.download_button(
                        label="Download Encrypted File",
                        data=BytesIO(encrypted_file_contents_base64.encode()),
                        file_name="encrypted_file.txt",
                        mime="text/plain"
                    )
    elif mode == "Decrypt File":
        file = st.file_uploader("Upload File", type=["txt", "pdf"])  # File uploader for text or PDF files
        if st.button(mode):
            if not key:
                st.error("Please enter a key")  # Error if key is not entered
            elif not file:
                st.error("Please upload a file")  # Error if file is not uploaded
            else:
                file_contents = file.read()  # Read the contents of the uploaded file
                derived_key = PBKDF2(key, salt.encode(), dkLen=16, count=1000000)  # Derive the key
                try:
                    # Decode the base64-encoded encrypted file contents
                    decrypted_file_contents_bytes = base64.b64decode(file_contents)
                except base64.binascii.Error as e:
                    st.error("Invalid base64 encoded file. Please check the input and try again.")
                else:
                    # Decrypt the file contents and display them
                    decrypted_file_contents = rc4_decrypt(decrypted_file_contents_bytes, derived_key)
                    st.text_area("Decrypted File", value=decrypted_file_contents.decode(), height=200)

# Run the main function if the script is executed directly
if __name__ == "__main__":
    main()
