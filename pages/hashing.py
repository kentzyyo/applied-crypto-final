import streamlit as st
import hashlib
import io

def calculate_hash(data, hash_type):
    # Calculate the hash value based on the input data and hash function type
    hasher = hashlib.new(hash_type)
    hasher.update(data)
    return hasher.hexdigest()

# Streamlit app
st.title("Hashing Functions")

# Ask the user to input text or upload a file
option = st.radio("Choose input method:", ("Text", "File"))

if option == "Text":
    # Ask the user to input text
    text = st.text_input("Enter text to hash:")
    if text:
        # Ask the user to select the hash function
        hash_type = st.selectbox("Choose a hash function:", ("md5", "sha1", "sha256", "sha512"))

        # Hash the text using the selected hash function
        hashed_text = calculate_hash(text.encode(), hash_type)

        # Display the hash value
        st.write("Hash value:", hashed_text)
elif option == "File":
    # Ask the user to upload a file
    file = st.file_uploader("Upload a file to hash:", type=["txt", "pdf", "docx", "csv", "xlsx"])
    if file:
        # Read the file contents
        file_contents = file.read()

        # Ask the user to select the hash function
        hash_type = st.selectbox("Choose a hash function:", ("md5", "sha1", "sha256", "sha512"))

        # Hash the file contents using the selected hash function
        hashed_file = calculate_hash(file_contents, hash_type)

        # Display the hash value
        st.write("Hash value:", hashed_file)