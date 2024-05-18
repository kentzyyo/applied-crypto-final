import streamlit as st
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm

st.title("DSA Signature")

st.markdown(
    """
    The Digital Signature Algorithm (DSA) is a Federal Information Processing Standard for digital signatures. Digital signatures are used to verify the authenticity and integrity of a message, software, or digital document.
    """
)

st.write("""
## Instructions:
1. Make sure your keys are in PEM format.
2. A public key should look like:
    ```
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2u...
    -----END PUBLIC KEY-----
    ```
3. A private key should look like:
    ```
    -----BEGIN PRIVATE KEY-----
    MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKY...
    -----END PRIVATE KEY-----
    ```
4. Ensure there are no extra spaces or newlines in the PEM data.
""")

col1, col2, col3, col4 = st.columns([2, 1, 1, 1])

with col1:
    mode = st.radio("Mode", ("Sign", "Verify"))

with col1:
    message_input = st.text_area("Enter Message:", key="message_input")
    key_input = st.text_area("Enter Private/Public Key:", key="key_input")

def generate_dsa_keypair():
    private_key = dsa.generate_private_key(key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

with col3:
    pass

with col4:
    if st.button("Generate New Keys"):
        private_key, public_key = generate_dsa_keypair()

        st.text_area("Private Key:", private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode("utf-8"), key="private_key")

        st.text_area("Public Key:", public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8"), key="public_key")

def process_message(message, key, mode):
    try:
        if mode == "Sign":
            private_key = serialization.load_pem_private_key(
                key.encode(), password=None
            )
            signature = private_key.sign(
                message.encode(),
                hashes.SHA256()
            )
            return signature.hex()  
        elif mode == "Verify":
            public_key = serialization.load_pem_public_key(key.encode())
            signature_bytes = bytes.fromhex(message)  
            try:
                public_key.verify(
                    signature_bytes,
                    key_input.encode(),
                    hashes.SHA256()
                )
                return "Signature is valid"
            except InvalidSignature:
                return "Signature is invalid"
    except (ValueError, UnsupportedAlgorithm, TypeError) as e:
        st.error(f"An error occurred: {e}")
        return None

if st.button("Process"):
    result = process_message(message_input, key_input, mode)
    if result:
        st.text_area(f"{mode}ed Message:", result, key="result")
    else:
        st.error("Invalid key or message. Please check your input.")

