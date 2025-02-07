import os
from flask import Flask, request, jsonify
from datetime import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

app = Flask(__name__)

# Load the private key from file
def load_private_key():
    try:
        with open("private_key.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )
        print("Private key loaded successfully.")
        return private_key
    except Exception as e:
        print(f"Error loading private key: {e}")
        return None

# Load the public key from file
def load_public_key():
    try:
        with open("public_key.pem", "rb") as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read()
            )
        print("Public key loaded successfully.")
        return public_key
    except Exception as e:
        print(f"Error loading public key: {e}")
        return None

# Decrypt the RSA-encrypted symmetric key
def decrypt_symmetric_key(encrypted_key, private_key):
    try:
        encrypted_key_bytes = base64.b64decode(encrypted_key)
        print(f"Decoded encrypted key size: {len(encrypted_key_bytes)} bytes")
        decrypted_key = private_key.decrypt(
            encrypted_key_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        print("Symmetric key decrypted successfully.")
        return decrypted_key
    except Exception as e:
        print(f"Error decrypting symmetric key: {e}")
        return None

# Decrypt the AES-encrypted data
def decrypt_aes_data(encrypted_data, iv, symmetric_key):
    try:
        print(f"Starting AES decryption with IV size: {len(iv)}, Encrypted data size: {len(encrypted_data)}, Symmetric key size: {len(symmetric_key)}")
        cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        print("AES decryption successful.")
        return decrypted_data.decode('utf-8')  # Convert to string
    except Exception as e:
        print(f"Error decrypting AES data: {e}")
        return None

@app.route('/public-key', methods=['GET'])
def public_key():
    public_key = load_public_key()
    if public_key:
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return jsonify({"public_key": public_pem.decode()}), 200
    return "Unable to retrieve public key", 500

@app.route('/report', methods=['POST'])
def report():
    print("Received a POST request.")
    print(f"Request headers: {request.headers}")

    # Log the incoming form data
    print(f"Form data received: {request.form}")
    print(f"Files received: {request.files}")

    try:
        # Retrieve message and location directly from the form data
        message = request.form.get('message')
        location = request.form.get('location')

        # Log received data
        print(f"Message received: {message}")
        print(f"Location received: {location}")

        # Process and save the image file
        if 'image' in request.files:
            image = request.files['image']
            print(f"Received image: {image.filename}")

            folder_name = datetime.now().strftime("%Y%m%d_%H%M%S")
            folder_path = f"../received/{folder_name}"
            
            # Ensure the received directory exists
            os.makedirs(folder_path, exist_ok=True)

            image_path = os.path.join(folder_path, image.filename)
            image.save(image_path)
            print(f"Image saved at: {image_path}")
        else:
            print("No image provided.")

        # Save the message and location to a text file
        text_file_path = os.path.join(folder_path, "report.txt")
        with open(text_file_path, 'w') as text_file:
            if location:
                text_file.write(f"Location: {location}\n")
            if message:
                text_file.write(f"Message: {message}\n")
        print(f"Report saved at: {text_file_path}")

        return "Problem received and logged", 200

    except Exception as e:
        print(f"Error processing the request: {e}")
        return "Server error", 500

if __name__ == '__main__':
    app.run(debug=True, port=5001)