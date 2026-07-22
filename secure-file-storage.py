import os
import io
from flask import Flask, request, render_template, send_file, jsonify
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import base64
import json
from pathlib import Path

app = Flask(__name__)

# Create necessary directories
UPLOAD_FOLDER = Path('secure_storage')
KEYS_FOLDER = Path('keys')
for folder in [UPLOAD_FOLDER, KEYS_FOLDER]:
    folder.mkdir(exist_ok=True)


class SecureFileStorage:
    def __init__(self):
        self.metadata_file = UPLOAD_FOLDER / 'metadata.json'
        self.load_metadata()

    def load_metadata(self):
        """Load metadata from file, creating a new one if it doesn't exist or is corrupted"""
        try:
            if self.metadata_file.exists():
                with open(self.metadata_file, 'r') as f:
                    content = f.read().strip()  # Remove any whitespace
                    if content:  # Check if file is not empty
                        self.metadata = json.loads(content)
                    else:
                        self.metadata = {}
            else:
                self.metadata = {}
        except (json.JSONDecodeError, IOError) as e:
            print(f"Error loading metadata: {str(e)}. Creating new metadata file.")
            self.metadata = {}
        finally:
            self.save_metadata()

    def save_metadata(self):
        """Save metadata to file with error handling"""
        try:
            with open(self.metadata_file, 'w') as f:
                json.dump(self.metadata, f, indent=2)
        except IOError as e:
            print(f"Error saving metadata: {str(e)}")

    def generate_keys(self):
        """Generate RSA key pair for encryption and ECC key pair for signing"""
        # Generate RSA keys
        rsa_key = RSA.generate(2048)
        private_key = rsa_key.export_key()
        public_key = rsa_key.publickey().export_key()

        # Generate ECC keys for signing
        ecc_key = ECC.generate(curve='P-256')
        signing_key = ecc_key.export_key(format='PEM')
        verify_key = ecc_key.public_key().export_key(format='PEM')

        # Save keys
        with open(KEYS_FOLDER / 'private_key.pem', 'wb') as f:
            f.write(private_key)
        with open(KEYS_FOLDER / 'public_key.pem', 'wb') as f:
            f.write(public_key)
        with open(KEYS_FOLDER / 'signing_key.pem', 'wb') as f:
            f.write(signing_key.encode())
        with open(KEYS_FOLDER / 'verify_key.pem', 'wb') as f:
            f.write(verify_key.encode())

        return {
            'private_key': private_key.decode(),
            'public_key': public_key.decode(),
            'signing_key': signing_key,
            'verify_key': verify_key
        }

    def encrypt_file(self, file_data, filename):
        """Encrypt file using AES and encrypt the AES key using RSA"""
        # Generate AES key and encrypt file
        aes_key = get_random_bytes(32)
        cipher_aes = AES.new(aes_key, AES.MODE_GCM)
        ciphertext, tag = cipher_aes.encrypt_and_digest(file_data)

        # Load RSA public key and encrypt AES key
        public_key = RSA.import_key(open(KEYS_FOLDER / 'public_key.pem').read())
        cipher_rsa = PKCS1_OAEP.new(public_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)

        # Calculate file hash
        file_hash = SHA256.new(file_data)

        # Sign the hash
        signer = DSS.new(ECC.import_key(open(KEYS_FOLDER / 'signing_key.pem').read()), 'fips-186-3')
        signature = signer.sign(file_hash)

        # Save encrypted file
        encrypted_filename = f"{filename}.encrypted"
        with open(UPLOAD_FOLDER / encrypted_filename, 'wb') as f:
            [f.write(x) for x in (encrypted_aes_key, cipher_aes.nonce, tag, ciphertext)]

        # Save metadata with private key in PEM format
        with open(KEYS_FOLDER / 'private_key.pem', 'r') as f:
            private_key_pem = f.read()

        with open(KEYS_FOLDER / 'verify_key.pem', 'r') as f:
            verify_key_pem = f.read()

        self.metadata[encrypted_filename] = {
            'original_filename': filename,
            'hash': file_hash.hexdigest(),
            'signature': base64.b64encode(signature).decode(),
            'private_key_pem': private_key_pem,
            'v_key': verify_key_pem

        }
        self.save_metadata()

        return encrypted_filename

    def decrypt_file(self, encrypted_filename):
        """Decrypt file and verify its integrity and signature"""
        if not (UPLOAD_FOLDER / encrypted_filename).exists():
            raise FileNotFoundError("Encrypted file not found")

        # Read the encrypted file
        with open(UPLOAD_FOLDER / encrypted_filename, 'rb') as f:
            encrypted_aes_key = f.read(256)  # RSA-2048 encrypted key
            nonce = f.read(16)  # GCM nonce
            tag = f.read(16)  # GCM tag
            ciphertext = f.read()  # Encrypted data

        # Load RSA private key and decrypt AES key
        private_key = RSA.import_key(self.metadata[encrypted_filename]['private_key_pem'])
        cipher_rsa = PKCS1_OAEP.new(private_key)
        aes_key = cipher_rsa.decrypt(encrypted_aes_key)

        # Decrypt file
        cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)

        # Verify hash and signature
        file_hash = SHA256.new(data)
        stored_hash = self.metadata[encrypted_filename]['hash']
        if file_hash.hexdigest() != stored_hash:
            raise ValueError("File integrity check failed")

        # Create verifier with the correct mode parameter
        verifier = DSS.new(ECC.import_key(self.metadata[encrypted_filename]['v_key']), 'deterministic-rfc6979')
        signature = base64.b64decode(self.metadata[encrypted_filename]['signature'])
        try:
            verifier.verify(file_hash, signature)
        except ValueError:
            raise ValueError("File signature verification failed")

        return data, self.metadata[encrypted_filename]['original_filename']

    def delete_file(self, encrypted_filename):
        """Delete an encrypted file and remove its metadata."""
        file_path = UPLOAD_FOLDER / encrypted_filename
        if file_path.exists():
            file_path.unlink()  # Delete the file
            # Remove metadata if the file exists in metadata
            if encrypted_filename in self.metadata:
                del self.metadata[encrypted_filename]
                self.save_metadata()
            return True
        else:
            raise FileNotFoundError("File not found")


storage = SecureFileStorage()

# Flask routes
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/generate_keys', methods=['POST'])
def generate_keys():
    try:
        keys = storage.generate_keys()
        return jsonify({'status': 'success', 'message': 'Keys generated successfully'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'status': 'error', 'message': 'No file provided'})

    file = request.files['file']
    if file.filename == '':
        return jsonify({'status': 'error', 'message': 'No file selected'})

    try:
        encrypted_filename = storage.encrypt_file(file.read(), file.filename)
        return jsonify({
            'status': 'success',
            'message': 'File encrypted and stored successfully',
            'filename': encrypted_filename
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/download/<filename>')
def download_file(filename):
    try:
        data, original_filename = storage.decrypt_file(filename)
        return send_file(
            io.BytesIO(data),
            download_name=original_filename,
            as_attachment=True
        )
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


@app.route('/files')
def list_files():
    return jsonify({
        'status': 'success',
        'files': [
            {
                'encrypted_filename': filename,
                'original_filename': metadata['original_filename']
            }
            for filename, metadata in storage.metadata.items()
        ]
    })


@app.route('/delete/<filename>', methods=['DELETE'])
def delete_file(filename):
    try:
        storage.delete_file(filename)
        return jsonify({'status': 'success', 'message': f'File {filename} deleted successfully'})
    except FileNotFoundError:
        return jsonify({'status': 'error', 'message': 'File not found'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})


if __name__ == '__main__':
    app.run(debug=True)