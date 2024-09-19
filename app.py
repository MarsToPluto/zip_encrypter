import os
import shutil
import base64
import hashlib
from concurrent.futures import ThreadPoolExecutor
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from getpass import getpass

# Global salt storage (could also store per-file if desired)
SALT = os.urandom(16)  # Random salt for PBKDF2


def generate_key_from_passphrase(passphrase, salt=SALT):
    """Derive a cryptographic key from the passphrase using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashlib.sha256(),
        length=32,
        salt=salt,
        iterations=100000,  # 100,000 iterations to slow down brute-force attacks
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
    return key


def encrypt_file(file_path, passphrase):
    """Encrypt a file with a given passphrase."""
    key = generate_key_from_passphrase(passphrase)
    fernet = Fernet(key)

    with open(file_path, 'rb') as file:
        file_data = file.read()

    encrypted_data = fernet.encrypt(file_data)

    with open(f"{file_path}.enc", 'wb') as file:
        file.write(encrypted_data)

    # Optionally delete the original file after encryption
    os.remove(file_path)

    print(f"File '{file_path}' has been encrypted and saved as '{file_path}.enc'.")


def encrypt_folder(folder_path, passphrase):
    """Compress and encrypt a folder."""
    # Compress the folder into a .zip file
    shutil.make_archive(folder_path, 'zip', folder_path)
    zip_file = f"{folder_path}.zip"
    
    encrypt_file(zip_file, passphrase)  # Encrypt the zip file

    print(f"Folder '{folder_path}' has been compressed and encrypted.")


def scan_and_encrypt_directory(passphrase):
    """Scan the current directory for folders and zip files to encrypt."""
    current_dir = os.getcwd()
    tasks = []

    with ThreadPoolExecutor() as executor:
        for root, dirs, files in os.walk(current_dir):
            # Encrypt folders by compressing them
            for folder in dirs:
                folder_path = os.path.join(root, folder)
                # Submit folder encryption tasks to the thread pool
                tasks.append(executor.submit(encrypt_folder, folder_path, passphrase))

            # Encrypt existing zip files
            for file in files:
                if file.endswith('.zip') and not file.endswith('.zip.enc'):
                    file_path = os.path.join(root, file)
                    # Submit zip file encryption tasks to the thread pool
                    tasks.append(executor.submit(encrypt_file, file_path, passphrase))

            # Break if you don't want recursive scanning in subdirectories
            break

        # Wait for all tasks to complete
        for task in tasks:
            task.result()


if __name__ == "__main__":
    action = input("Do you want to (e)ncrypt or (d)ecrypt files? ").lower()

    if action == 'e':
        passphrase = getpass("Enter the passphrase: ")

        # Scan the current directory for folders and zip files
        scan_and_encrypt_directory(passphrase)

    elif action == 'd':
        enc_file_path = input("Enter the path of the encrypted file (.enc): ")
        output_folder = input("Enter the output folder for the decrypted content: ")
        passphrase = getpass("Enter the passphrase: ")

        key = generate_key_from_passphrase(passphrase)
        fernet = Fernet(key)

        try:
            with open(enc_file_path, 'rb') as enc_file:
                encrypted_data = enc_file.read()

            decrypted_data = fernet.decrypt(encrypted_data)

            zip_file = enc_file_path.replace('.enc', '')

            with open(zip_file, 'wb') as zip_file_write:
                zip_file_write.write(decrypted_data)

            shutil.unpack_archive(zip_file, output_folder)
            os.remove(zip_file)

            print(f"File '{enc_file_path}' has been decrypted to '{output_folder}'.")

        except Exception as e:
            print(f"Failed to decrypt. Error: {e}")

    else:
        print("Invalid option.")