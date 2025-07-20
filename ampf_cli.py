import os
import getpass
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64

# --- Configuration ---
CONFIG_FILE = "ampf_config.json" # File to store configuration (e.g., encryption key)

def generate_key_from_password(password: str, salt: bytes) -> bytes:
    """
    Generates a cryptographic key from a password using PBKDF2HMAC.
    This is suitable for deriving a key from a user-provided password.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32, # 32 bytes for a 256-bit key
        salt=salt,
        iterations=100000, # High iteration count for security
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def save_config(config: dict):
    """Saves the configuration to a JSON file."""
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)
        print(f"Configuration saved to {CONFIG_FILE}")
    except IOError as e:
        print(f"Error saving configuration: {e}")

def load_config() -> dict | None:
    """Loads the configuration from a JSON file."""
    if not os.path.exists(CONFIG_FILE):
        return None
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        print(f"Error loading configuration: {e}")
        return None

def encrypt_data(data: str, key: bytes) -> bytes:
    """Encrypts data using Fernet symmetric encryption."""
    f = Fernet(key)
    return f.encrypt(data.encode())

def decrypt_data(encrypted_data: bytes, key: bytes) -> str:
    """Decrypts data using Fernet symmetric encryption."""
    f = Fernet(key)
    return f.decrypt(encrypted_data).decode()

def install_ampf():
    """
    Guides the user through setting up the AMPF service configuration.
    """
    print("\n--- AMPF Service Setup ---")

    # 1. Get folder name
    folder_name = input("Enter the desired folder name for AMPF: ").strip()
    if not folder_name:
        print("Folder name cannot be empty. Aborting setup.")
        return

    # 2. Get and encrypt password
    password = getpass.getpass("Enter a password to encrypt your data (will not be stored directly): ")
    if not password:
        print("Password cannot be empty. Aborting setup.")
        return

    confirm_password = getpass.getpass("Confirm password: ")
    if password != confirm_password:
        print("Passwords do not match. Aborting setup.")
        return

    # Generate a new salt for key derivation
    salt = os.urandom(16)
    encryption_key = generate_key_from_password(password, salt)

    # 3. Get directory location
    while True:
        base_directory = input("Enter the base directory path (e.g., C:\\Users\\YourUser or /home/youruser): ").strip()
        if not base_directory:
            print("Directory path cannot be empty.")
            continue
        if not os.path.isdir(base_directory):
            print(f"Directory '{base_directory}' does not exist. Please enter a valid path.")
        else:
            break

    # Construct the full path for the encrypted folder
    encrypted_folder_path = os.path.join(base_directory, folder_name)

    # Create the encrypted folder
    try:
        os.makedirs(encrypted_folder_path, exist_ok=True)
        # Create a placeholder file to indicate this is the "encrypted" folder
        with open(os.path.join(encrypted_folder_path, "README_ENCRYPTED_FOLDER.txt"), "w") as f:
            f.write("This folder is designated for AMPF's encrypted data.\n")
            f.write("Actual file encryption would happen on the contents placed within this folder.\n")
        print(f"Created AMPF folder at: {encrypted_folder_path}")
        print("Note: This script creates the folder. Actual file content encryption would be handled by your service logic.")
    except OSError as e:
        print(f"Error creating directory '{encrypted_folder_path}': {e}")
        return

    # Save the salt (not the key or password) and folder path
    config = {
        "folder_name": folder_name,
        "base_directory": base_directory,
        "encrypted_folder_path": encrypted_folder_path,
        "salt": base64.urlsafe_b64encode(salt).decode('utf-8') # Store salt as base64 string
    }
    save_config(config)

    print("\nAMPF setup complete!")
    print("Remember to keep your password secure. It is NOT stored directly.")
    print("The encryption key is derived from your password and a unique salt.")
    print("To access or manage your encrypted folder, you would need to run a separate AMPF 'manage' command and provide the same password.")

def main():
    """Main function to run the CLI."""
    print("AMPF CLI - Service Management")
    print("----------------------------")

    # For a simple script, we'll just offer an "install" command.
    # In a full CLI, you'd use argparse for commands like 'install', 'status', 'manage', etc.
    command = input("Enter command (e.g., 'install'): ").strip().lower()

    if command == "install":
        install_ampf()
    else:
        print(f"Unknown command: '{command}'. Try 'install'.")

if __name__ == "__main__":
    # Check for cryptography library
    try:
        import cryptography
    except ImportError:
        print("The 'cryptography' library is required. Please install it using:")
        print("pip install cryptography")
        exit(1)
    main()
