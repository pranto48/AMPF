AMPF CLI - Encrypted Folder Service
This repository contains a basic command-line interface (CLI) tool for setting up a simulated "encrypted folder" service on your system.

**Disclaimer:** This tool provides a *demonstration* of password-based encryption and folder creation. For production-grade security and robust service management (e.g., running as a background service, advanced file encryption), additional development and security considerations are required.

## Features

* Prompts for a folder name, a password, and a directory location.
* Derives an encryption key from your password and a unique salt (the password itself is not stored).
* Creates the specified folder and a placeholder file within it.

## Prerequisites

* Python 3.6 or higher
* `pip` (Python package installer)

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/pranto48/AMPF.git
    cd AMPF-CLI
    ```
    *(Replace `pranto48` with your actual GitHub username)*

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Usage

To set up the AMPF service configuration, run the `ampf_cli.py` script:

```bash
python ampf_cli.py
```

Follow the prompts to:
* Enter the desired folder name.
* Set and confirm a password (this password will be used to derive an encryption key).
* Specify the base directory where the AMPF folder will be created.

### Example Interaction:

```
AMPF CLI - Service Management
----------------------------
Enter command (e.g., 'install'): install

--- AMPF Service Setup ---
Enter the desired folder name for AMPF: MySecureVault
Enter a password to encrypt your data (will not be stored directly): ********
Confirm password: ********
Enter the base directory path (e.g., C:\Users\YourUser or /home/youruser): /home/youruser/Documents
Created AMPF folder at: /home/youruser/Documents/MySecureVault
Note: This script creates the folder. Actual file content encryption would be handled by your service logic.
Configuration saved to ampf_config.json

AMPF setup complete!
Remember to keep your password secure. It is NOT stored directly.
The encryption key is derived from your password and a unique salt.
To access or manage your encrypted folder, you would need to run a separate AMPF 'manage' command and provide the same password.
```

## Next Steps for a Full Service

This script provides the foundational logic. To turn this into a full-fledged service, you would need to:

* **Service Daemonization:**
    * **Linux:** Create a `systemd` unit file to run the Python script as a background service.
    * **Windows:** Use tools like `pyinstaller` to create an executable and then `nssm` (Non-Sucking Service Manager) to register it as a Windows Service.
* **Actual File Encryption:** Implement logic within your service to encrypt/decrypt files *placed inside* the `MySecureVault` folder using the derived encryption key.
* **CLI Enhancements:** Expand the `ampf_cli.py` to include commands like `ampf status`, `ampf encrypt <file>`, `ampf decrypt <file>`, `ampf unlock`, etc., requiring the user to provide the password for sensitive operations.
* **Error Handling and Logging:** Add more robust error handling and logging for production use.
* **Security Audit:** Have a security expert review your encryption implementation.
