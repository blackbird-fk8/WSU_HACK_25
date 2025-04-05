from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import easygui
import os
import pyperclip  # For clipboard functionality

# Generate RSA keys
def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Encrypt a message using the public key
def encrypt_message(message, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    ciphertext = cipher.encrypt(message.encode('utf-8'))
    return ciphertext

# Decrypt a message using the private key
def decrypt_message(ciphertext, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode('utf-8')

# Save private key to a file
def save_private_key(private_key, filename="private_key.pem"):
    with open(filename, "wb") as key_file:
        key_file.write(private_key)

# Save public key to a file
def save_public_key(public_key, filename="public_key.pem"):
    with open(filename, "wb") as key_file:
        key_file.write(public_key)

# Load private key from a file
def load_private_key(filename="private_key.pem"):
    if not os.path.exists(filename):
        raise FileNotFoundError(f"Private key file '{filename}' not found.")
    with open(filename, "rb") as key_file:
        return key_file.read()

# Load public key from a file
def load_public_key(filename="public_key.pem"):
    if not os.path.exists(filename):
        raise FileNotFoundError(f"Public key file '{filename}' not found.")
    with open(filename, "rb") as key_file:
        return key_file.read()

# Main function with easygui popups
def main():
    while True:
        # Show a choice dialog
        choice = easygui.buttonbox(
            "What would you like to do?",
            "RSA Encrypter/Decrypter",
            choices=["Generate RSA Keys", "Encrypt a Message", "Decrypt a Message", "Exit"]
        )

        if choice == "Generate RSA Keys":
            # Generate and save keys
            private_key, public_key = generate_keys()
            save_private_key(private_key)
            save_public_key(public_key)
            easygui.msgbox("Keys generated and saved to 'private_key.pem' and 'public_key.pem'.", "Success")

        elif choice == "Encrypt a Message":
            # Load public key
            try:
                public_key = load_public_key()
            except FileNotFoundError as e:
                easygui.msgbox(str(e), "Error")
                continue

            # Ask for the message to encrypt
            message = easygui.enterbox("Enter the message to encrypt:", "Encrypt Message")

            if message:
                # Encrypt the message
                ciphertext = encrypt_message(message, public_key)
                # Copy the encrypted message to the clipboard
                pyperclip.copy(str(ciphertext))
                easygui.msgbox(
                    f"Encrypted message:\n{ciphertext}\n\nThe message has been copied to the clipboard.",
                    "Encrypted Message"
                )
            else:
                easygui.msgbox("No message entered!", "Error")

        elif choice == "Decrypt a Message":
            # Load private key
            try:
                private_key = load_private_key()
            except FileNotFoundError as e:
                easygui.msgbox(str(e), "Error")
                continue

            # Ask for the encrypted message
            ciphertext = easygui.enterbox("Enter the encrypted message (in bytes format):", "Decrypt Message")

            if ciphertext:
                try:
                    ciphertext_bytes = eval(ciphertext)  # Convert string input to bytes

                    # Decrypt the message
                    decrypted_message = decrypt_message(ciphertext_bytes, private_key)
                    easygui.msgbox(f"Decrypted message:\n{decrypted_message}", "Decrypted Message")
                except Exception as e:
                    easygui.msgbox(f"Failed to decrypt the message: {e}", "Error")
            else:
                easygui.msgbox("No encrypted message entered!", "Error")

        elif choice == "Exit":
            easygui.msgbox("Goodbye!", "Exit")
            break

if __name__ == "__main__":
    main()
