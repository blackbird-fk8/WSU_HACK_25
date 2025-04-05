from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import easygui
import os
import pyperclip  # For clipboard functionality
import webbrowser  # For opening a link in the browser


# File to store saved messages
SAVED_MESSAGES_FILE = "saved_messages.txt"

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

# Save a message to the saved messages file
def save_message(message):
    with open(SAVED_MESSAGES_FILE, "a") as file:
        file.write(message + "\n")

# Load saved messages from the file and format them as a numbered list with bold numbers
def load_saved_messages():
    if not os.path.exists(SAVED_MESSAGES_FILE):
        return "No saved messages."
    with open(SAVED_MESSAGES_FILE, "r") as file:
        messages = file.readlines()
    # Format messages as a numbered list with simulated bold numbers and a space
    return "\n".join([f"**{i + 1}.** {message.strip()}" for i, message in enumerate(messages)])

# Clear all saved messages
def clear_saved_messages():
    if os.path.exists(SAVED_MESSAGES_FILE):
        os.remove(SAVED_MESSAGES_FILE)

# Main function with easygui popups
def main():
    # Password protection
    correct_password = "ee2026"  # Set the password to "ee2026"
    password_attempt = easygui.passwordbox("Enter the password to access the program:", "Password Required")

    if password_attempt != correct_password:
        # Open a link to a video when the password is incorrect
        webbrowser.open("https://www.youtube.com/watch?v=dQw4w9WgXcQ")  # Replace with your desired video URL
        easygui.msgbox("LOL NERD YOU DONT KNOW THE PASSWORD.", "Access Denied")
        return  # Exit the program if the password is incorrect

    while True:
        # Show a choice dialog
        choice = easygui.buttonbox(
            "What would you like to do?",
            "RSA Encrypter/Decrypter",
            choices=["Generate RSA Keys", "Encrypt a Message", "Decrypt a Message", "View Saved Messages", "Exit"]
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
                easygui.msgbox(
                    "Public key not found! Please generate RSA keys first.",
                    "Error"
                )
                continue  # Return to the main menu


            # Ask for the message to encrypt
            message = easygui.enterbox("Enter the message to encrypt:", "Encrypt Message")

            if message:
                # Encrypt the message
                ciphertext = encrypt_message(message, public_key)
                # Save the encrypted message
                save_message(str(ciphertext))
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

        elif choice == "View Saved Messages":
            # Load and display saved messages in a scrollable text box
            saved_messages = load_saved_messages()
            easygui.textbox(
                "Here are the saved messages: (Press OK to reset or continue)",
                "Saved Messages",
                saved_messages
            )

            # Add a reset button after displaying the messages
            reset_choice = easygui.ynbox(
                "Do you want to delete all saved messages?",
                "Reset Messages",
                choices=["Yes", "No"]
            )
            if reset_choice:
                clear_saved_messages()
                easygui.msgbox("All saved messages have been deleted.", "Reset Successful")

        elif choice == "Exit":
            easygui.msgbox("Goodbye!", "Exit")
            break

if __name__ == "__main__":
    main()