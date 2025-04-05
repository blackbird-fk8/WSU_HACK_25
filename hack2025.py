from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import easygui
import os
import pyperclip  # For clipboard functionality
import webbrowser  # For opening a link in the browser
import tkinter as tk
from tkinter import scrolledtext
from threading import Thread
import time
import base64  # Add this import at the top of the file

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
    return base64.b64encode(ciphertext).decode('utf-8')  # Encode as Base64 string

# Decrypt a message using the private key
def decrypt_message(ciphertext, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    ciphertext_bytes = base64.b64decode(ciphertext)  # Decode from Base64 string
    plaintext = cipher.decrypt(ciphertext_bytes)
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
        file.write(message + "\n")  # Message is now a Base64-encoded string

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

# Live Chatbox Functionality
def start_chatbox():
    def send_message():
        message = message_entry.get()
        if message:
            chat_display.insert(tk.END, f"You: {message}\n")
            message_entry.delete(0, tk.END)
            # Simulate receiving a response
            Thread(target=receive_message, args=(message,)).start()

    def receive_message(message):
        time.sleep(1)  # Simulate delay
        response = f"Echo: {message}"  # Replace with actual response logic
        chat_display.insert(tk.END, f"Bot: {response}\n")

    # Create the chatbox window
    chatbox = tk.Tk()
    chatbox.title("Live Chatbox")

    # Chat display area
    chat_display = scrolledtext.ScrolledText(chatbox, wrap=tk.WORD, width=50, height=20)
    chat_display.pack(padx=10, pady=10)
    chat_display.config(state=tk.NORMAL)

    # Message entry area
    message_entry = tk.Entry(chatbox, width=40)
    message_entry.pack(side=tk.LEFT, padx=10, pady=10)

    # Send button
    send_button = tk.Button(chatbox, text="Send", command=send_message)
    send_button.pack(side=tk.RIGHT, padx=10, pady=10)

    chatbox.mainloop()

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
            choices=["Generate RSA Keys", "Encrypt a Message", "Decrypt a Message", "View Saved Messages", "Live Chatbox", "Exit"]
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
            except FileNotFoundError:
                easygui.msgbox(
                    "Public key not found! Please generate RSA keys first.",
                    "Error"
                )
                continue  # Return to the main menu

            # Ask for the message to encrypt
            message = easygui.enterbox("Enter the message to encrypt:", "Encrypt Message")

            if not message:
                easygui.msgbox("No message entered! Please enter a valid message.", "Error")
                continue

            try:
                # Encrypt the message
                ciphertext = encrypt_message(message, public_key)
                # Save the encrypted message
                save_message(ciphertext)
                # Copy the encrypted message to the clipboard
                try:
                    pyperclip.copy(ciphertext)
                    easygui.msgbox(
                        f"Encrypted message:\n{ciphertext}\n\nThe message has been copied to the clipboard.",
                        "Encrypted Message"
                    )
                except pyperclip.PyperclipException:
                    easygui.msgbox(
                        f"Encrypted message:\n{ciphertext}\n\nFailed to copy the message to the clipboard.",
                        "Encrypted Message"
                    )
            except Exception as e:
                easygui.msgbox(f"An error occurred during encryption: {e}", "Error")

        elif choice == "Decrypt a Message":
            # Load private key
            try:
                private_key = load_private_key()
            except FileNotFoundError as e:
                easygui.msgbox(str(e), "Error")
                continue

            # Ask for the encrypted message
            ciphertext = easygui.enterbox("Enter the encrypted message (Base64 format):", "Decrypt Message")

            if ciphertext:
                try:
                    # Decrypt the message
                    decrypted_message = decrypt_message(ciphertext, private_key)
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

        elif choice == "Live Chatbox":
            # Start the live chatbox
            start_chatbox()

        elif choice == "Exit":
            easygui.msgbox("Goodbye!", "Exit")
            break

if __name__ == "__main__":
    main()