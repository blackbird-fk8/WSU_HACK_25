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
import socket  # For network communication
import tempfile  # Add this import at the top of the file

# File to store saved messages
SAVED_MESSAGES_FILE = "saved_messages.txt"

# Define a consistent directory for storing keys
KEYS_DIR = os.path.join(os.path.expanduser("~"), "rsa_keys")  # Use the user's home directory

# Ensure the directory exists
if not os.path.exists(KEYS_DIR):
    os.makedirs(KEYS_DIR)

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
    try:
        # Import the private key
        rsa_key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(rsa_key)

        # Decode the Base64-encoded ciphertext
        ciphertext_bytes = base64.b64decode(ciphertext)
        easygui.msgbox(f"Decoded ciphertext bytes:\n{ciphertext_bytes}", "Debug: Decoded Ciphertext")

        # Decrypt the message
        plaintext = cipher.decrypt(ciphertext_bytes)
        easygui.msgbox(f"Decrypted plaintext bytes:\n{plaintext}", "Debug: Decrypted Plaintext")

        # Return the plaintext as a UTF-8 string
        return plaintext.decode('utf-8')
    except Exception as e:
        easygui.msgbox(f"Decryption failed: {e}", "Error")
        return None

# Save private key to the keys directory
def save_private_key(private_key, filename="private_key.pem"):
    filepath = os.path.join(KEYS_DIR, filename)
    try:
        with open(filepath, "wb") as key_file:
            key_file.write(private_key)
        easygui.msgbox(f"Private key saved to {filepath}", "Success")
    except Exception as e:
        easygui.msgbox(f"An error occurred while saving the private key: {e}", "Error")

# Save public key to the keys directory
def save_public_key(public_key, filename="public_key.pem"):
    filepath = os.path.join(KEYS_DIR, filename)
    try:
        with open(filepath, "wb") as key_file:
            key_file.write(public_key)
        easygui.msgbox(f"Public key saved to {filepath}", "Success")
    except Exception as e:
        easygui.msgbox(f"An error occurred while saving the public key: {e}", "Error")

# Load private key from the keys directory
def load_private_key(filename="private_key.pem"):
    filepath = os.path.join(KEYS_DIR, filename)
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Private key file '{filepath}' not found.")
    with open(filepath, "rb") as key_file:
        return key_file.read()

# Load public key from the keys directory
def load_public_key(filename="public_key.pem"):
    filepath = os.path.join(KEYS_DIR, filename)
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Public key file '{filepath}' not found.")
    with open(filepath, "rb") as key_file:
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

# Function to send a message to another user
def send_message():
    host = easygui.enterbox("Enter the recipient's IP address:", "Send Message")
    if not host:
        easygui.msgbox("No IP address entered. Returning to the main menu.", "No IP Address")
        return

    port = 12345  # Port to connect to
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Attempt to connect to the recipient
        client_socket.connect((host, port))
        easygui.msgbox(f"Connected to {host}:{port}", "Connection Established")

        # Prompt the user to enter a message
        message = easygui.enterbox("Enter your message:", "Send Message")
        if message:
            # Encrypt the message before sending
            public_key = load_public_key()  # Load the public key for encryption
            encrypted_message = encrypt_message(message, public_key)

            # Send the encrypted message
            client_socket.send(encrypted_message.encode('utf-8'))
            easygui.msgbox("Message sent successfully!", "Message Sent")

            # Save the encrypted message to the saved messages file
            save_message(encrypted_message)
        else:
            easygui.msgbox("No message entered. Connection closed.", "No Message")

        client_socket.close()
    except Exception as e:
        easygui.msgbox(f"Failed to send message: {e}", "Connection Error")

# Function to receive a message and decrypt it using the same decryption logic
def receive_message():
    host = socket.gethostbyname(socket.gethostname())  # Get the local IP address
    port = 12345  # Port to listen on
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    easygui.msgbox(f"Waiting for a connection...\nYour IP: {host}", "Waiting for Connection")

    try:
        conn, addr = server_socket.accept()  # Accept an incoming connection
        easygui.msgbox(f"Connected to {addr}", "Connection Established")

        # Receive the encrypted message
        data = conn.recv(1024).decode('utf-8')
        if data:
            # Display the received encrypted message
            decrypt_choice = easygui.buttonbox(
                f"Encrypted message received:\n{data}\n\nWould you like to decrypt it?",
                "Message Received",
                choices=["Decrypt", "Close"]
            )

            if decrypt_choice == "Decrypt":
                try:
                    # Load the private key
                    private_key = load_private_key()

                    # Decrypt the message using the decrypt_message function
                    decrypted_message = decrypt_message(data, private_key)
                    if decrypted_message:
                        easygui.msgbox(f"Decrypted message:\n{decrypted_message}", "Decrypted Message")
                    else:
                        easygui.msgbox("Decryption failed. Please check the keys or the message.", "Error")
                except Exception as e:
                    easygui.msgbox(f"Failed to decrypt the message: {e}", "Error")
            else:
                easygui.msgbox("Message decryption skipped.", "Skipped")
        else:
            easygui.msgbox("No message received.", "No Message")

        conn.close()
        server_socket.close()
    except Exception as e:
        easygui.msgbox(f"Failed to receive message: {e}", "Connection Error")

# Updated main function with "Send" and "Receive" options
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
            choices=[
                "Generate RSA Keys",
                "Encrypt a Message",
                "Decrypt a Message",
                "View Saved Messages",
                "Send",
                "Receive",
                "Exit"
            ]
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
                    # Call the decrypt_message function
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

        elif choice == "Send":
            send_message()

        elif choice == "Receive":
            receive_message()

        elif choice == "Exit":
            easygui.msgbox("Goodbye!", "Exit")
            break

if __name__ == "__main__":
    main()