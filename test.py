import easygui
import os
import pyperclip  # For clipboard functionality
import webbrowser  # For opening a link in the browser


# File to store saved messages
SAVED_MESSAGES_FILE = "saved_messages.txt"

# Generate RSA keys
def generate_keys():
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
            if message:
                # Encrypt the message
                ciphertext = encrypt_message(message, public_key)
                # Save the encrypted message
                save_message(str(ciphertext))
                # Copy the encrypted message to the clipboard
                pyperclip.copy(str(ciphertext))
                easygui.msgbox
            else:
                easygui.msgbox("No encrypted message entered!", "Error")

        elif choice == "View Saved Messages":
            # Load and display saved messages in a scrollable text box
            saved_messages = load_saved_messages()
            easygui.textbox(
                "Here are the saved messages:",
                "Saved Messages",
                saved_messages
            )

        elif choice == "Exit":
            easygui.msgbox("Goodbye!", "Exit")
            break

if __name__ == "__main__":
    main()