import tkinter as tk
from tkinter import messagebox
import pyperclip

# Function to handle the button click event
def on_button_click():
    user_input = entry.get()
    if user_input:
        messagebox.showinfo("Input", f"You entered: {user_input}")
        text_to_display.set(user_input)  # Update the displayed text
    else:
        messagebox.showwarning("No Input", "Please enter something.")

# Function to copy text to the clipboard
def copy_to_clipboard():
    text = text_to_display.get()
    if text:
        pyperclip.copy(text)
        messagebox.showinfo("Copied", f"Text copied to clipboard: {text}")
    else:
        messagebox.showwarning("No Text", "There is no text to copy.")

# Set up the main application window
root = tk.Tk()
root.title("Popup with Copy to Clipboard")
root.geometry("400x250")  # Set the window size

# Create a Label and an Entry (input box) widget
label = tk.Label(root, text="Enter something:")
label.pack(pady=10)

entry = tk.Entry(root)
entry.pack(pady=10)

# Create a Button to trigger the input handling
button = tk.Button(root, text="Submit", command=on_button_click)
button.pack(pady=10)

# Label to display the text after user submits
text_to_display = tk.StringVar()
display_label = tk.Label(root, textvariable=text_to_display, wraplength=300)
display_label.pack(pady=10)

# Create a Button to copy the displayed text to clipboard
copy_button = tk.Button(root, text="Copy to Clipboard", command=copy_to_clipboard)
copy_button.pack(pady=10)

# Run the application
root.mainloop()
