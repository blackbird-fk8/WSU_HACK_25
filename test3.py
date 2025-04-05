import socket
import threading
import json
import time
import base64
import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os

# Configuration
HOST = '0.0.0.0'  # Server listens on all interfaces
PORT = 5555
BUFFER_SIZE = 4096

class SecureChat:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat")
        self.root.geometry("700x500")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Initialize variables
        self.server_socket = None
        self.client_socket = None
        self.server_thread = None
        self.clients = {}  # {client_address: (socket, username, public_key)}
        self.connected = False
        self.is_server = False
        self.username = ""
        self.user_keys = {}  # {username: public_key}
        
        # RSA keys
        self.private_key = None
        self.public_key = None
        
        # Set up the UI
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the user interface"""
        # Main frame
        main_frame = tk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Setup frame
        setup_frame = tk.Frame(main_frame)
        setup_frame.pack(fill=tk.X, pady=5)
        
        # Server/Client choice
        self.is_server_var = tk.BooleanVar(value=False)
        server_radio = tk.Radiobutton(setup_frame, text="Start Server", variable=self.is_server_var, value=True)
        server_radio.pack(side=tk.LEFT, padx=5)
        
        client_radio = tk.Radiobutton(setup_frame, text="Join Chat", variable=self.is_server_var, value=False)
        client_radio.pack(side=tk.LEFT, padx=5)
        
        # Host/IP input
        tk.Label(setup_frame, text="Host:").pack(side=tk.LEFT, padx=(10, 0))
        self.host_input = tk.Entry(setup_frame, width=15)
        self.host_input.insert(0, "localhost")
        self.host_input.pack(side=tk.LEFT, padx=5)
        
        # Connect button
        self.connect_button = tk.Button(setup_frame, text="Connect", command=self.handle_connection)
        self.connect_button.pack(side=tk.RIGHT, padx=5)
        
        # Username input
        tk.Label(setup_frame, text="Username:").pack(side=tk.LEFT, padx=(10, 0))
        self.username_input = tk.Entry(setup_frame, width=15)
        self.username_input.pack(side=tk.LEFT, padx=5)
        
        # Chat area
        self.chat_display = scrolledtext.ScrolledText(main_frame, wrap=tk.WORD, height=20)
        self.chat_display.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.chat_display.config(state=tk.DISABLED)
        
        # Input area with recipient selection
        input_frame = tk.Frame(main_frame)
        input_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Recipient selection
        tk.Label(input_frame, text="To:").pack(side=tk.LEFT, padx=(0, 5))
        
        self.recipient_var = tk.StringVar(value="Everyone")
        self.recipient_menu = tk.OptionMenu(input_frame, self.recipient_var, "Everyone")
        self.recipient_menu.pack(side=tk.LEFT, padx=5)
        
        # Message input
        self.message_input = tk.Entry(input_frame)
        self.message_input.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.message_input.bind("<Return>", self.send_message)
        
        # Send button
        send_button = tk.Button(input_frame, text="Send", command=self.send_message)
        send_button.pack(side=tk.RIGHT)
        
        # User list
        user_frame = tk.Frame(main_frame)
        user_frame.pack(fill=tk.X, padx=5, pady=5)
        
        tk.Label(user_frame, text="Online Users:").pack(side=tk.LEFT)
        
        self.user_listbox = tk.Listbox(user_frame, height=3)
        self.user_listbox.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        
        # Status bar
        self.status_var = tk.StringVar(value="Not connected")
        status_label = tk.Label(self.root, textvariable=self.status_var, bd=1, relief=tk.SUNKEN, anchor=tk.W)
        status_label.pack(side=tk.BOTTOM, fill=tk.X)
        
    def handle_connection(self):
        """Handle connection setup based on server/client selection"""
        self.username = self.username_input.get().strip()
        
        if not self.username:
            messagebox.showerror("Error", "Username is required")
            return
            
        # Disable connection controls
        self.connect_button.config(state=tk.DISABLED)
        self.username_input.config(state=tk.DISABLED)
        self.host_input.config(state=tk.DISABLED)
        
        # Load or generate RSA keys
        self.load_or_generate_keys()
        
        if self.is_server_var.get():
            # Start as server
            self.is_server = True
            self.start_server()
        else:
            # Connect as client
            host = self.host_input.get().strip()
            self.connect_to_server(host)
            
    def start_server(self):
        """Start the chat server"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((HOST, PORT))
            self.server_socket.listen(5)
            
            self.status_var.set(f"Server running on port {PORT}")
            self.add_message("System", f"Server started. Waiting for connections...", "system")
            
            # Connect to self as a client
            self.connect_to_server("localhost")
            
            # Start server thread
            self.server_thread = threading.Thread(target=self.accept_connections)
            self.server_thread.daemon = True
            self.server_thread.start()
            
        except Exception as e:
            self.status_var.set(f"Server error: {e}")
            self.add_message("System", f"Failed to start server: {e}", "error")
            self.reset_connection_controls()
            
    def accept_connections(self):
        """Accept incoming connections"""
        try:
            while True:
                client_socket, client_address = self.server_socket.accept()
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address)
                )
                client_thread.daemon = True
                client_thread.start()
                
        except:
            pass  # Server socket closed
            
    def handle_client(self, client_socket, client_address):
        """Handle communication with a connected client"""
        try:
            # Receive join message
            data = client_socket.recv(BUFFER_SIZE)
            if not data:
                return
                
            message = json.loads(data.decode('utf-8'))
            
            if message['type'] == 'join':
                username = message['username']
                public_key = message['public_key']
                
                # Store client info
                self.clients[client_address] = (client_socket, username, public_key)
                
                # Notify others of new user
                self.broadcast({
                    'type': 'system',
                    'message': f"{username} has joined the chat."
                }, None)
                
                # Send user list to the new client
                self.send_user_list(client_socket)
                
                self.add_message("System", f"{username} connected from {client_address[0]}:{client_address[1]}", "system")
                
            # Handle client messages
            while True:
                data = client_socket.recv(BUFFER_SIZE)
                if not data:
                    break
                    
                message = json.loads(data.decode('utf-8'))
                
                if message['type'] == 'message':
                    sender_username = self.clients[client_address][1]
                    
                    msg_payload = {
                        'type': 'message',
                        'sender': sender_username,
                        'encrypted_message': message['encrypted_message'],
                        'recipient': message.get('recipient', 'all')
                    }
                    
                    self.broadcast(msg_payload, client_address)
                    
        except Exception as e:
            print(f"Error handling client {client_address}: {e}")
            
        finally:
            # Clean up when client disconnects
            if client_address in self.clients:
                username = self.clients[client_address][1]
                del self.clients[client_address]
                
                self.broadcast({
                    'type': 'system',
                    'message': f"{username} has left the chat."
                }, None)
                
                self.add_message("System", f"{username} disconnected", "system")
                
            client_socket.close()
            
    def broadcast(self, message, sender_address):
        """Broadcast a message to all connected clients except the sender"""
        payload = json.dumps(message).encode('utf-8')
        
        disconnected_clients = []
        
        for client_address, (client_socket, _, _) in self.clients.items():
            if client_address != sender_address:  # Don't send to the sender
                try:
                    client_socket.sendall(payload)
                except:
                    disconnected_clients.append(client_address)
                    
        # Remove disconnected clients
        for client_address in disconnected_clients:
            if client_address in self.clients:
                username = self.clients[client_address][1]
                del self.clients[client_address]
                self.add_message("System", f"{username} disconnected", "system")
                
    def connect_to_server(self, host):
        """Connect to the chat server"""
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((host, PORT))
            
            # Send join message
            join_message = {
                'type': 'join',
                'username': self.username,
                'public_key': self.public_key.decode('utf-8')
            }
            
            self.client_socket.sendall(json.dumps(join_message).encode('utf-8'))
            
            # Update status
            self.connected = True
            self.status_var.set(f"Connected as {self.username}")
            
            # Start receiving messages
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
            
            self.add_message("System", f"Connected to the server as {self.username}", "system")
            
        except Exception as e:
            self.status_var.set(f"Connection error: {e}")
            self.add_message("System", f"Failed to connect: {e}", "error")
            self.reset_connection_controls()
            
    def send_user_list(self, client_socket):
        """Send the list of connected users to a client"""
        user_list = [
            {'username': username, 'public_key': public_key}
            for _, (_, username, public_key) in self.clients.items()
        ]
        
        message = {
            'type': 'user_list',
            'users': user_list
        }
        
        try:
            client_socket.sendall(json.dumps(message).encode('utf-8'))
        except Exception as e:
            print(f"Error sending user list: {e}")
            
    def receive_messages(self):
        """Receive and process messages from the server"""
        while self.connected:
            try:
                data = self.client_socket.recv(BUFFER_SIZE)
                if not data:
                    break
                    
                message = json.loads(data.decode('utf-8'))
                
                if message['type'] == 'message':
                    # Handle encrypted message
                    sender = message['sender']
                    encrypted_message_b64 = message['encrypted_message']
                    recipient = message.get('recipient', 'all')
                    
                    if recipient == 'all' or recipient == self.username:
                        try:
                            # Decrypt the message
                            encrypted_message = base64.b64decode(encrypted_message_b64)
                            decrypted_message = self.decrypt_message(encrypted_message)
                            
                            # Add message to chat
                            self.add_message(sender, decrypted_message, "message")
                        except Exception as e:
                            self.add_message("System", f"Failed to decrypt message from {sender}: {e}", "error")
                
                elif message['type'] == 'system':
                    # Handle system message
                    self.add_message("System", message['message'], "system")
                
                elif message['type'] == 'user_list':
                    # Update user list
                    self.update_user_list(message['users'])
                    
            except Exception as e:
                if self.connected:
                    self.add_message("System", f"Connection error: {e}", "error")
                break
                
        # If we got here, the connection was lost
        if self.connected:
            self.connected = False
            self.status_var.set("Disconnected")
            self.add_message("System", "Connection lost", "error")
            self.reset_connection_controls()
            
    def update_user_list(self, users):
        """Update the list of online users"""
        # Clear existing list
        self.user_listbox.delete(0, tk.END)
        
        # Update recipient dropdown
        menu = self.recipient_menu["menu"]
        menu.delete(0, tk.END)
        menu.add_command(label="Everyone", command=lambda: self.recipient_var.set("Everyone"))
        
        # Add users to list and dropdown
        for user_info in users:
            username = user_info['username']
            public_key = user_info['public_key']
            
            # Skip our own username
            if username != self.username:
                self.user_listbox.insert(tk.END, username)
                menu.add_command(label=username, command=lambda name=username: self.recipient_var.set(name))
                
                # Store the user's public key
                self.user_keys[username] = public_key
                
    def load_or_generate_keys(self):
        """Load existing RSA keys or generate new ones"""
        # Create keys directory if it doesn't exist
        os.makedirs("keys", exist_ok=True)
        
        # Key file paths
        private_key_path = os.path.join("keys", "private_key.pem")
        public_key_path = os.path.join("keys", "public_key.pem")
        
        # Check if keys exist
        if os.path.exists(private_key_path) and os.path.exists(public_key_path):
            # Load existing keys
            with open(private_key_path, "rb") as key_file:
                self.private_key = key_file.read()
            with open(public_key_path, "rb") as key_file:
                self.public_key = key_file.read()
        else:
            # Generate new keys
            key = RSA.generate(2048)
            self.private_key = key.export_key()
            self.public_key = key.publickey().export_key()
            
            # Save keys
            with open(private_key_path, "wb") as key_file:
                key_file.write(self.private_key)
            with open(public_key_path, "wb") as key_file:
                key_file.write(self.public_key)
                
    def send_message(self, event=None):
        """Send a message to the server"""
        if not self.connected:
            messagebox.showerror("Error", "Not connected to server")
            return
            
        message_text = self.message_input.get().strip()
        if not message_text:
            return
            
        recipient = self.recipient_var.get()
        if recipient == "Everyone":
            recipient = "all"
            
        try:
            # Encrypt the message for simplicity, we'll encrypt with our own key
            # In a real app, we'd encrypt with the recipient's key
            encrypted_message = self.encrypt_message(message_text, self.public_key)
            
            # Convert to base64 for JSON
            encrypted_message_b64 = base64.b64encode(encrypted_message).decode('utf-8')
            
            # Create message payload
            message_payload = {
                'type': 'message',
                'encrypted_message': encrypted_message_b64,
                'recipient': recipient
            }
            
            # Send to server
            self.client_socket.sendall(json.dumps(message_payload).encode('utf-8'))
            
            # Clear input
            self.message_input.delete(0, tk.END)
            
            # Display sent message
            if recipient == "all":
                self.add_message(f"{self.username} (You)", message_text, "own_message")
            else:
                self.add_message(f"You to {recipient}", message_text, "private_message")
                
        except Exception as e:
            messagebox.showerror("Send Error", f"Failed to send message: {e}")
            
    def encrypt_message(self, message, public_key_str):
        """Encrypt a message using a public key"""
        if isinstance(public_key_str, str):
            public_key_str = public_key_str.encode('utf-8')
            
        rsa_key = RSA.import_key(public_key_str)
        cipher = PKCS1_OAEP.new(rsa_key)
        return cipher.encrypt(message.encode('utf-8'))
        
    def decrypt_message(self, encrypted_message):
        """Decrypt a message using our private key"""
        rsa_key = RSA.import_key(self.private_key)
        cipher = PKCS1_OAEP.new(rsa_key)
        return cipher.decrypt(encrypted_message).decode('utf-8')
        
    def add_message(self, sender, message, message_type):
        """Add a message to the chat display"""
        # Run on the main thread
        self.root.after(0, self._add_message_ui, sender, message, message_type)
            
    def _add_message_ui(self, sender, message, message_type):
        """Add a message to the chat display (UI thread)"""
        self.chat_display.config(state=tk.NORMAL)
        
        # Format timestamp
        timestamp = time.strftime("%H:%M:%S")
        
        # Format message based on type
        if message_type == "system":
            self.chat_display.insert(tk.END, f"[{timestamp}] ", "timestamp")
            self.chat_display.insert(tk.END, f"{sender}: ", "system_sender")
            self.chat_display.insert(tk.END, f"{message}\n", "system_message")
        elif message_type == "error":
            self.chat_display.insert(tk.END, f"[{timestamp}] ", "timestamp")
            self.chat_display.insert(tk.END, f"{sender}: ", "error_sender")
            self.chat_display.insert(tk.END, f"{message}\n", "error_message")
        elif message_type == "own_message":
            self.chat_display.insert(tk.END, f"[{timestamp}] ", "timestamp")
            self.chat_display.insert(tk.END, f"{sender}: ", "own_sender")
            self.chat_display.insert(tk.END, f"{message}\n", "own_message")
        elif message_type == "private_message":
            self.chat_display.insert(tk.END, f"[{timestamp}] ", "timestamp")
            self.chat_display.insert(tk.END, f"{sender}: ", "private_sender")
            self.chat_display.insert(tk.END, f"{message}\n", "private_message")
        else:  # Regular message
            self.chat_display.insert(tk.END, f"[{timestamp}] ", "timestamp")
            self.chat_display.insert(tk.END, f"{sender}: ", "sender")
            self.chat_display.insert(tk.END, f"{message}\n", "message")
            
        # Set text tags/styles
        self.chat_display.tag_config("timestamp", foreground="gray")
        self.chat_display.tag_config("sender", foreground="blue", font=("Arial", 10, "bold"))
        self.chat_display.tag_config("message", foreground="black")
        self.chat_display.tag_config("system_sender", foreground="green", font=("Arial", 10, "bold"))
        self.chat_display.tag_config("system_message", foreground="green")
        self.chat_display.tag_config("error_sender", foreground="red", font=("Arial", 10, "bold"))
        self.chat_display.tag_config("error_message", foreground="red")
        self.chat_display.tag_config("own_sender", foreground="purple", font=("Arial", 10, "bold"))
        self.chat_display.tag_config("own_message", foreground="purple")
        self.chat_display.tag_config("private_sender", foreground="brown", font=("Arial", 10, "bold"))
        self.chat_display.tag_config("private_message", foreground="brown")
        
        # Scroll to bottom
        self.chat_display.see(tk.END)
        self.chat_display.config(state=tk.DISABLED)
    
    def reset_connection_controls(self):
        """Reset connection control elements"""
        self.connect_button.config(state=tk.NORMAL)
        self.username_input.config(state=tk.NORMAL)
        self.host_input.config(state=tk.NORMAL)
            
    def on_closing(self):
        """Handle window closing"""
        # Clean up connections
        self.connected = False
        
        if self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass
                
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
                
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureChat(root)
    root.mainloop()