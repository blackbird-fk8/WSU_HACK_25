from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes

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
def save_private_key(private_key, filename):
    with open(filename, "wb") as key_file:
        key_file.write(private_key)

# Save public key to a file
def save_public_key(public_key, filename):
    with open(filename, "wb") as key_file:
        key_file.write(public_key)

# Load private key from a file
def load_private_key(filename):
    with open(filename, "rb") as key_file:
        return key_file.read()

# Load public key from a file
def load_public_key(filename):
    with open(filename, "rb") as key_file:
        return key_file.read()

# Main function to demonstrate RSA encryption and decryption
def main():
    print("Welcome to the RSA Encrypter/Decrypter!")
    print("1. Encrypt a message")
    print("2. Decrypt a message")
    choice = input("Enter your choice (1 or 2): ")

    if choice == "1":
        # Generate keys
        private_key, public_key = generate_keys()

        # Save keys to files
        save_private_key(private_key, "private_key.pem")
        save_public_key(public_key, "public_key.pem")

        # Message to encrypt
        message = input("Enter the message to encrypt: ")

        # Encrypt the message
        ciphertext = encrypt_message(message, public_key)
        print(f"Encrypted message: {ciphertext}")

    elif choice == "2":
        # Load keys from files
        private_key = load_private_key("private_key.pem")

        # Encrypted message to decrypt
        ciphertext = input("Enter the encrypted message (in bytes format): ")
        ciphertext = eval(ciphertext)  # Convert string input to bytes

        # Decrypt the message
        try:
            decrypted_message = decrypt_message(ciphertext, private_key)
            print(f"Decrypted message: {decrypted_message}")
        except Exception as e:
            print(f"Failed to decrypt the message: {e}")

    else:
        print("Invalid choice. Please enter 1 or 2.")

if __name__ == "__main__":
    main()