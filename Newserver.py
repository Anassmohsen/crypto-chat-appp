import socket
import threading
import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# List to hold connected clients and their session keys 
active_clients = {}
client_session_keys = {}

def encrypt_data(session_key, data):
    """Encrypts the data using the session key and AES encryption."""
    iv = os.urandom(16)  # Generate a random initialization vector
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_data = iv + encryptor.update(data) + encryptor.finalize()  # Return IV + encrypted message
    return encrypted_data

def decrypt_data(session_key, encrypted_data):
    """Decrypts the encrypted data using the session key."""
    iv = encrypted_data[:16]  # Extract the IV from the data
    actual_encrypted_data = encrypted_data[16:]  # Get the encrypted message
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(actual_encrypted_data) + decryptor.finalize()  # Decrypt the message
    return decrypted_data

def send_message_to_all(message, sender_socket):
    """Send an encrypted message to all clients except the sender."""
    for client_socket in active_clients:
        if client_socket != sender_socket:
            try:
                encrypted_message = encrypt_data(client_session_keys[client_socket], message)
                # Display encrypted message in terminal
                print(f"Encrypted message: {encrypted_message.hex()}")
                client_socket.send(encrypted_message)  # Send the encrypted message
            except Exception as e:
                print(f"Error sending message: {e}")

def handle_client_connection(client_socket, client_address):
    """Handles the communication with an individual client."""
    print(f"New connection from {client_address}")
    active_clients[client_socket] = client_address  # Add the new client to the list

    try:
        # Generate RSA keys (public and private)
        public_key, private_key = rsa.newkeys(512)
        client_socket.send(public_key.save_pkcs1())  # Send the public key to the client

        # Receive the encrypted session key from the client
        encrypted_session_key = client_socket.recv(1024)
        session_key = rsa.decrypt(encrypted_session_key, private_key)  # Decrypt the session key
        client_session_keys[client_socket] = session_key  # Store the session key for the client

        # Notify all other clients that this client has joined
        send_message_to_all(f"System: {client_address} has joined the chat.".encode(), client_socket)

        # Handle incoming messages from the client
        while True:
            encrypted_message = client_socket.recv(1024)
            if not encrypted_message:  # Client has disconnected
                break
            # Decrypt the message received from the client
            decrypted_message = decrypt_data(client_session_keys[client_socket], encrypted_message).decode()
            print(f"Encrypted message received: {encrypted_message.hex()}")  # Print encrypted message in hex
            print(f"Decrypted message from {client_address}: {decrypted_message}")  # Print decrypted message
            send_message_to_all(decrypted_message.encode(), client_socket)  # Broadcast the message to others

    except Exception as e:
        print(f"Error handling client {client_address}: {e}")
    finally:
        # Clean up after the client disconnects
        print(f"Client {client_address} disconnected.")
        del active_clients[client_socket]  # Remove client from active list
        del client_session_keys[client_socket]  # Remove client's session key
        client_socket.close()  # Close the connection
        send_message_to_all(f"System: {client_address} has left the chat.".encode(), None)  # Notify others

def start_server():
    """Sets up the server to listen for incoming connections."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("localhost", 1111))  # Bind the server to localhost on port 1111
    server_socket.listen(5)  # Listen for up to 5 connections
    print("Server is running...")

    while True:
        # Accept a new client connection
        client_socket, client_address = server_socket.accept()
        # Start a new thread to handle this client
        threading.Thread(target=handle_client_connection, args=(client_socket, client_address), daemon=True).start()

if __name__ == "__main__":
    start_server()
