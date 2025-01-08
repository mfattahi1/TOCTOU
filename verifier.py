import hmac
import hashlib
import os
import socket
import time  # Import time for timing

SECRET_KEY = b'shared_secret'  # A shared secret key for HMAC

def generate_nonce():
    return os.urandom(16)

def verifier():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 12345))
    server_socket.listen(1)
    print("Waiting for the Prover to connect...")

    conn, addr = server_socket.accept()
    print(f"Connected to Prover: {addr}")

    # Timing nonce generation
    start_nonce_time = time.perf_counter()
    nonce = generate_nonce()
    conn.send(nonce)
    end_nonce_time = time.perf_counter()
    print(f"Nonce sent: {nonce.hex()}")
    print(f"Nonce generation and sending time: {end_nonce_time - start_nonce_time:.6f} seconds")

    # Timing response verification
    response = conn.recv(1024)
    print(f"Response received: {response.hex()}")

    start_verify_time = time.perf_counter()
    expected = hmac.new(SECRET_KEY, nonce, hashlib.sha256).digest()
    if hmac.compare_digest(response, expected):
        print("Attestation successful. The Prover is trusted.")
    else:
        print("Attestation failed. Possible tampering detected.")
    end_verify_time = time.perf_counter()
    print(f"Verification time: {end_verify_time - start_verify_time:.6f} seconds")

    conn.close()
    server_socket.close()

if __name__ == "__main__":
    verifier()
