import hmac
import hashlib
import socket
import time  # Import time for timing

SECRET_KEY = b'shared_secret'

def prover():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 12345))

    # Timing nonce receiving
    start_receive_time = time.perf_counter()
    nonce = client_socket.recv(1024)
    end_receive_time = time.perf_counter()
    print(f"Nonce received: {nonce.hex()}")
    print(f"Time taken to receive nonce: {end_receive_time - start_receive_time:.6f} seconds")

    # Timing HMAC computation
    start_hmac_time = time.perf_counter()
    response = hmac.new(SECRET_KEY, nonce, hashlib.sha256).digest()
    end_hmac_time = time.perf_counter()
    print(f"HMAC computation time: {end_hmac_time - start_hmac_time:.6f} seconds")
    print(f"Computed HMAC: {response.hex()}")

    client_socket.send(response)
    print("Response sent to Verifier.")
    client_socket.close()

if __name__ == "__main__":
    prover()
