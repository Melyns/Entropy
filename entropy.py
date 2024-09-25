from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import time
import numpy as np
import os

max_attempts = 5000
key_length = 1024
entropy_goal = 5.995
current_time = time.time()
timestamp = time.strftime("%Y%m%d%H%M%S", time.localtime(current_time))
log_file = f"entropy_log_{key_length}_{timestamp}.txt"

def calculate_entropy(key):
    pem_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    pem_str = pem_bytes.decode()
    pem_str = pem_str.replace("-----BEGIN RSA PRIVATE KEY-----", "")
    pem_str = pem_str.replace("-----END RSA PRIVATE KEY-----", "")
    pem_str = pem_str.strip()

    byte_array = np.frombuffer(pem_str.encode(), dtype=np.uint8)
    frequencies = np.bincount(byte_array)
    frequencies = frequencies[frequencies > 0]
    probabilities = frequencies / len(byte_array)
    entropy = -np.sum(probabilities * np.log2(probabilities))
    return entropy

attempts = 0
highest_entropy = 0
lowest_entropy = float('inf')
total_entropy = 0
start_time = time.time()

while True:
    attempts += 1
    random_seed = os.urandom(32)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_length, backend=default_backend())
    
    entropy = calculate_entropy(private_key)
    total_entropy += entropy
    if entropy > highest_entropy:
        highest_entropy = entropy
        with open(log_file, "a") as f:
            f.write(f"Entropy: {entropy:.3f} - attempt {attempts:03d}\n")
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ).decode() + "\n\n")
    if entropy < lowest_entropy:
        lowest_entropy = entropy

    current_time = time.time()
    elapsed_time = current_time - start_time
    ops_per_sec = attempts / elapsed_time
    print(f"Attempt {attempts}, Operations/s: {ops_per_sec:.1f}, Current Entropy: {entropy:.3f}, Highest Entropy: {highest_entropy:.3f}, Average Entropy: {(total_entropy / attempts):.3f}, Lowest Entropy: {lowest_entropy:.3f}", end='\r')
    
    if entropy > entropy_goal:
        print()
        print(f"Final Entropy: {entropy:.3f}, Operations/s: {ops_per_sec:.1f}, Highest Entropy: {highest_entropy:.3f}, Average Entropy: {(total_entropy / attempts):.3f}, Lowest Entropy: {lowest_entropy:.3f}")
        print()
        break

    if max_attempts is not None and attempts >= max_attempts:
        print()
        print(f"Reached maximum attempts: {max_attempts}. Stopping.")
        break
