import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
ENV_PATH = BASE_DIR / ".env"

def generate_secret_key(length=64):
    """
    Generates a cryptographically secure random secret key of a specified length.

    Args:
        length (int): The desired length of the secret key.

    Returns:
        str: The generated secret key as a hexadecimal string.
    """
    # secrets.token_hex(nbytes) generates a random string of hexadecimal digits.
    # Each byte is represented by two hexadecimal digits, so for a 64-character
    # key, we need 32 bytes (32 * 2 = 64).
    if length % 2 != 0:
        raise ValueError("Length must be an even number for hexadecimal representation.")
    
    num_bytes = length // 2
    secret_key = secrets.token_hex(num_bytes)
    with open(ENV_PATH,"w") as f:
        f.write(f"AUTHBARN_SECRET_KEY = {secret_key}")
    return secret_key

# Generate a 64-character secret key
secret_key = generate_secret_key(64)
print(secret_key)
print(f"Length of the secret key: {len(secret_key)}")




