import base64
import json

def encrypt_order(order: dict) -> str:
    """Simulate encryption by encoding the order as base64 JSON."""
    return base64.b64encode(json.dumps(order).encode()).decode()

def decrypt_order(enc_order: str) -> dict:
    """Simulate decryption by decoding base64 JSON."""
    return json.loads(base64.b64decode(enc_order.encode()).decode()) 