from flask import Flask, jsonify, abort, request
import random
import string
import json
import bcrypt
import requests
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Initialize Flask-Limiter
limiter = Limiter(
    get_remote_address,  # Use the client's IP address for rate limiting
    app=app,
    default_limits=["200 per day", "50 per hour"]  # Global rate limits
)

# List of allowed IP addresses for IP whitelisting
ALLOWED_IPS = {'127.0.0.1', '192.168.1.1'}  # Add your allowed IPs here

generated_passwords = []

def generate_password(length=12, lower=True, upper=True, numbers=True, symbols=True):
    low = string.ascii_lowercase if lower else ''
    upp = string.ascii_uppercase if upper else ''
    num = string.digits if numbers else ''
    symb = string.punctuation if symbols else ''

    passw = low + upp + num + symb

    if not passw:
        return None

    password = ''.join(random.choice(passw) for _ in range(length))
    return password

def password_policy(password):
    """Checks if a password meets policy requirements."""
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    if not any(char.islower() for char in password):
        return "Password must include at least one lowercase letter."
    if not any(char.isupper() for char in password):
        return "Password must include at least one uppercase letter."
    if not any(char.isdigit() for char in password):
        return "Password must include at least one digit."
    if not any(char in string.punctuation for char in password):
        return "Password must include at least one special character."
    return "Valid"

def hash_password(password):
    """Hashes a password using bcrypt."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password_leak(password_hash):
    """Checks if a password hash has been leaked using Have I Been Pwned API."""
    prefix = password_hash[:5]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url)
    if response.status_code == 200:
        hashes = (line.split(':') for line in response.text.splitlines())
        for h, count in hashes:
            if password_hash[5:] == h:
                return True, count
    return False, 0

def ip_whitelist(allowed_ips):
    """Decorator to restrict access based on IP address."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            client_ip = request.remote_addr
            if client_ip not in allowed_ips:
                abort(403, description="Access denied. Your IP is not allowed.")
            return func(*args, **kwargs)
        wrapper.__name__ = func.__name__
        return wrapper
    return decorator

@app.route('/')
def home():
    return (
        "Welcome to the Password Generator!<br>"
        "Go to <a href='/generate-password'>/generate-password</a> to see a generated password.<br>"
        "Visit <a href='/stored-passwords'>/stored-passwords</a> to see stored passwords."
    )

@app.route('/generate-password', methods=['GET'])
@limiter.limit("5 per minute")  # Rate limiting
def generate_password_automatically():
    """Generates a password automatically."""
    
    length = 12
    lower, upper, numbers, symbols = True, True, True, True

    password = generate_password(length, lower, upper, numbers, symbols)
    if password is None:
        abort(400, description="Error: No character set available to generate password.")

    policy_check = password_policy(password)
    if policy_check != "Valid":
        abort(400, description=f"Error: {policy_check}")

    # Hash the password
    hashed_password = hash_password(password)
    hashed_password_hex = hashed_password.hex()

    # Check if the password has been leaked
    is_leaked, count = check_password_leak(hashed_password_hex)
    if is_leaked:
        abort(400, description=f"Error: This password has been leaked {count} times.")

    # Save hashed password to memory and JSON file
    if hashed_password_hex not in generated_passwords:
        generated_passwords.append(hashed_password_hex)
        with open("passwords.json", "w") as file:
            json.dump(generated_passwords, file, indent=4)

    return jsonify({
        "message": "Password generated successfully!",
        "password": password,
        "hashed_password": hashed_password_hex,
        "policy": "Password policy has been satisfied."
    }), 200

@app.route('/stored-passwords', methods=['GET'])
@limiter.limit("5 per minute")  # Rate limiting
@ip_whitelist(ALLOWED_IPS)  # IP whitelisting
def get_stored_passwords():
    """Returns all stored hashed passwords."""
    if not generated_passwords:
        return jsonify({"message": "No passwords have been generated yet."}), 200

    return jsonify({
        "message": "Here are the stored hashed passwords:",
        "hashed_passwords": generated_passwords
    }), 200

if __name__ == '__main__':
    app.run(debug=True, ssl_context=('cert.pem', 'key.pem'))  # HTTPS