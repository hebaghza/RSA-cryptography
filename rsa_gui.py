import tkinter as tk
import math
import hashlib

# Global variables for RSA keys
p, q, n, r, e, d = 0, 0, 0, 0, 0, 0

# Function to check if a number is prime
def prime_check(a):
    if a == 2:
        return True
    elif a < 2 or a % 2 == 0:
        return False
    for i in range(3, int(math.sqrt(a)) + 1, 2):
        if a % i == 0:
            return False
    return True

# Function to calculate the greatest common divisor (GCD)
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

# Function to find the multiplicative inverse of e modulo r
def multiplicative_inverse(e, r):
    original_r = r
    x, y = 0, 1
    last_x, last_y = 1, 0

    while r != 0:
        quotient = e // r
        e, r = r, e % r
        x, last_x = last_x - quotient * x, x
        y, last_y = last_y - quotient * y, y

    if last_x < 0:
        last_x += original_r
    return last_x

# Function to generate RSA keys
def generate_keys():
    global p, q, n, r, e, d
    p = int(entry_p.get())
    q = int(entry_q.get())

    # Check if p and q are prime
    if not prime_check(p) or not prime_check(q):
        result_label.config(text="Both p and q must be prime.")
        return

    n = p * q
    r = (p - 1) * (q - 1)

    # Find e
    for i in range(2, r):
        if gcd(i, r) == 1:
            e = i
            break

    # Find d using Extended Euclidean Algorithm
    d = multiplicative_inverse(e, r)

    # Update labels with the generated keys
    public_key_label.config(text=f"Alice's Public Key: (e={e}, n={n})")
    private_key_label.config(text=f"Alice's Private Key: (d={d}, n={n})")

# Function to encrypt a message using the public key
def encrypt_message():
    global e, n
    message = entry_message.get()
    encrypted_message = []
    for char in message:
        encrypted_char = pow(ord(char), e, n)
        encrypted_message.append(str(encrypted_char))
    encrypted_message_str = ' '.join(encrypted_message)
    encrypted_message_label.config(text=f"Encrypted Message: {encrypted_message_str}")

# Function to decrypt a message using the private key
def decrypt_message():
    global d, n
    encrypted_message_str = encrypted_message_label.cget("text").split(": ")[1].strip()
    encrypted_message = encrypted_message_str.split()
    decrypted_message = ''
    for char in encrypted_message:
        decrypted_char = pow(int(char), d, n)
        decrypted_message += chr(decrypted_char)
    decrypted_message_label.config(text=f"Decrypted Message: {decrypted_message}")

# Function to hash a message using SHA-1
def hash_function(message):
    sha1 = hashlib.sha1()
    sha1.update(message.encode())
    return int(sha1.hexdigest(), 16)

# Function to sign a message using Alice's private key
def alice_signing(d, n, message):
    cipher = ''
    for m in message:
        c = ord(m)
        cipher = cipher + str(pow(c, d, n)) + ' '
    return cipher.strip()

# Function to verify a signed message using Alice's public key
def bob_verify(e, n, cipher, message):
    plainMsg = ''
    sp = cipher.split()
    for c in sp:
        if c:
            p = int(c)
            plainMsg += chr(pow(p, e, n))
    return plainMsg == message

# Initialize the GUI
root = tk.Tk()
root.title("RSA Encryption/Decryption with Digital Signature")

frame = tk.Frame(root)
frame.pack(padx=10, pady=10)

# Prime input for p
p_label = tk.Label(frame, text="Enter Alice's p:")
p_label.grid(row=0, column=0)
entry_p = tk.Entry(frame)
entry_p.grid(row=0, column=1)

# Prime input for q
q_label = tk.Label(frame, text="Enter Alice's q:")
q_label.grid(row=1, column=0)
entry_q = tk.Entry(frame)
entry_q.grid(row=1, column=1)

# Button to generate RSA keys
generate_button = tk.Button(frame, text="Generate Alice's Keys", command=generate_keys)
generate_button.grid(row=2, columnspan=2)

# Labels to display the generated public and private keys
public_key_label = tk.Label(frame, text="Alice's Public Key: (e=?, n=?)")
public_key_label.grid(row=3, columnspan=2)

private_key_label = tk.Label(frame, text="Alice's Private Key: (d=?, n=?)")
private_key_label.grid(row=4, columnspan=2)

# Input for the message to be encrypted
message_label = tk.Label(frame, text="Enter Alice's message:")
message_label.grid(row=5, column=0)
entry_message = tk.Entry(frame)
entry_message.grid(row=5, column=1)

# Button to encrypt the message
encrypt_button = tk.Button(frame, text="Encrypt", command=encrypt_message)
encrypt_button.grid(row=6, columnspan=2)

# Label to display the encrypted message
encrypted_message_label = tk.Label(frame, text="Encrypted Message: ")
encrypted_message_label.grid(row=7, columnspan=2)

# Button to decrypt the message
decrypt_button = tk.Button(frame, text="Decrypt", command=decrypt_message)
decrypt_button.grid(row=8, columnspan=2)

# Label to display the decrypted message
decrypted_message_label = tk.Label(frame, text="Decrypted Message: ")
decrypted_message_label.grid(row=9, columnspan=2)

# Label to display Bob's digital signature
bob_signature_label = tk.Label(frame, text="Bob's Digital Signature: ")
bob_signature_label.grid(row=10, columnspan=2)

# Label to display the verification result
bob_verify_label = tk.Label(frame, text="Bob's Verification: ")
bob_verify_label.grid(row=11, columnspan=2)

# Function to handle interaction between Alice and Bob
def alice_bob_interaction():
    message = entry_message.get()
    # Alice signs the message
    alice_signature = alice_signing(d, n, message)
    bob_signature_label.config(text=f"Bob's Digital Signature: {alice_signature}")
    # Bob verifies the message
    verification_result = bob_verify(e, n, alice_signature, message)
    verification_text = "Yes" if verification_result else "No"
    bob_verify_label.config(text=f"Bob's Verification: {verification_text}")

# Button to initiate Alice-Bob interaction
alice_bob_button = tk.Button(frame, text="Alice-Bob Interaction", command=alice_bob_interaction)
alice_bob_button.grid(row=12, columnspan=2)

# Label to display result messages
result_label = tk.Label(frame, text="")
result_label.grid(row=13, columnspan=2)

# Run the Tkinter main loop
root.mainloop()
