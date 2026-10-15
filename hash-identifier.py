import pandas as pd
from tabulate import tabulate
import re

text = input("Enter the hash to identify: ")
characters = len(text) # Length of hash in characters

def identify_hash(hash_string):
    match hash_string:
    # ----------------------------------------------------------------------------------------------------------   
        # Bcrypt hash types
        case _ if hash_string.startswith("$2a$") or hash_string.startswith("$2x$"):
            return "bcrypt (old version)"
        case _ if hash_string.startswith("$2y$") or hash_string.startswith("$2b$") and characters == 60:
            return "bcrypt"
        case _ if hash_string.startswith("$bcrypt$"):
            return "bcrypt (new version)"
    # ----------------------------------------------------------------------------------------------------------   
        # Argon2 hash types
        case _ if hash_string.startswith("$argon2id$"):
            return "Argon2id"
        case _ if hash_string.startswith("$argon2i$"):
            return "Argon2i"
        case _ if hash_string.startswith("$argon2d$"):
            return "Argon2d"
        case _ if hash_string.startswith("$argon2"):
            return "Argon2"
    # ----------------------------------------------------------------------------------------------------------   
        # SHA hash types
        case _ if characters == 40 and all(c in "0123456789abcdefABCDEF" for c in hash_string):
            return "SHA-1"
        case _ if characters == 64 and all(c in "0123456789abcdefABCDEF" for c in hash_string):
            return "SHA-256"
        case _ if characters == 128 and all(c in "0123456789abcdefABCDEF" for c in hash_string):
            return "SHA-512"        
        case _ if hash_string.startswith("$5$"):
            return "SHA-256 (Unix)"
        case _ if hash_string.startswith("$6$"):
            return "SHA-512 (Unix)"
        case _ if hash_string.startswith("$S$"):
            return "SHA-512 (WordPress)"
    # ----------------------------------------------------------------------------------------------------------   
        # MD5 hash types
        case _ if characters == 32 and all(c in "0123456789abcdefABCDEF" for c in hash_string):
            return "MD5"
        case _ if hash_string.startswith("$1$"):
            return "MD5 (Unix)"
        case _ if hash_string.startswith("$apr1$"):
            return "Apache MD5"
    # ----------------------------------------------------------------------------------------------------------   
        # PBKDF2 hash types
        case _ if hash_string.startswith("$pbkdf2$"):
            return "PBKDF2"
        case _ if hash_string.startswith("$pbkdf2-sha256$"):
            return "PBKDF2-SHA256"
        case _ if hash_string.startswith("$pbkdf2-sha512$"):
            return "PBKDF2-SHA512"
    # ----------------------------------------------------------------------------------------------------------   
        # scrypt hash types
        case _ if hash_string.startswith("$scrypt$"):
            return "scrypt"
    # ----------------------------------------------------------------------------------------------------------   
        # Base hash types
        case _ if hash_string.endswith("==") or hash_string.endswith("="):
            return "Base64"
    # ----------------------------------------------------------------------------------------------------------   
        # Misc hash types
        case _ if hash_string.startswith("$P$") or hash_string.startswith("$H$"):
            return "PHPass"
        case _:
            return "Unknown"
    # ----------------------------------------------------------------------------------------------------------   

def extract_salt(hash_string, hash_type):
    if "bcrypt" in hash_type and len(hash_string) >= 60:
        return hash_string[7:29]

    elif hash_type.startswith("Argon2"):
        parts = hash_string.split("$")
        return parts[4] if len(parts) >= 5 else "Embedded"

    elif "Unix" in hash_type:
        parts = hash_string.split("$")
        return parts[2] if len(parts) >= 3 else "Embedded"

    return "None Detected"

identified_type = identify_hash(text)

data = {
    "Hash": [text],
    "Type": [identified_type],
    "Salt": [extract_salt(text, identified_type)],
}

table = pd.DataFrame(data)

print(tabulate(table, headers='keys', tablefmt='grid', showindex=False))