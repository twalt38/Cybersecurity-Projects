text = input("Enter the hash to identify: ")
characters = len(text) # Length of hash in characters

def identify_hash(hash_string):
    match hash_string:
    # Character Cases
        case _ if characters == 32:
            return "MD5"
        case _ if characters == 40:
            return "SHA-1"
        case _ if characters == 64:
            return "SHA-256"
        case _ if characters == 128:
            return "SHA-512"
    # Pattern Cases
        case _ if hash_string.startswith("$2y$") or hash_string.startswith("$2b$"):
            return "bcrypt"
        case _ if hash_string.startswith("$argon2"):
            return "Argon2"
        case _ if hash_string.startswith("$5$"):
            return "SHA-256 (Unix)"
        case _ if hash_string.startswith("$6$"):
            return "SHA-512 (Unix)"
        case _ if hash_string.startswith("$1$"):
            return "MD5 (Unix)"
        case _ if hash_string.startswith("$apr1$"):
            return "Apache MD5"
        case _ if hash_string.startswith("$P$") or hash_string.startswith("$H$"):
            return "PHPass"
        case _ if hash_string.startswith("$S$"):
            return "SHA-512 (WordPress)"
        case _ if hash_string.startswith("$2a$") or hash_string.startswith("$2x$"):
            return "bcrypt (old version)"
        case _ if hash_string.startswith("$pbkdf2-sha256$"):
            return "PBKDF2-SHA256"
        case _ if hash_string.startswith("$pbkdf2-sha512$"):
            return "PBKDF2-SHA512"
        case _ if hash_string.startswith("$scrypt$"):
            return "scrypt"
        case _ if hash_string.startswith("$argon2i$"):
            return "Argon2i"
        case _ if hash_string.startswith("$argon2d$"):
            return "Argon2d"
        case _ if hash_string.startswith("$argon2id$"):
            return "Argon2id"
        case _ if hash_string.startswith("$pbkdf2$"):
            return "PBKDF2"
        case _ if hash_string.startswith("$bcrypt$"):
            return "bcrypt (new version)"
        case _ if hash_string.endswith("==") or hash_string.endswith("="):
            return "Base64"
        case _:
            return "Unknown"

print(f"The hash type is: {identify_hash(text)}")