import secrets
import math
import os
from SHA256 import sha256  

class RSAOAEP:
    """
        Reference:
        - PKCS #1 v2.2:  PKCS #1: RSA Cryptography Specifications Version 2.2 (Section 7.1)
        - https://en.wikipedia.org/wiki/Optimal_asymmetric_encryption_padding
        - https://datatracker.ietf.org/doc/html/rfc8017#section-7.1
    """
    
    def is_prime(n: int, a=0, round=40) -> bool:
        """
        Miller-Rabin primality test (simplified version)
        
        Args:
            n: Number to check for primality
            a: Base
            k: Number of test rounds (higher = more accurate)
        
        Returns:
            True if n is probably prime, False if definitely composite
        
        Reference:
            - https://stackoverflow.com/questions/6325576/how-many-iterations-of-rabin-miller-should-i-use-for-cryptographic-safe-primes
            - https://www.ccbp.in/blog/articles/python-program-to-check-prime-number
        """
        # Handle simple cases
        if n <= 1:
            return False
        if n <= 3:
            return True
        if n % 2 == 0:
            return False

        # Write n-1 == 2^k * q
        k, q = 0, n - 1
        while q % 2 == 0:
            k += 1
            q //= 2

        # 1 < a < n-1
        if (a == 0):
            a = secrets.randbelow(n - 3) + 2
        x = pow(a, q, n)
        
        if x == 1:
            return True
        
        for _ in range(k - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                return True
        
        return False

    def generate_large_prime(bits: int) -> int:
        """
        Generate a large prime number with specified number of bits
        
        Reference:
            - https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test
        """
        
        while True:
            # Step 1: Pick a random odd integer in [2^(bits-1), 2^bits - 1]
            min_num = 2 ** (bits - 1)  # Smallest number with 'bits' bits
            max_num = (2 ** bits) - 1  # Largest number with 'bits' bits

            n = secrets.randbelow(max_num - min_num + 1) + min_num

            if n % 2 == 0:  # If even, make it odd
                n += 1
            
            # Step 2: Miller-Rabin primality test
            if RSAOAEP.is_prime(n):
                return n

    def generate_rsa_keys(key_size: int) -> tuple[int, int, int]:
        '''
        Generate RSA key pair (n, e, d) with built-in modular inverse calculation.
        Key size // 2 to ensure the key n = key size because x bit of number multiply by y bit of number = x * y bit of number.
        
        Args:
            key_size = bits
            p, q, e = customizable
        
        Returns:
            n, e, d. Public = {e, n}, Private = {d, n}

        Reference:
            - https://crypto.stackexchange.com/questions/3110/impacts-of-not-using-rsa-exponent-of-65537
        '''
        p = RSAOAEP.generate_large_prime(key_size // 2)
        q = RSAOAEP.generate_large_prime(key_size // 2)

        while p == q:
            q = RSAOAEP.generate_large_prime(key_size // 2)
        
        n = p * q
        phi = (p - 1) * (q - 1)
        
        e = 65537
        while math.gcd(e, phi) != 1:
            e += 2
        
        d = pow(e, -1, phi)
        
        return n, e, d
    
    # ----- OAEP Padding Functions -----
    
    def mgf1(seed: bytes, length: int) -> bytes:
        """
        Mask Generation Function (MGF1) as defined in PKCS#1 v2.2
        
        Args:
            seed: Seed to generate mask from
            length: Length of the mask to generate
            
        Returns:
            Byte string of requested length
            
        Reference:
            - https://en.wikipedia.org/wiki/Mask_generation_function
            - PKCS #1 v2.1: RSA Cryptography Standard
        """
        hLen = 32  # SHA-256 digest size hardcoded to 32 bytes
        mask = b""
        counter = 0
        
        while len(mask) < length:
            C = counter.to_bytes(4, 'big')
            
            mask += sha256(seed + C) 
            counter += 1
        
        # Return only the requested length
        return mask[:length]
    
    def oaep_pad(message: bytes, key_size: int, label=b"") -> bytes:
        """
        Apply OAEP padding to a message
        
        Args:
            message: Message to pad (bytes)
            key_size: Size of RSA modulus in bytes
            label: Optional label (bytes)
            
        Returns:
            OAEP padded message as bytes
        """
        hLen = 32 
        
        mLen = len(message)
        maxLen = key_size - 2 * hLen - 2
        
        if mLen > maxLen:
            raise ValueError(f"Message too long for OAEP padding with this key size: {mLen} > {maxLen}")
        
        lHash = sha256(label)  
        PS = b'\0' * (key_size - mLen - 2 * hLen - 2)
        DB = lHash + PS + b'\1' + message
        
        # Generate random seed
        seed = os.urandom(hLen)
        
        # Apply MGF to seed to get mask for DB
        dbMask = RSAOAEP.mgf1(seed, key_size - hLen - 1)
        maskedDB = bytes(a ^ b for a, b in zip(DB, dbMask))
        
        # Apply MGF to masked DB to get mask for seed
        seedMask = RSAOAEP.mgf1(maskedDB, hLen)
        maskedSeed = bytes(a ^ b for a, b in zip(seed, seedMask))
        
        return b'\0' + maskedSeed + maskedDB
    
    def oaep_unpad(padded_message: bytes, key_size: int, label=b"") -> bytes:
        """
        Remove OAEP padding from a message
        
        Args:
            padded_message: OAEP padded message (bytes)
            key_size: Size of RSA modulus in bytes
            label: Optional label (bytes)
            
        Returns:
            Original message as bytes
        """
        hLen = 32  
        
        # Check minimum length and first byte
        if len(padded_message) != key_size or padded_message[0] != 0:
            raise ValueError("Invalid OAEP padding format")
        
        # Separate parts of the padded message
        maskedSeed = padded_message[1:1+hLen]
        maskedDB = padded_message[1+hLen:]
        
        # Apply MGF to masked DB to recover seed mask
        seedMask = RSAOAEP.mgf1(maskedDB, hLen)
        seed = bytes(a ^ b for a, b in zip(maskedSeed, seedMask))
        
        # Apply MGF to seed to recover DB mask
        dbMask = RSAOAEP.mgf1(seed, key_size - hLen - 1)
        DB = bytes(a ^ b for a, b in zip(maskedDB, dbMask))
        
        lHash = sha256(label) 
        if DB[:hLen] != lHash:
            raise ValueError("Invalid label in OAEP unpadding")
        
        # Find message separator (0x01)
        separator_index = hLen
        while separator_index < len(DB):
            if DB[separator_index] == 0:
                separator_index += 1
                continue
            if DB[separator_index] == 1:
                break
            raise ValueError("Invalid OAEP padding format")
        
        # Check if we found the separator
        if separator_index == len(DB):
            raise ValueError("Invalid OAEP padding format: separator not found")
        
        return DB[separator_index+1:]
    
    # ----- RSA-OAEP Encryption/Decryption Functions -----
    
    def encrypt(message: bytes, public_key: tuple[int, int], label=b"") -> bytes:
        """
        Encrypt a message using RSA-OAEP
        
        Args:
            message: Message to encrypt (bytes)
            public_key: Tuple (e, n) - RSA public key
            label: Optional label for OAEP (bytes)
            
        Returns:
            RSA-OAEP encrypted message as bytes
        """
        e, n = public_key
        
        key_size = (n.bit_length() + 7) // 8
        padded_message = RSAOAEP.oaep_pad(message, key_size, label)
        
        m_int = int.from_bytes(padded_message, 'big')
        c_int = pow(m_int, e, n)
        
        return int.to_bytes(c_int, key_size, 'big')
    
    def decrypt(ciphertext: bytes, private_key: tuple[int, int], label=b"") -> bytes:
        """
        Decrypt a message using RSA-OAEP
        
        Args:
            ciphertext: Encrypted message (bytes)
            private_key: Tuple (d, n) - RSA private key
            label: Optional label for OAEP (bytes)
            
        Returns:
            Decrypted message as bytes
        """
        d, n = private_key
        
        key_size = (n.bit_length() + 7) // 8
        
        c_int = int.from_bytes(ciphertext, 'big')
        m_int = pow(c_int, d, n)
        
        padded_message = int.to_bytes(m_int, key_size, 'big')
        
        return RSAOAEP.oaep_unpad(padded_message, key_size, label)
    
    # ----- File Operations -----
    
    def load_key_from_file(filename: str) -> tuple[int, int]:
        """
        Load a key from a file
        
        Args:
            filename: Path to the key file
            
        Returns:
            Tuple (e or d, n) for public or private key
        """
        e_or_d = None
        n = None
        
        with open(filename, 'r') as f:
            for line in f:
                if line.startswith('n='):
                    n = int(line.split('=')[1].strip(), 16)
                elif line.startswith('e='):
                    e_or_d = int(line.split('=')[1].strip(), 16)
                elif line.startswith('d='):
                    e_or_d = int(line.split('=')[1].strip(), 16)
        
        if e_or_d is None or n is None:
            raise ValueError("Invalid key file format")
        
        return (e_or_d, n)
    
    def encrypt_file(input_file: str, output_file: str, public_key_file: str):
        """
        Encrypt a file using RSA-OAEP
        
        Args:
            input_file: Path to the file to encrypt
            output_file: Path to save the encrypted file
            public_key_file: Path to the public key file
        """
        public_key = RSAOAEP.load_key_from_file(public_key_file)
        
        # Calculate maximum data size per block (in bytes)
        n = public_key[1]
        key_size_bits = n.bit_length()
        key_size_bytes = (key_size_bits + 7) // 8
        
        # Maximum data size is: key_size - 2*hash_len - 2
        # For SHA-256 (32 bytes), with 2048-bit key (256 bytes):
        # max_size = 256 - 2*32 - 2 = 190 bytes
        max_block_size = key_size_bytes - 2*32 - 2
        
        with open(input_file, 'rb') as f_in:
            plaintext = f_in.read()
        
        with open(output_file, 'wb') as f_out:
            for i in range(0, len(plaintext), max_block_size):
                chunk = plaintext[i:i+max_block_size]
                
                encrypted_chunk = RSAOAEP.encrypt(chunk, public_key)
                
                # Write the encrypted chunk size and data
                chunk_size = len(encrypted_chunk)
                f_out.write(chunk_size.to_bytes(2, 'big'))
                f_out.write(encrypted_chunk)
    
    def decrypt_file(input_file: str, output_file: str, private_key_file: str):
        """
        Decrypt a file using RSA-OAEP
        
        Args:
            input_file: Path to the file to decrypt
            output_file: Path to save the decrypted file
            private_key_file: Path to the private key file
        """
        private_key = RSAOAEP.load_key_from_file(private_key_file)
        
        n = private_key[1]
        key_size_bytes = (n.bit_length() + 7) // 8
        
        with open(input_file, 'rb') as f_in, open(output_file, 'wb') as f_out:
            while True:
                size_bytes = f_in.read(2)
                if not size_bytes:
                    break  # End of file
                
                chunk_size = int.from_bytes(size_bytes, 'big')
                
                encrypted_chunk = f_in.read(chunk_size)
                if len(encrypted_chunk) != chunk_size:
                    raise ValueError("File format error: incomplete chunk")
                
                # Decrypt the chunk
                decrypted_chunk = RSAOAEP.decrypt(encrypted_chunk, private_key)
                f_out.write(decrypted_chunk)