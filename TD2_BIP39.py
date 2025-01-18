import os
import hashlib
import hmac
import binascii
from hashlib import pbkdf2_hmac

class WalletGenerator:
    def __init__(self, wordlist_path='wordlist.txt'):
        """Initialize the wallet generator with the path to the word list."""
        self.wordlist = self._load_wordlist(wordlist_path)
        
    def _load_wordlist(self, wordlist_path):
        """Load BIP-39 word list from file."""
        try:
            with open(wordlist_path, 'r') as file:
                content = file.read()
                # Find list between parentheses
                start = content.find('(')
                end = content.rfind(')')
                if start == -1 or end == -1:
                    raise ValueError("Invalid file format")
                words_list = content[start:end+1]
                # Convert tuple to list
                return list(eval(words_list))
        except Exception as e:
            print(f"Error loading word list: {e}")
            return []

    def generate_entropy(self, bits=128):
        """Generate random entropy of specified bit length."""
        return os.urandom(bits // 8)

    def calculate_checksum(self, entropy):
        """Calculate entropy checksum."""
        entropy_hash = hashlib.sha256(entropy).digest()
        checksum_length = len(entropy) * 8 // 32  # ENT / 32
        return format(entropy_hash[0], '08b')[:checksum_length]

    def create_binary_seed(self, entropy):
        """Create complete binary string (entropy + checksum)."""
        entropy_bits = bin(int.from_bytes(entropy, 'big'))[2:].zfill(len(entropy) * 8)
        checksum = self.calculate_checksum(entropy)
        return entropy_bits + checksum

    def split_binary_to_11bits(self, binary_string):
        """Split binary string into 11-bit chunks."""
        return [binary_string[i:i+11] for i in range(0, len(binary_string), 11)]

    def get_mnemonic_words(self, binary_seed):
        """Convert binary string to mnemonic words."""
        if not self.wordlist:
            raise ValueError("Word list was not loaded correctly")
            
        chunks = self.split_binary_to_11bits(binary_seed)
        word_indexes = [int(chunk, 2) for chunk in chunks]
        
        if any(index >= len(self.wordlist) for index in word_indexes):
            raise ValueError("Index out of range for word list")
            
        return [self.wordlist[index] for index in word_indexes]

    def create_seed_from_mnemonic(self, mnemonic, passphrase=""):
        """Create seed from mnemonic phrase."""
        mnemonic_bytes = mnemonic.encode('utf-8')
        salt = ("mnemonic" + passphrase).encode('utf-8')
        return pbkdf2_hmac('sha512', mnemonic_bytes, salt, 2048)

    def derive_master_keys(self, seed):
        """Derive master private key and chain code from seed."""
        hmac_obj = hmac.new(b"Bitcoin seed", seed, hashlib.sha512)
        master_key = hmac_obj.digest()
        return master_key[:32], master_key[32:]  # private_key, chain_code

def main():
    try:
        # Initialize generator
        wallet_gen = WalletGenerator()
        
        # Verify word list is loaded
        if not wallet_gen.wordlist:
            print("Error: Word list could not be loaded.")
            return
        
        # Generate entropy
        entropy = wallet_gen.generate_entropy()
        print(f"\n1. Generated entropy (hex): {entropy.hex()}")
        
        # Create binary string (entropy + checksum)
        binary_seed = wallet_gen.create_binary_seed(entropy)
        print(f"\n2. Complete binary string: {binary_seed}")
        
        # Split into 11-bit chunks
        chunks = wallet_gen.split_binary_to_11bits(binary_seed)
        print("\n2b. 11-bit chunks:")
        for i, chunk in enumerate(chunks, 1):
            print(f"   Chunk {i}: {chunk} (decimal: {int(chunk, 2)})")
        
        # Generate mnemonic words
        mnemonic_words = wallet_gen.get_mnemonic_words(binary_seed)
        mnemonic_phrase = " ".join(mnemonic_words)
        print(f"\n3. Mnemonic phrase: {mnemonic_phrase}")
        
        # Create seed
        seed = wallet_gen.create_seed_from_mnemonic(mnemonic_phrase)
        print(f"\n4. Seed (hex): {seed.hex()}")
        
        # Derive master keys
        master_private_key, master_chain_code = wallet_gen.derive_master_keys(seed)
        print(f"\n5. Master Private Key (hex): {master_private_key.hex()}")
        print(f"6. Master Chain Code (hex): {master_chain_code.hex()}")
        
    except Exception as e:
        print(f"\nAn error occurred: {str(e)}")

if __name__ == "__main__":
    main()
