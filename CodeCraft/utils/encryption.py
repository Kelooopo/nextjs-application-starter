import os
import base64
from cryptography.fernet import Fernet

class EncryptionManager:
    def __init__(self, key_file='encryption.key'):
        self.key_file = key_file
        self.cipher = self._load_or_generate_key()
    
    def _load_or_generate_key(self):
        """Load existing key or generate a new one"""
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as f:
                key = f.read()
        else:
            key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(key)
        
        return Fernet(key)
    
    def encrypt(self, data):
        """Encrypt data and return base64 encoded string"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        encrypted_data = self.cipher.encrypt(data)
        return base64.b64encode(encrypted_data).decode('utf-8')
    
    def decrypt(self, encrypted_data):
        """Decrypt base64 encoded string and return original data"""
        try:
            encrypted_bytes = base64.b64decode(encrypted_data.encode('utf-8'))
            decrypted_data = self.cipher.decrypt(encrypted_bytes)
            return decrypted_data.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
    
    def encrypt_file(self, file_path, output_path=None):
        """Encrypt a file"""
        if output_path is None:
            output_path = file_path + '.encrypted'
        
        with open(file_path, 'rb') as f:
            file_data = f.read()
        
        encrypted_data = self.cipher.encrypt(file_data)
        
        with open(output_path, 'wb') as f:
            f.write(encrypted_data)
        
        return output_path
    
    def decrypt_file(self, encrypted_file_path, output_path=None):
        """Decrypt a file"""
        if output_path is None:
            output_path = encrypted_file_path.replace('.encrypted', '')
        
        with open(encrypted_file_path, 'rb') as f:
            encrypted_data = f.read()
        
        decrypted_data = self.cipher.decrypt(encrypted_data)
        
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)
        
        return output_path
    
    def generate_new_key(self):
        """Generate a new encryption key (warning: this will invalidate existing encrypted data)"""
        key = Fernet.generate_key()
        with open(self.key_file, 'wb') as f:
            f.write(key)
        
        self.cipher = Fernet(key)
        return key
