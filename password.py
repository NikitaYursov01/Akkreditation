import getpass
import hashlib
import json
import os
import re
import sys
from difflib import SequenceMatcher
from itertools import dropwhile
from pathlib import Path

from cryptography.fernet import Fernet  # Resolve import for Fernet


# Rest of the code remains the same

class Password:
    # empty constructor
    def __init__(self):
        pass

    # add method - given two numbers, return the addition
    def validate_by_regexp(self, password):
        """Валидация пароля по регулярному выражению."""
        # Проверяет наличие символов в обоих регистрах,
        # чисел, спецсимволов и минимальную длину 8 символов
        pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$'
        if re.match(pattern, password) is None:
            return "Password has incorrecr format."

    def validate_by_common_list(self, password):
        """Валидация пароля по списку самых распространенных паролей."""
        common_passwords_filepath = Path(__file__).parent.resolve() / 'pwnedpasswords-v2-top20k.txt'
        max_similarity = 0.7

        with open(common_passwords_filepath) as f:
            for line in dropwhile(lambda x: x.startswith('#'), f):
                common = line.strip().split(':')[-1]
                diff = SequenceMatcher(a=password.lower(), b=common)
                if diff.ratio() >= max_similarity:
                    return "Do not use so common password."

    def validate_by_similarity(self, password, *other_fields):
        """Проверяем, что пароль не слишком похож на другие поля пользователя."""
        max_similarity = 0.75

        for field in other_fields:
            field_parts = re.split(r'\W+', field) + [field]
            for part in field_parts:
                if SequenceMatcher(a=password.lower(), b=part.lower()).ratio() >= max_similarity:
                    return "Password is too similar on other user field."

    # Function for Hashing the Master Password.
    def hash_password(self, password):
        sha256 = hashlib.sha256()
        sha256.update(password.encode())
        return sha256.hexdigest()

    # Generate a secret key. This should be done only once as you'll see.
    def generate_key(self):
        return Fernet.generate_key()

    # Initialize Fernet cipher with the provided key.
    def initialize_cipher(self, key):
        return Fernet(key)

    # Function to encrypt a  password.
    def encrypt_password(self, cipher, password):
        return cipher.encrypt(password.encode()).decode()

    # Function to decrypt a  password.
    def decrypt_password(self, cipher, encrypted_password):
        return cipher.decrypt(encrypted_password.encode()).decode()

    # Function to register you.
    def register(self, username, master_password):
        # Encrypt the master password before storing it
        hashed_master_password = self.hash_password(master_password)
        user_data = {'username': username, 'master_password': hashed_master_password}
        file_name = 'user_data.json'
        if os.path.exists(file_name) and os.path.getsize(file_name) == 0:
            with open(file_name, 'w') as file:
                json.dump(user_data, file)
                print("\n[+] Registration complete!!\n")
        else:
            with open(file_name, 'x') as file:
                json.dump(user_data, file)
                print("\n[+] Registration complete!!\n")

    # Function to log you in.
    def login(self, username, entered_password):
        try:
            with open('user_data.json', 'r') as file:
                user_data = json.load(file)
            stored_password_hash = user_data.get('master_password')
            entered_password_hash = self.hash_password(entered_password)
            if entered_password_hash == stored_password_hash and username == user_data.get('username'):
                print("\n[+] Login Successful..\n")
            else:
                print("\n[-] Invalid Login credentials. Please use the credentials you used to register.\n")
                sys.exit()
        except Exception:
            print("\n[-] You have not registered. Please do that.\n")
            sys.exit()

    # Function to view saved websites.
    def view_websites(self):
        try:
            with open('passwords.json', 'r') as data:
                view = json.load(data)
                print("\nWebsites you saved...\n")
                for x in view:
                    print(x['website'])
                print('\n')
        except FileNotFoundError:
            print("\n[-] You have not saved any passwords!\n")

    # Function to add (save password).
    def add_password(self, website, password):
        # Check if passwords.json exists
        if not os.path.exists('passwords.json'):
            # If passwords.json doesn't exist, initialize it with an empty list
            data = []
        else:
            # Load existing data from passwords.json
            try:
                with open('passwords.json', 'r') as file:
                    data = json.load(file)
            except json.JSONDecodeError:
                # Handle the case where passwords.json is empty or invalid JSON.
                data = []
        # Encrypt the password
        encrypted_password = self.encrypt_password(self.get_key(), password)
        # Create a dictionary to store the website and password
        password_entry = {'website': website, 'password': encrypted_password}
        data.append(password_entry)
        # Save the updated list back to passwords.json
        with open('passwords.json', 'w') as file:
            json.dump(data, file, indent=4)

    # Function to retrieve a saved password.
    def get_password(self, website):
        # Check if passwords.json exists
        if not os.path.exists('passwords.json'):
            return None
        # Load existing data from passwords.json
        try:
            with open('passwords.json', 'r') as file:
                data = json.load(file)
        except json.JSONDecodeError:
            data = []
        # Loop through all the websites and check if the requested website exists.
        for entry in data:
            if entry['website'] == website:
                # Decrypt and return the password
                decrypted_password = self.decrypt_password(self.get_key(), entry['password'])
                return decrypted_password
        return None

    def get_key(self):
        # Load or generate the encryption key.
        key_filename = 'encryption_key.key'
        if os.path.exists(key_filename):
            with open(key_filename, 'rb') as key_file:
                key = key_file.read()
        else:
            key = self.generate_key()
            with open(key_filename, 'wb') as key_file:
                key_file.write(key)

        cipher = self.initialize_cipher(key)
        return cipher



