import getpass
import hashlib
import json
import os
import re
import sys
from difflib import SequenceMatcher
from itertools import dropwhile
from pathlib import Path

import password
from password import Password

p = Password()
# Infinite loop to keep the program running until the user chooses to quit.
while True:
    print("1. Register")  # Ushka@666
    print("2. Login")
    print("3. Quit")
    choice = input("Enter your choice: ")
    if choice == '1':  # If a user wants to register
        file = 'user_data.json'
        if os.path.exists(file) and os.path.getsize(file) != 0:
            print("\n[-] Master user already exists!!")
            sys.exit()
        else:
            username = input("Enter your username: ")
            master_password = getpass.getpass("Enter your master password: ")
            while True:
                if (p.validate_by_regexp(master_password) == "Password has incorrecr format."):
                    print("Password has incorrecr format.")
                    master_password = getpass.getpass("Enter your master password: ")
                elif (p.validate_by_common_list(master_password) == "Do not use so common password."):
                    print("Do not use so common password.")
                    master_password = getpass.getpass("Enter your master password: ")
                elif (p.validate_by_similarity(master_password,
                                               username) == "Password is too similar on other user field."):
                    print("Password is too similar on other user field.")
                    master_password = getpass.getpass("Enter your master password: ")
                else:
                    p.register(username, master_password)
                    break
    elif choice == '2':  # If a User wants to log in
        file = 'user_data.json'
        if os.path.exists(file):
            username = input("Enter your username: ")
            master_password = getpass.getpass("Enter your master password: ")
            p.login(username, master_password)
        else:
            print("\n[-] You have not registered. Please do that.\n")
            sys.exit()
        # Various options after a successful Login.
        while True:
            print("1. Add Password")
            print("2. Get Password")
            print("3. View Saved websites")
            print("4. Quit")
            password_choice = input("Enter your choice: ")
            if password_choice == '1':  # If a user wants to add a password
                website = input("Enter website: ")
                password = getpass.getpass("Enter password: ")
                # Encrypt and add the password
                p.add_password(website, password)
                print("\n[+] Password added!\n")
            elif password_choice == '2':  # If a User wants to retrieve a password
                website = input("Enter website: ")
                decrypted_password = p.get_password(website)
                if website and decrypted_password:
                    # Copy password to clipboard for convenience
                    # pyperclip.copy(decrypted_password)
                    print(f"\n[+] Password for {website}: {decrypted_password}\n")
                else:
                    print("\n[-] Password not found! Did you save the password?"
                          "\n[-] Use option 3 to see the websites you saved.\n")
            elif password_choice == '3':  # If a user wants to view saved websites
                p.view_websites()
            elif password_choice == '4':  # If a user wants to quit the password manager
                break
    elif choice == '3':  # If a user wants to quit the program
        break
