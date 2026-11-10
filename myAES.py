"""
myAES.py
Program Description: Project #3: File Encryption and Statistical Analysis of both plaintext and ciphertext files 
Program Usage: python3 myAES.py 

Group Members: Ian Holbrook & Cole Faulk
Date: 11/10/2026
Course: Computer Security (CSCI 3250)
"""

#needed libraries for the program
import os as os
import binascii
import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

#create a dictionary to store the file types and their corresponding files
files ={}
for filetype in os.listdir('mydata'):
    files[filetype] = os.listdir(f'mydata/{filetype}')

#iterate through the dictionary and print the first 32 bytes of each file in hex format
for filetype in files:
    for filename in files[filetype]:
        with open(f'mydata/{filetype}/{filename}', 'rb') as f:
            chunck = f.read(32)
            print(f'{binascii.hexlify(chunck)} -- {filename}')


def get_file_stats(filename):
    """
    This function will read a file and return both the mean and standard deviation of the byte values.

    Args:
        filename (str): the path to the file to be analyzed
    
    Returns:
        tuple: the mean and standard deviation of the byte values
        """
    
    with open(filename, 'rb') as f:
        file_bytes = bytearray(f.read())
    data = np.frombuffer(file_bytes, np.uint8)
    return(np.mean(data), np.std(data))


def print_file_stats():
    """
    This function prints the mean and standard deviation of the byte values for each file in the 'mydata' directory.
    """

    print("\nFile Stats: ")
    for filetype in files:
        for filename in files[filetype]:
            mean, std = get_file_stats(f'mydata/{filetype}/{filename}')
            print(f'{filename}: Mean={mean:.4f}, Std={std:.4f}')


def encrypt_and_stats(filename):
    """
    This function will encrypt a file using AES encryption and return both the mean and standard deviation of the encrypted byte values.
    
    Args:
        filename (str): the path to the file to be encrypted

    Returns:
        tuple: the mean and standard deviation of the encrypted byte values
        
        """
    
    with open(filename, 'rb') as f:
        file_bytes = bytearray(f.read())
    key = os.urandom(32)
    iv = os.urandom(32)
    aes_cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = aes_cipher.encryptor()
    ciphertext = encryptor.update(file_bytes) + encryptor.finalize()
    data = np.frombuffer(ciphertext, np.uint8)
    return(np.mean(data), np.std(data))


def print_encrypted_stats():
    """
    This function prints the mean and standard deviation of the byte values for each file in the 'mydata' directory after encrypting them using AES encryption.
    
        """
    
    print("\nEncrypted File Stats: ")
    for filetype in files:
        for filename in files[filetype]:
            mean, std = encrypt_and_stats(f'mydata/{filetype}/{filename}')
            print(f'{filename}: Mean={mean:.4f}, Std={std:.4f}')

print_file_stats()
print_encrypted_stats()