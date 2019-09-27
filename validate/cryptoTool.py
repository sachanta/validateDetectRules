from fileCrypto import FileCrypto

banner = r'''

Enter 'E' to Encrypt a File
Enter 'D' to Decrypt a File
Enter 'Q' to Quit
'''
print(banner)


def quit():
    alpha = input("Are You Sure?[yes/no] - ").lower()
    if alpha == "yes":
        exit()
    if alpha == "no":
        print(banner)
        choice()


def choice():
    try:
        selection = input("tool:- ").upper()
        if selection == "E":

            input_file = input("Enter name of the file to encrypt:- ")
            usr_key = input("Please enter a key to use as your encryption key:- ")
            output_file = input("Enter name of the encrypted file:- ")

            fc1 = FileCrypto(input_file, output_file, usr_key)
            fc1.encrypt_file()

        if selection == "D":

            input_file = input("Enter name of the file to decrypt:- ")
            usr_key = input("Please enter the key used to encrypt the file:- ")
            output_file = input("Enter name of the decrypted file:- ")

            fc1 = FileCrypto(input_file, output_file, usr_key)
            fc1.decrypt_file()

        if selection == 'Q':
            quit()

    except KeyboardInterrupt:
        print("Programme Interrupted")
        exit()


choice()