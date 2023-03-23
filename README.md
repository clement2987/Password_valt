# Password_valt
A very basic password manager that makes it easy to save and retrieve said passwords

Password Valt
Password Valt is a simple password manager that allows users to store and retrieve passwords for different services. The program uses encryption to keep passwords secure and requires users to enter a master password to access their password list.

Getting Started
To use Password Valt, simply download the program files and run the main.py file. The program will prompt you to create a master password if it is your first time using the program. Once you have created a master password, you can sign in to access your password list.

Features
Store and retrieve passwords for different services
Encrypt passwords for added security
Require a master password to access password list
Search for passwords by service name
Edit and delete saved passwords
How It Works
When a user enters a password, the program encrypts it using a custom encryption algorithm. The encrypted password is then stored in a CSV file on the user's computer. To access their password list, the user must enter their master password, which is also encrypted and stored in a separate file.

Dependencies
The program requires the following Python libraries:

csv
os
ctypes
tkinter
werkzeug
Known Issues
There are currently no known issues with the program.
Contributing
If you would like to contribute to the development of Password Valt, please fork the repository and submit a pull request.
