# CRYPTO TOOL by alef 
This is a very simple tool to cipher/decipher any file or message of your choice, using a password you will provide.

Based on: https://nitratine.net/blog/post/encryption-and-decryption-in-python/ (@brentvollebregt)
     and: https://cryptography.io/en/latest/hazmat/primitives/cryptographic-hashes/
     (I replaced salt random number method, which has to be stored, by a fully password-based method, using a hash)
     
Basically, it:

- Asks for a password (which will never be stored)
- Obtains a hash from the password (SHA-256)
- Adds a random timestamp number to the data to be encrypted (same data will never produce same result)
- Uses the hash as a key to encrypt/decrypt data (using Fernet)
- Removes random number from decrypted data (original data remains unaltered)
- Returns encrypted/decrypted data on console, file or QR
- Optionally, it may generate a key from a password, but it will not store or manage keys in any safe way 

## Usage

     python3 crypto.py ARGUMENT [OPTIONS]

     ARGUMENTS:
          -e    Encrypt data
          -d    Decrypt data
          -g    Generate key

     OPTIONS:
          -i    Input file to Encrypt/Decrypt
          -iq   Input file in QR format (.png only)
          -m    Message to Encrypt/Decrypt
          -o    Output file to write encrypted/decrypted data or key
          -oq   Output file in QR format (.png)
          -p    Password to Encrypt/Decrypt data (use quotation marks if required)
          -k    Key to Encrypt/Decrypt data

#### SUGGESTION:
If you intend to compress the file, first compress it, then cipher it (will reduce size and time)

#### WARNING:
Will only work running it from command-line

#### WARNING:
Fernet is ideal for encrypting data that easily fits in memory, so I developed a "chunky" method for files!!!

#### SUPERWARNING:
Do not interchange or store keys. Just interchange passwords, by a secure method (e.g. mouth-to-ear)

#### SUPERSUPERWARNING:
Not sure how secure it is!!! Do not use it to cipher, let's say, your more precious secrets...

#### UPDATE:
Recently discovered 'gpg' command (native on Ubuntu) which is able to do a lot more (and better, I guess)

        Encrypt: gpg --symmetric --cipher-algo AES256 input_file
        
        Decrypt: gpg -d input_file.gpg -o output_file
         
... nevertheless, it does not use QRs in any way, and it's a "little bit" more complex to use and adapt to your needs! 
