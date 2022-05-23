# Challenge explanation:

In this challenge, we get the source code of the server running at the CTFs infrastructure.

```Python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from secrets import flag
import random
import os

BLOCK_SIZE = 16
KEY = os.urandom(BLOCK_SIZE)

def encrypt(msg):
    iv = os.urandom(BLOCK_SIZE)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    return (iv + cipher.encrypt(pad(msg, BLOCK_SIZE))).hex()


def decrypt(data):
    iv = data[:BLOCK_SIZE]
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(data[BLOCK_SIZE:]), BLOCK_SIZE)

def parse(enc_token):
    dec = decrypt(enc_token)
    splitted_token = dec.split(b"|")
    assert len(splitted_token) == 2, "Please enter a token in the format encrypt(name|rm=int)"
    assert splitted_token[1].startswith(b"rm="), "no room is found"
    name, room = splitted_token[0], splitted_token[1][3:].decode()
    return name, int(room)

def menu():
    print("\n==================== DaVinci House - Entry ====================")
    print("1. Show Rooms")
    print("2. Get Room Access Token")
    print("3. Enter Room")
    print("4. Quit")

    choice = int(input("> "))

    return choice

def showRooms():
    print("\n*** Davinci House - Available Rooms ***")

    print("  Room 1: Monalisa Room")
    print("  Room 2: The Last Supper Room")
    print("  Room 3: Vitruvian Man Room")
    print("  Room 4: Salvator Mundi Room")
    print("  Room 1337: Secret Room")

def getRoomAccess():
    print("*** DaVinci House - Registration Gate ***")

    name = input("Name : ").encode()
    assert not b"davinci" in name.lower(), "No you're Not DaVinci, FRAUD!"

    room = int(input("Room number : "))
    assert 1 <= room <= 4, "Where you think can go ?"
    token = name + b"|" + b"rm=" + str(room).encode()

    return encrypt(token)

def enterRoom():
    print("\n*** Davinci House - Enter a Room ***")
    token = bytes.fromhex(input("Give your secret token (hex): "))
    name, room = parse(token)
    if name == b"DaVinci":
        if room == 1337:
            print("You made the impossible! Welcome to DaVinci's secret room, now take this ...")
            print(flag)
            print("And RUUN!")
            exit()
        else:
            print("Yeah Davinci can go anywhere in his house!\n")
    else:
        if room == 1337:
            print("Get lost!\n")
        else:
            print(f"Welcome to room {room}, enjoy !\n")


def welcome():
    welcome = "Welcome to"
    welcome += """
    ___               _               _                                  
   /   \ __ _ /\   /\(_) _ __    ___ (_)   /\  /\ ___   _   _  ___   ___ 
  / /\ // _` |\ \ / /| || '_ \  / __|| |  / /_/ // _ \ | | | |/ __| / _ \\
 / /_//| (_| | \ V / | || | | || (__ | | / __  /| (_) || |_| |\__ \|  __/
/___,'  \__,_|  \_/  |_||_| |_| \___||_| \/ /_/  \___/  \__,_||___/ \___|
                                                                         
"""

    welcome += "\nDaVinci gives you the one and only opportunity to visit his house"
    welcome += "\nAnd discover his paintings. All the his work is divided into 5 rooms."
    welcome += "\nBut there is one room that he refused to open."

    print(welcome)

def main():
    welcome()


    for i in range(3):
        try:
            choice = menu()
            if choice == 1:
                showRooms()

            if choice == 2:
                enc_token = getRoomAccess()
                print("Here is your token, use it carefully:", enc_token)

            if choice == 3:
                enterRoom()
                
            if choice == 4:
                print("\nSee next time!")
                exit()
        except:
            print("\nDon't cause problems. Bye!")
            exit()
    
if __name__ == "__main__":
    main()

```

At first, I got overwhelmed by the large codebase. But, after further inspection, I realised it's simply a token generation and verification server. Let's first dissect how it works :

The server relies on AES-CBC to encrypt its tokens, with the key regenerating at each server connection and the IV regenerating at each token encryption. *encrypt* and *decrypt* functions are self-explanatory, they implement the encryption and decryption algorithms, nothing fancy. The important thing to remark here is that the IV is appended to the decrypted message.

Fast forward to the main menu, we could see two important options : Get Room Access Token and Enter Room.

- The *getRoomAccess* function gets the user's name and checks if it's DaVinci (considering all case variations), and if so, refuses to generate token. And then asks for the desired room and checks if it's out of the \[1..4\] range, also denying denying token generation if so. The important part is what comes after. After doing its checks, the function generates the token as follows: it creates the token as \[name\]|rm=\[roomNumber\], encrypts it with the aforementioned encrypt function, and present it to the user.
- The enterRoom function is simple. It first parses the token through the parse function (nothing fancy happens here, just some checks and then name and room number parsing). If your name is DaVinci and your room number is 1337, you get the flag. Else, you get sacked hahahahahahahahahahahaha.

# Vulnerability :

The culprit here is so clear and simple. Using the CBC mode of operation, the server puts itself at risk of a **Bit Flip Attack**. Knowing the token format, and having the IV, we've got all we need to prepare our payload. Let's first discuss shortly the Bit Flip Attack.
CBC's main property is that it chains each data block with its predecessor. This is what makes it achieve the confidentiality goal in a nearly unbreakable way, making it one of the most used modes of operation out there. But, this same property causes a weakness in the data integrity. Let's see why :

![CBC_decryption.svg](:/239cdd31b8b04d46b3bd8343ec8c3ff4)

As we can see, the CBC decryption algorithm is so simple. It decrypts each ciphertext block, and then XORs it with its previous ciphertext block to get the plaintext. The integrity weakness lies there. Having control over the previous block, an attacker could influence current block's produced plaintext. And since the XOR operation is applied AFTER the algorithm decryption, he won't need to bother himself with the used algorithm or key.

A typical Bit Flip Attack on CBC goes like this (We'll consider the case of changing the value of one byte, the first one in the desired block):
You must know beforehand the value you'll be changing and you have a ciphertext containing at least two ciphertext blocks (Or a ciphertext block and an IV).
Let's call C1 the first byte of the first ciphertext, C2 the first byte of the second ciphertext (The one we're going to change), P1 the original plaintext's second block's first byte, MC1 our malicious ciphertext's first byte and MP the desired malicious plaintext's first byte. And let's call the byte produced after the algorithm decryption and before the XOR operation I1.

A simplified payload creation process is:

- ${C1 ⊕ I1 = P1}$
- ${C1 ⊕ P1 ⊕ I1 = P1 ⊕ P1 = 0}$
- ${C1 ⊕ P1 ⊕ MP1 = 0 ⊕ MP1 = MP1}$

Thus, ${MC1 = C1 ⊕ P1 ⊕ MP1}$.
Feeding the decryption server a malicious ciphertext that start with MP1 will make it produce the next plaintext block starting with MP1.

Long story short, and I'm quoting Layka_ on this one, a generalised payload format for the Bit Flip Attack is:

`Tampered_Cipher_N-1 = Plaintext_N ⊕ Cipher_N-1 ⊕ Wanted_Plaintext_N`

**Important notes:**

- Since we didn't mess with the second ciphertext block, and we're not messing with anything related to the decryption algorithm, I1 is always the same.
- The malicious block's data should be meaningless in the context you're running the attack in.
- Unless you have the IV, you can't execute the attack on the first block.

# Exploit:

After this lengthy explanation, let's get our hands dirty. We already know the token's format, the name and room number are chosen by us and the padding algorithm is the default. So we know each byte of the produced plaintext. And as the token format tells us that it will usually fit in one block, we don't need to worry as we're given the IV. All the required criteria do exist.
We have three things to change during the attack:

- The name: This is the simplest part. All you have to do is enter a string of the same length as DaVinci so you could later change it. I chose to insert: aaaaaaa .
- The room number : Things get pretty messy here. The room number is formed of a single digit due to imposed checks. So, changing it to a 4-digits number (1337) would imply that we're gonna change the padding value, which we should calculate. I choose to insert 1, so that I had one less byte to mess with. Knowing that AES's block size is 16, and the produced token's length is 12 (aaaaaaa|rm=1), we're going to have 4 bytes of padding. And since PKCS#7 is the default padding algorithm in PyCryptoDome's pad, the padding bytes would have 0x04 as values.
- The new padding: Messing with the token's length and the old padding, we're gonna need to fix the padding value so that it doesn't raise an exception while unpadding. Our desired plaintext is DaVinci|rm=1337. Being 15-bytes-long, the padding will only be one byte, the last one, having 0x01 as value.

To execute the attack, I inserted the chosen values and then fed them to a solver which :

- XORs the first 7 IV bytes with 'aaaaaaa' and 'DaVinci'
- XORs 13th,14th and 15th IV bytes with \\x04\\x04\\x04 and '337'
- XORS the last IV byte with \\x04 \\x01.
- Returns the malicious payload.

And Voilà ! I got the flag inserting the payload in Enter Room option.

![token.png](https://user-images.githubusercontent.com/53778121/169809376-99d132bf-ccc0-45ea-b00a-b15b72e2ae49.png)

![solver.png](https://user-images.githubusercontent.com/53778121/169809459-82bf340a-3496-4525-911e-05e003d07f3d.png)

![flag.png](https://user-images.githubusercontent.com/53778121/169809532-33b35deb-ce3a-4769-92e4-f68aaf54bdd9.png)

# Solver:

```Python
#!/usr/bin/env python3
from pwn import xor,enhex
import sys
#name = [37, 0, 55, 8, 15, 2, 8]
name = xor(b'aaaaaaa',b'DaVinci')
#roomNumber = [0x37,0x37,0x33,0x05]
roomNumber = xor(b'337\x01',b'\x04\04\x04\x04')
token = bytes.fromhex(sys.argv[1])

payload = ''.join([enhex(xor(name[i],token[i])) for i in range(7)])
payload += ''.join([enhex(xor(token[i],b'\x00')) for i in range(7,12)])
payload += ''.join([enhex(xor(roomNumber[i-12],token[i])) for i in range(12,16)]) 
payload += ''.join([enhex(xor(token[i],b'\x00')) for i in range(16,32)])
print(payload)

```
