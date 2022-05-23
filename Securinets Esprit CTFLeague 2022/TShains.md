In the challenge, we're given this code :
``` Python
flag = b64encode(flag)
enc = b""
for i in range(len(flag)):
	enc += bytes([flag[i] ^ flag[(i+1) %len(flag)]])
enc = b64encode(enc)
# Z1oYPRg5GS1qfAcHCgIJF2p7e3wKHWloaH4hIQoCMzwaFnho

```

What it's doing is simple. It encoded the flag in base64, XORed its characters two by two, encoded it again then printed it. The important detail that we're gonna exploit is that it XORs the last character with the first one. So, all we have to do is to bruteforce the first character using the base64 alphabet, XORing the rest of the characters and doing the necessary decoding.

``` Python
#!/usr/bin/env python3

from base64 import b64decode
from pwn import xor
decoded = b64decode(b'Z1oYPRg5GS1qfAcHCgIJF2p7e3wKHWloaH4hIQoCMzwaFnho')
print(decoded)
alphabet = [b'a',b'b',b'c',b'd',b'e',b'f',b'g',b'h',b'i',b'j',b'k',b'l',b'm',b'n',b'o',b'p',b'q',b'r',b's',b't',b'u',b'v',b'w',b'x',b'y',b'z',b'A',b'B',b'C',b'D',b'E',b'F',b'G',b'H',b'I',b'J',b'K',b'L',b'M',b'N',b'O',b'P',b'Q',b'R',b'S',b'T',b'U',b'V',b'W',b'X',b'Y',b'Z',b'0',b'1',b'2',b'3',b'4',b'5',b'6',b'7',b'8',b'9']

for i in alphabet:
    dec=[]
    dec.insert(0,bytes(xor(decoded[len(decoded)-1],i)))
    for j in range(len(decoded)-2,0,-1):
        dec.insert(0,bytes(xor(decoded[j],dec[0])))
    try:
        print(b64decode(i+b''.join(dec)))
    except:
        pass
```
