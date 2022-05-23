# Challenge Explanation

In this challenge, we're given this source code.

```Python
from Crypto.Util.number import getPrime, long_to_bytes, inverse, getRandomNBitInteger
from secrets import flag

class RSA:
    def __init__(self):
        self.p = getPrime(512)
        self.q = getPrime(512)
        self.e = 0x10001
        self.n = self.p * self.q
        self.d = inverse(self.e, (self.p-1)*(self.q-1))
        self.DaVinciSecretPass = b"Gimme The Ultimate Secret"
    
    def sign(self, data):
        return pow(data, self.d, self.n)
    
    def verify(self, data, sig):
        return self.sign(data) == sig

def welcome():
    welcom = ""
    welcom += """
 __   __   ______     __  __     __         ______      __  __     ______     ______     ______   ______    
/\ \ / /  /\  __ \   /\ \/\ \   /\ \       /\__  _\    /\ \/ /    /\  ___\   /\  ___\   /\  == \ /\  == \   
\ \ \\'/   \ \  __ \  \ \ \_\ \  \ \ \____  \/_/\ \/    \ \  _"-.  \ \  __\   \ \  __\   \ \  _-/ \ \  __<   
 \ \__|    \ \_\ \_\  \ \_____\  \ \_____\    \ \_\     \ \_\ \_\  \ \_____\  \ \_____\  \ \_\    \ \_\ \_\ 
  \/_/      \/_/\/_/   \/_____/   \/_____/     \/_/      \/_/\/_/   \/_____/   \/_____/   \/_/     \/_/ /_/ 
                                                                                                                                                                                                     
    """
    welcom += "Leonardo is a trust paranoiac. He build a machine for authentication. He claims that is unhackable.\n"

    print(welcom)


def SignSecret(cipher):
    print("\n --------- Sign -------------")
    user_secret = int(input(" Enter a secret to sign (hex): "), 16)
    assert 0 < user_secret < cipher.n
    if cipher.DaVinciSecretPass in long_to_bytes(user_secret):
        print(" Get Lost!")
    else:
        print(" Signed secret :",hex(cipher.sign(user_secret)))

def VerifySecret(cipher):
    print("\n --------- Verify -------------")
    user_secret = int(input(" Enter a secret to verify (hex): "), 16)
    user_signature = int(input(" Enter a signature (hex): "), 16)
    vrf = cipher.verify(user_secret, user_signature)
    if vrf :
        if cipher.DaVinciSecretPass == long_to_bytes(user_secret):
            print(" You own it!")
            print(flag)
            print("RUN ...")
            exit()
        else:
            print(" Ok!")
    else:
        print(" Get Lost liar!")
    
def menu():
    print("\n ==================== Secret Keeper - Options ====================")
    print(" 1. Sign a secret")
    print(" 2. Verify a secret")
    print(" 3. Quit")

    choice = int(input("> "))

    return choice

def main():
    welcome()
    PainterVault = RSA()
    print(" N :", hex(PainterVault.n))
    print(" e :", hex(PainterVault.e))
    for i in range(4):
        try:
            choice = menu()
            if choice == 1:
                SignSecret(PainterVault)
            if choice == 2:
                VerifySecret(PainterVault)
            if choice == 3:
                print(" Bye Bye.")
                exit()
        except:
            print(' Do not miss behave! Bye.')
            exit()

if __name__ == "__main__":
    main()
```

The source code is self-explanatory. This is a digital signature issuing and verification server, relying on RSA-1024. For each connection you're given N and e. The SignSecret function accepts any data you choose to sign except the "Secret Pass" : b"Gimme The Ultimate Secret". Obviously, to get the flag we must provide that secret pass alongside a valid signature to the verification function, which then return the flag. One important thing to not forget is that RSA works on numbers.

# Exploit

The exploit here is simple. In fact, it relies on some basic arithmetic principles.
When issuing a digital signature using RSA, this is what you do:
${Signature = Data^d [N]}$
But, as we have seen, we don't have the right to sign the desired string. This is were mathematics come to rescue. As we know :
for ![](https://render.githubusercontent.com/render/math?math=a%5Cequiv%20x%5Ed%28N%29) and ![](https://render.githubusercontent.com/render/math?math=b%5Cequiv%20y%5Ed%28N%29) : ![](https://render.githubusercontent.com/render/math?math=%28a*b%29%5Cequiv%20%28x*y%29%5Ed%28N%29)

So, to sign the secret pass of our flag, all we have to do is to factorise it, sign its factors then multiply them modulo N. that is:
let ![](https://render.githubusercontent.com/render/math?math=SecretPass=A*B)  
![](https://render.githubusercontent.com/render/math?math=SignedA%5Cequiv%20A%5Ed%28N%29)  
![](https://render.githubusercontent.com/render/math?math=SignedB%5Cequiv%20B%5Ed%28N%29)  
![](https://render.githubusercontent.com/render/math?math=%28SignedA%20*%20signedB%29%5Cequiv%20%28A*B%29%5Ed%28N%29%5Cequiv%20%28SecretPass%29%5Ed%28N%29%5Cequiv%20SignedSecretPass%28N%29)

# Solution

- Numerical Representation:
    `int.from_bytes(b"Gimme The Ultimate Secret","big")` = 448259296776519099895519136826694247309155561019569830258036
    
- Factorisation :
    448259296776519099895519136826694247309155561019569830258036 = 2^2 * 3^3 * 31 * 41 * 73 * 113 * 909648042841 * 435196412249196787243968099573349628353 = 1030016066676217002612 * 435196412249196787243968099573349628353
    
    - 1030016066676217002612 = 0x37d6582b620cfaba74
        
    - 435196412249196787243968099573349628353 =
        0x14767c7bb74128e11d2978745fe8239c1
        
- Digital signature :
    N = 0x7c930694e91ca076d715664244cb1823edd54e9a7bcdc44ec4709aa06c81766d345545e4df2feb484fdb36b4b07787583d3ef9098bb158ec70725e0dc56fab93790bf268fd9f204e8e9be923b731b27dcda7d9078f6cddc6258ccce78d52150e562fbd387719173ccf1fe25515cf987a376111402c2aad1c4f4ec404204fe235
    
    - Signature(1030016066676217002612) =
        0x5bd240dfe2cb98e3496baa0a16fe2c04364f3d8b3c6af96225bbddd1d2b7aea76b016f226b2d39285e4c9081ead37070447ff1785837cc3fd17d213efdc15838e840fcb2c16324982acd6ae9e55d0bb45102770f6164361b6627d25df0e0a4d0a3e1bf30dce7b26f6a6357345dce44cb8b6f655318743ea285345095973ad4d9
    - Signature(435196412249196787243968099573349628353)=
        0x3e160f8a257dff3a0dbd3738e6f6bcba870c430a987c74aa63abc3c032ec2b83c2d3333217f3fb9b55468969319bf4b153eaf061907532d1256fd0f40c9f7a9a31c4b9d8b917983f3662b460ef50505b13636fdeb98b15178cc77ed85ad4f220dd8936c86c164796b17a354b3f4209d9026373eab09f90718f65edf19b2dac82
    - Signature(b"Gimme The Ultimate Secret")= 0x4398797a200bef0a7cad333e6155424618ae1404d150e973306e83a4d0b62c68ff63436e98620c32b3057a39a72df3f4ed5b289c6760129e8e6ce10cbbb8f90b8072be4225de5da234d3ca93d7d8f3861ff5b2cd519a93b92df07c3cc772fe836d6940d8beacdb40cb11a846c140aeddec986e1d553403ff03b903ac60158e33  
      
      
      Upon sumbission of these values, I got the flag :
        ![vault.png](https://user-images.githubusercontent.com/53778121/169810316-e2cd7934-d3e0-469d-8170-ccfcdb5855b7.png)
