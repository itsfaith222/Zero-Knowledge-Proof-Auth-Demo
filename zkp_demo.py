import hashlib #for hashing non-interactive ZKP
import random #to generate random values needed
from dataclasses import dataclass #to create datat structures

@dataclass 
class PublicValues:
    p: int #modulus
    q: int #subgroup order of g
    g: int #generator

@dataclass
class UserRecords:
    username: str 
    h: int #public key for user h=g^x mod p


class ZKPDEMO: 
    def __init__(self):
        #Here is where the public values and users are initlized 
        self.public = PublicValues(p=23, q=11, g=2)
        self.users: dict[str, UserRecords] = {}     #dictionary for each user to have username and public key

    def mod_equation(self, base: int, exponent: int, modulus: int):
        #Method when needing to calculate base ^ exponent then mod. 
        return pow(base, exponent, modulus)
    
    #Before communication can start for ZKP users need to inilize a secret and public key 
    def user_init(self, usname: str, secret: int):
        "Public key formula h=g^x mod p"
        p = self.public.p
        g = self.public.g
        #calculate
        h = self.mod_equation(g, secret, p)
        #add to user class
        self.users[usname] = UserRecords(username=usname, h=h)

        #print to follow in ternimal 
        print(f"\n REGISTERED User {usname}")
        print(f'Publick key: h = {g}^{secret} mod {p} = {h}')

    #this is the method that is called to run the interactive ZKP demo 
    def interactive_login(self, usname: str, secret_guess: int ):
        "Schnorr protocol"
        #first check if username is valid 
        if usname not in self.users:
            print(f"ERROR {usname} not found in usernames.")
            return 0
        
        print("\n=== INTERACTIVE SCHNORR LOGIN ===")
        print(f"Public values: p={self.public.p}, q={self.public.q}, g={self.public.g}, h={self.users[usname].h}")
        
        #if found start ZKP 
        #STEP 1: Prover chooses random r and sends U to verifier
        r = random.randint(0, self.public.q-1)
        u = self.mod_equation(self.public.g, r, self.public.p)
        print(f"STEP 1 - Prover: generates random r ={r} and computes u")
        print(f"Sends u={u} -->> Verifier!")

        #STEP 2: Verifier picks random challange c for prover
        c = random.randint(0, self.public.q-1)
        print(f"STEP 2: Verifier picks random challange value c.")
        print(f"Sends c={c} -->> Prover!")

        #STEP 3: Prover computes resonse z value z = r + c * x mod q
        z = (r + (c * secret_guess)) % self.public.q
        print(f"STEP 3: Prover computes resonse valuse z.")
        print(f"Sends z={z} -->> Verifier!")

        #STEP 4: Verifier checks if prover knows secret gz = u * h^c mod p
        
        #left side
        left = self.mod_equation(self.public.g, z, self.public.p)
        right =( u * (self.mod_equation(self.users[usname].h, c, self.public.p)) )

        print("STEP 4: Verifier checks if prover really know the secret. ")
        if left == right:
            
            print(f"Left side = {left}  |   Right side = {right} \nBoth sides are equal: PROVER KNOWS Secret! :)")
        else: 
            print(f"Left side = {left}  |   Right side = {right} \nBoth sides are NOT equal: PROVER DOES NOT KNOW Secret! :)")

    
def main():
    demo = ZKPDEMO()    #create object

    print("=== ZKP AUTHENTICATION DEMO ===")
    print("Toy setup only: p=23, q=11, g=2\n")

    demo.user_init("faith123", 10)

    
    demo.interactive_login("faith123", secret_guess=10) 
    
    demo.interactive_login("faith123", secret_guess=6)

if __name__ == "__main__":
    main()