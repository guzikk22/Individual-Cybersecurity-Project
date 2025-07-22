import cryptography.hazmat.primitives.ciphers as ciphers
import cryptography.hazmat.primitives.hashes as hashes
import cryptography.hazmat.primitives.hmac as hmac
import os

def bytes_to_str(b) :
    if type(b) != type(b'') :
        return ""
    s = str(b)
    s = s[2:-2]
    return s

#interprets big as a positive integer written in big endian notation
def bytes_to_int(b) :
    n = 0
    for i in b:
        n *= 256
        n += i
    return n

# returns a big endian representation of a positive integer
# in a string of bytes, fixes string's byte-length to l if given
def int_to_bytes(n, l=0) :
    b = b''
    i = 0
    while i < l or l==0 :
        b = bytes((n%256,)) + b
        i += 1
        n = n//256
        if l==0 and n==0:
            break
    return b
# efficient integer modular exponentiation with base b, exponent e and modulus m
def modExp(b, e, mod) :
    n = 1
    b = b%mod
    while e > 0 :
        if e%2 == 1 :
            n*=b
            n = n%mod
        b *= b
        b = b%mod
        e = e//2
    e = 0
    b = 0

    return n
# returns smallest positive integer l such that b**l >= n
def intLog(b, n) :
    if b <= 0:
        return 1
    if n <= 1:
        return 0
    if n <= b:
        return 1
    
    l = 1 # lower bound log
    p = b # lower bound power
    L = 1 # upper bound log
    P = b # upper bound power
    biExp = [b]

    while P < n :
        l = L ; p = P
        L *= 2; P *= P
        biExp.append(P)

    a = len(biExp)-3
    while a>=0 :
        if p*biExp[a] < n:
            l += 2**a
            p *= biExp[a]
        else :
            L = l+2**a
            P = p*biExp[a]
        a -= 1
        
    return L

# returns random integer 0<=out<n
def trueRand_int(n) :
    bit = intLog(2, n)
    byte_l = bit//8
    bit = 2**(bit%8)

    while True:
        r_byte = bytes( (os.urandom(1)[0] % bit,) )
        r_bytes = r_byte + os.urandom(byte_l)
        r = bytes_to_int(r_bytes)
        if r<n :
            break
    return r
        
#Prepares message m to be sent applies AES and HMAC in encrypt-then-hash order
def PrepareMessage(m, encK, authK) :  
    if len(encK) != 32 or len(authK) != 32 :
        return b''
    if len(m) % 16 != 0:
        return b''
    pm = b'' #prepared message
    IV = os.urandom(16)
    aes_cbc = ciphers.Cipher(
        ciphers.algorithms.AES256(encK),
        ciphers.modes.CBC(IV))
    enc = aes_cbc.encryptor()

    pm += enc.update(m)
    pm += enc.finalize()
    pm += IV
    
    auth = hmac.HMAC(
        authK,
        hashes.SHA3_256() )

    auth.update(pm) 
    pm += auth.finalize()
    
    del encK; del authK

    return pm

#Verifies and decrypts prepared message
def ReadMessage(pm, encK, authK) :
    if len(encK) != 32 or len(authK) != 32:
        return b''
    if len(pm) < 48:
        return b''
    m = b''

    MAC = pm[-32:]
    pm = pm[0:-32]

    auth = hmac.HMAC(
        authK,
        hashes.SHA3_256() )
    
    auth.update(pm)
    auth.verify(MAC)

    IV = pm[-16:]
    pm = pm[0:-16]
    
    aes_cbc = ciphers.Cipher(
        ciphers.algorithms.AES(encK),
        ciphers.modes.CBC(IV))
    dec = aes_cbc.decryptor()

    m += dec.update(pm)
    m += dec.finalize()

    return m
#performs OAEP padding
def OAEP(m, label):
    cs = os.urandom(32)
    return OAEP_cs(m, label, cs)

#performs OAEP padding with chosen seed (cs)
def OAEP_cs(m, label, cs):
    if len(m) > 190 :
        return bytes(256)
    if len(cs) != 32 :
        return bytes(256)
    
    H = hashes.Hash(hashes.SHA3_256())
    H.update(label)
    label_hash = H.finalize()

    mb = label_hash + bytes(190-len(m)) + b'\x01' + m

    maskGen = hashes.Hash(hashes.SHAKE128(223))
    maskGen.update(cs)
    mask = maskGen.finalize()
    # XOR mask
    mb = bytes(a ^ b for a, b in zip(mb, mask))
    
    maskGen = hashes.Hash(hashes.SHAKE128(32))
    maskGen.update(mb)
    mask = maskGen.finalize()
    # XOR mask
    cs = bytes(a ^ b for a, b in zip(cs, mask))

    return b'\x00' + cs + mb
# removes OAEP padding returns empty string if padding is invalid
def deOAEP(pad_m, label):
    if len(pad_m) != 256 :
        return b''
    if pad_m[0] != 0:
        return b''

    cs = pad_m[1:33]
    mb = pad_m[33:]

    maskGen = hashes.Hash(hashes.SHAKE128(32))
    maskGen.update(mb)
    mask = maskGen.finalize()
    # XOR mask
    cs = bytes(a ^ b for a, b in zip(cs, mask))

    maskGen = hashes.Hash(hashes.SHAKE128(223))
    maskGen.update(cs)
    mask = maskGen.finalize()
    # XOR mask
    mb = bytes(a ^ b for a, b in zip(mb, mask))

    label_hash = mb[:32]
    mb = mb[32:]

    H = hashes.Hash(hashes.SHA3_256())
    H.update(label)
    if label_hash != H.finalize() :
        return b''

    i = 0
    while i<190 and mb[i] == 0:
        i += 1
    if mb[i] != 1:
        return b''

    return mb[i+1:]
# encrypts/decrypts with RSA e-exponent n-modulus
def RSA_crypt(m, e, n):
    if len(m) != 256:
        return bytes(256)
    int_m = bytes_to_int(m)
    int_m = modExp(int_m, e, n)
    m = int_to_bytes(int_m, 256)
