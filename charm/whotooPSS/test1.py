from base64 import (
    b64encode,
    b64decode
)
from nacl.encoding import Base64Encoder
from nacl.public import (
    Box,
    PrivateKey,
    PublicKey
)

def base64_to_bytes(key: str) -> bytes:
    return b64decode(key.encode("utf-8"))

def encrypt(ssk: str, rpk: str, m: str) -> str:
    ssk = PrivateKey(base64_to_bytes(ssk))
    rpk = PublicKey(base64_to_bytes(rpk))
    b = Box(ssk, rpk)
    return b64encode(b.encrypt(bytes(m, "utf-8"))).decode("utf-8")

def decrypt(rsk: str, spk: str, c: str) -> str:
    rsk = PrivateKey(base64_to_bytes(rsk))
    spk = PublicKey(base64_to_bytes(spk))
    b = Box(rsk, spk)
    return b.decrypt(b64decode(c.encode("utf-8"))).decode("utf-8")

s1 = PrivateKey.generate()
p1 = s1.public_key

s2 = PrivateKey.generate()
p2 = s2.public_key

ss1 = s1.encode(Base64Encoder).decode("utf-8")
sp1 = p1.encode(Base64Encoder).decode("utf-8")

ss2 = s2.encode(Base64Encoder).decode("utf-8")
sp2 = p2.encode(Base64Encoder).decode("utf-8")

print(f"ss1 {type(ss1)}: {ss1}")
print(f"sp1 {type(sp1)}: {sp1}")
print(f"ss2 {type(ss2)}: {ss2}")
print(f"sp2 {type(sp2)}: {sp2}")

m = "Hello world"
print(m)
c = encrypt(ss1, sp2, m)
print(c)
nm = decrypt(ss2, sp1, c)
print(nm)