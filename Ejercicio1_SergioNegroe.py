import Crypto.Util.number
import hashlib

bits = 1024

def hash_string(data):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(data.encode('utf-8'))
    hashed_data = sha256_hash.hexdigest()

    return hashed_data

# Generar mensaje
M = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum." * 7

# Hashear mensaje
hashM = hash_string(M)

# Dividir mensaje en bloques de 128 bytes
bloques = [M[i:i+128] for i in range(0, len(M), 128)]

# Generar primos para Alice
pA = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
qA = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
# Generar primos para Bob
pB = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
qB = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
# Generar claves
nA = pA * qA
nB = pB * qB
# Calcular phi
phiA = (pA - 1) * (qA - 1)
phiB = (pB - 1) * (qB - 1)
# Calcular e, cuarto primo de Fermat
e = 65537
# Calcular d
dA = Crypto.Util.number.inverse(e, phiA)
dB = Crypto.Util.number.inverse(e, phiB)

# Cifrado de mensaje
cifradoCurrentM = [0] * len(bloques)
for i, bloque in enumerate(bloques):
    bytesCurrentM = int.from_bytes(bloque.encode(), byteorder='big') # Mensaje en bytes
    cifradoCurrentM[i-1] = pow(bytesCurrentM, e, nB) # Cifrado del mensaje

# Descifrado de mensaje
decifradoCurrentM = [0] * len(bloques)
decifradoCurrentMCharacteres = [0] * len(bloques)
mensajeDecifrado = ''
for i, bloque in enumerate(bloques):
    decifradoCurrentM[i-1] = pow(cifradoCurrentM[i-1], dB, nB)
    decifradoCurrentM[i-1] = decifradoCurrentM[i-1].to_bytes((decifradoCurrentM[i-1].bit_length() + 7) // 8, byteorder='big')
    decifradoCurrentMCharacteres[i-1] = decifradoCurrentM[i-1].decode()
    mensajeDecifrado += decifradoCurrentMCharacteres[i-1]

print("Mensaje:", mensajeDecifrado)

# Verificar hash
hashDecifrado = hash_string(mensajeDecifrado)
if hashM == hashDecifrado:
    print("Hashes iguales ✅")
else:
    print("Hashes diferentes ❌")