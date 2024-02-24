import Crypto.Util.number
import hashlib
from PyPDF2 import PdfWriter, PdfReader, PageObject
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

bits = 1024

def hash_file(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, 'rb') as file:
        for chunk in iter(lambda: file.read(4096), b''):
            sha256_hash.update(chunk)
    hashed_bytes = sha256_hash.digest()
    return hashed_bytes

def add_string_to_pdf(pdf_path, text_to_add, firmante):
    reader = PdfReader(pdf_path)
    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)
    with open("NDA.pdf", "wb") as f:
        writer.write(f)
        new_file_route = "NDA_firma_"+firmante+".pdf"
        c = canvas.Canvas(new_file_route, pagesize=letter)
        c.drawString(50,50, str(text_to_add))
        c.save()
    return new_file_route

# Generar primos para Alice
pA = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
qA = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
# Generar primos para Bob
pB = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
qB = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
# Generar primos para AC
pAC = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
qAC = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
# Generar claves
nA = pA * qA
nB = pB * qB
nAC = pAC * qAC
# Calcular phi
phiA = (pA - 1) * (qA - 1)
phiB = (pB - 1) * (qB - 1)
phiAC = (pAC - 1) * (qAC - 1)
# Calcular e, cuarto primo de Fermat
e = 65537
# Calcular d
dA = Crypto.Util.number.inverse(e, phiA)
dB = Crypto.Util.number.inverse(e, phiB)
dAC = Crypto.Util.number.inverse(e, phiAC)

# Hash del archivo
pdf_file_path = '/Users/sergionegroe/Documents/Anáhuac/Semestre 8/Seguridad Informática y análisis forense/Prcial1_SergioNegroe_SIAF/NDA.pdf'
pdf_hash = hash_file(pdf_file_path)
hash_archivo_int = int.from_bytes(pdf_hash, byteorder='big')

# Firma del hash del mensaje por Alice
hash_archivo_int_firmado_Alice = pow(hash_archivo_int, dA, nA)

# Agregar firma al archivo
archivo_firma_Alice = add_string_to_pdf(pdf_file_path, str(hash_archivo_int_firmado_Alice), "Alice")

# AC recibe de Alice y valida
hash_original = int.from_bytes(pdf_hash, byteorder='big')
hash_validacion = pow(hash_archivo_int_firmado_Alice, e, nA) # AC valida que la firma de Alice corresponda al archivo original
if hash_original == hash_validacion:
    print("La firma ha sido validada por AC. ✅")
else:
    print("La firma fue rechazada por AC. ❌")

# Firma del hash del mensaje por AC
hash_archivo_int_firmado_AC = pow(hash_archivo_int, dAC, nAC)

# Agregar firma al archivo
add_string_to_pdf(pdf_file_path, str(hash_archivo_int_firmado_AC), "AC")

# Bob recibe de AC y valida
hash_original = int.from_bytes(pdf_hash, byteorder='big')
hash_validacion = pow(hash_archivo_int_firmado_AC, e, nAC)
if hash_archivo_int == hash_validacion:
    print("La firma ha sido validada por Bob. ✅")
else:
    print("La firma fue rechazada por Bob. ❌")
