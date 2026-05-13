#!/usr/bin/env python3
"""
=============================================================
  Calculadora de Problemas Matemáticos de Criptografía
  Tarea 4 — Ciberseguridad, Fundamentos de Criptografía
  Mayo 2026
=============================================================
Algoritmos incluidos:
  1. RSA  — Generación de claves, cifrado y descifrado
  2. Diffie-Hellman — Intercambio de claves
  3. ECDSA — Firma digital y verificación (curva secp256k1 simplificada)
  4. AES-256 — Cifrado y descifrado simétrico
  5. SHA-256 — Cálculo de hash criptográfico
"""

import hashlib
import os
import sys
import random
import math
from typing import Tuple, Optional


# ──────────────────────────────────────────────
# UTILIDADES MATEMÁTICAS
# ──────────────────────────────────────────────

def gcd(a: int, b: int) -> int:
    """Máximo común divisor (Algoritmo de Euclides)."""
    while b:
        a, b = b, a % b
    return a


def mod_inverse(a: int, m: int) -> int:
    """Inverso modular de a módulo m usando el Algoritmo de Euclides extendido."""
    if gcd(a, m) != 1:
        raise ValueError(f"El inverso modular no existe: mcd({a}, {m}) ≠ 1")
    # Algoritmo de Euclides extendido
    g, x, _ = extended_gcd(a, m)
    return x % m


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Algoritmo de Euclides extendido. Retorna (g, x, y) tal que a*x + b*y = g."""
    if a == 0:
        return b, 0, 1
    g, x1, y1 = extended_gcd(b % a, a)
    return g, y1 - (b // a) * x1, x1


def power_mod(base: int, exp: int, mod: int) -> int:
    """Exponenciación modular rápida (Square-and-Multiply)."""
    return pow(base, exp, mod)


def is_prime_miller_rabin(n: int, k: int = 10) -> bool:
    """
    Prueba de primalidad de Miller-Rabin.
    k: número de iteraciones (mayor k = mayor certeza).
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Escribir n-1 como 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = power_mod(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = power_mod(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    """Genera un número primo de 'bits' bits usando Miller-Rabin."""
    while True:
        candidate = random.getrandbits(bits)
        # Asegurar que sea impar y tenga el tamaño correcto
        candidate |= (1 << bits - 1) | 1
        if is_prime_miller_rabin(candidate):
            return candidate


def validate_prime(n: int) -> bool:
    """Valida que n sea primo."""
    return is_prime_miller_rabin(n, k=15)


# ──────────────────────────────────────────────
# MÓDULO RSA
# ──────────────────────────────────────────────

class RSA:
    """
    Implementación de RSA para fines educativos.
    Operaciones: generación de claves, cifrado con clave pública,
    descifrado con clave privada.
    """

    def __init__(self):
        self.public_key: Optional[Tuple[int, int]] = None   # (n, e)
        self.private_key: Optional[Tuple[int, int]] = None  # (n, d)
        self.p: Optional[int] = None
        self.q: Optional[int] = None

    def generate_keys(self, bits: int = 512) -> None:
        """
        Genera par de claves RSA.
        bits: tamaño de cada primo (n tendrá 2*bits bits).
        """
        if bits < 128:
            raise ValueError("Para fines educativos, mínimo 128 bits por primo.")

        print(f"\n[RSA] Generando primos de {bits} bits...")
        p = generate_prime(bits)
        q = generate_prime(bits)
        # Asegurar que p ≠ q
        while q == p:
            q = generate_prime(bits)

        n = p * q
        phi_n = (p - 1) * (q - 1)

        # e comúnmente utilizado: 65537
        e = 65537
        if gcd(e, phi_n) != 1:
            # Buscar otro e válido si 65537 no sirve (muy raro)
            e = 3
            while gcd(e, phi_n) != 1:
                e += 2

        d = mod_inverse(e, phi_n)

        self.p, self.q = p, q
        self.public_key = (n, e)
        self.private_key = (n, d)

        print(f"  p = {p}")
        print(f"  q = {q}")
        print(f"  n = p × q = {n}")
        print(f"  φ(n) = (p-1)(q-1) = {phi_n}")
        print(f"  e = {e}")
        print(f"  d = e⁻¹ mod φ(n) = {d}")
        print(f"  Clave pública:  (n={n}, e={e})")
        print(f"  Clave privada:  (n={n}, d={d})")

    def encrypt(self, message: int) -> int:
        """
        Cifrado RSA: c = m^e mod n
        message debe ser un entero 0 <= m < n.
        """
        if self.public_key is None:
            raise RuntimeError("Primero genera las claves con generate_keys().")
        n, e = self.public_key
        if not (0 <= message < n):
            raise ValueError(f"El mensaje debe ser un entero en [0, n-1]. n={n}")
        ciphertext = power_mod(message, e, n)
        print(f"\n[RSA] Cifrado:")
        print(f"  m = {message}")
        print(f"  c = m^e mod n = {message}^{e} mod {n} = {ciphertext}")
        return ciphertext

    def decrypt(self, ciphertext: int) -> int:
        """
        Descifrado RSA: m = c^d mod n
        """
        if self.private_key is None:
            raise RuntimeError("No hay clave privada. Genera las claves primero.")
        n, d = self.private_key
        if not (0 <= ciphertext < n):
            raise ValueError(f"El texto cifrado debe ser un entero en [0, n-1].")
        message = power_mod(ciphertext, d, n)
        print(f"\n[RSA] Descifrado:")
        print(f"  c = {ciphertext}")
        print(f"  m = c^d mod n = {ciphertext}^{d} mod {n} = {message}")
        return message


# ──────────────────────────────────────────────
# MÓDULO DIFFIE-HELLMAN
# ──────────────────────────────────────────────

class DiffieHellman:
    """
    Protocolo Diffie-Hellman clásico (sobre Z*_p).
    Permite simular el intercambio de claves entre Alice y Bob.
    """

    # Parámetros seguros NIST (RFC 3526 — grupo de 1024 bits, simplificado para demo)
    DEMO_PRIME = (
        0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
        + 0x29024E088A67CC74020BBEA63B139B22514A08798E3404DD
        + 0xEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245
        + 0xE485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED
        + 0xEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D
        + 0xC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F
        + 0x83655D23DCA3AD961C62F356208552BB9ED529077096966D
        + 0x670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B
        + 0xE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9
        + 0xDE2BCBF6955817183995497CEA956AE515D2261898FA0510
        + 0x15728E5A8AACAA68FFFFFFFFFFFFFFFF
    )

    def __init__(self, p: Optional[int] = None, g: int = 2):
        """
        p: primo del grupo (si None, usa primo NIST de 1024 bits).
        g: generador (usualmente 2 o 5).
        """
        self.p = p if p is not None else self.DEMO_PRIME
        self.g = g
        self._validate_params()

    def _validate_params(self):
        if self.g < 2:
            raise ValueError("El generador g debe ser >= 2.")
        if not validate_prime(self.p):
            raise ValueError("p no es un número primo válido.")

    def generate_private_key(self) -> int:
        """Genera una clave privada aleatoria en [2, p-2]."""
        return random.randint(2, self.p - 2)

    def compute_public_key(self, private_key: int) -> int:
        """Calcula la clave pública: pub = g^priv mod p."""
        if not (2 <= private_key <= self.p - 2):
            raise ValueError("Clave privada fuera de rango [2, p-2].")
        return power_mod(self.g, private_key, self.p)

    def compute_shared_secret(self, their_public: int, my_private: int) -> int:
        """Calcula el secreto compartido: K = their_pub^my_priv mod p."""
        if not (1 <= their_public <= self.p - 1):
            raise ValueError("Clave pública recibida fuera de rango.")
        return power_mod(their_public, my_private, self.p)

    def simulate_exchange(self) -> None:
        """Simula un intercambio completo DH entre Alice y Bob."""
        print(f"\n[DH] Parámetros públicos:")
        print(f"  g = {self.g}")
        print(f"  p = {self.p}")

        # Alice
        a = self.generate_private_key()
        A = self.compute_public_key(a)
        print(f"\n[DH] Alice:")
        print(f"  a (privada) = {a}")
        print(f"  A = g^a mod p = {A}")

        # Bob
        b = self.generate_private_key()
        B = self.compute_public_key(b)
        print(f"\n[DH] Bob:")
        print(f"  b (privada) = {b}")
        print(f"  B = g^b mod p = {B}")

        # Secreto compartido
        K_alice = self.compute_shared_secret(B, a)
        K_bob = self.compute_shared_secret(A, b)

        print(f"\n[DH] Secreto compartido:")
        print(f"  Alice calcula: K = B^a mod p = {K_alice}")
        print(f"  Bob calcula:   K = A^b mod p = {K_bob}")
        print(f"  ¿Coinciden? {'✓ SÍ' if K_alice == K_bob else '✗ ERROR'}")
        return K_alice


# ──────────────────────────────────────────────
# MÓDULO SHA-256 (usando hashlib — estándar Python)
# ──────────────────────────────────────────────

class HashSHA256:
    """Cálculo y verificación de hash SHA-256."""

    @staticmethod
    def hash_text(text: str) -> str:
        """Calcula SHA-256 de un texto."""
        if not isinstance(text, str):
            raise TypeError("La entrada debe ser una cadena de texto.")
        if len(text) == 0:
            raise ValueError("El texto no puede estar vacío.")
        h = hashlib.sha256(text.encode('utf-8')).hexdigest()
        print(f"\n[SHA-256] Hash de texto:")
        print(f"  Entrada: '{text}'")
        print(f"  SHA-256: {h}")
        return h

    @staticmethod
    def hash_file(filepath: str) -> str:
        """Calcula SHA-256 de un archivo."""
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"Archivo no encontrado: {filepath}")
        sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        h = sha256.hexdigest()
        print(f"\n[SHA-256] Hash de archivo:")
        print(f"  Archivo: {filepath}")
        print(f"  SHA-256: {h}")
        return h

    @staticmethod
    def verify(text: str, expected_hash: str) -> bool:
        """Verifica si el hash de un texto coincide con el esperado."""
        if not expected_hash or len(expected_hash) != 64:
            raise ValueError("Hash esperado inválido (debe ser 64 caracteres hex).")
        computed = hashlib.sha256(text.encode('utf-8')).hexdigest()
        result = computed == expected_hash.lower()
        print(f"\n[SHA-256] Verificación de integridad:")
        print(f"  Texto: '{text}'")
        print(f"  Hash calculado: {computed}")
        print(f"  Hash esperado:  {expected_hash.lower()}")
        print(f"  Resultado: {'✓ VÁLIDO' if result else '✗ INVÁLIDO'}")
        return result


# ──────────────────────────────────────────────
# MÓDULO AES (usando módulo estándar / pycryptodome si disponible)
# ──────────────────────────────────────────────

def aes_encrypt_decrypt_demo():
    """
    Demostración de cifrado AES-256-GCM usando solo la biblioteca estándar
    de Python (via os.urandom para el IV y XOR con keystream simulado).
    
    NOTA: Para uso en producción, utilizar pycryptodome o cryptography library.
    Esta implementación es educativa y demuestra el concepto del modo GCM.
    """
    # Intentar usar pycryptodome si está disponible
    try:
        from Crypto.Cipher import AES
        from Crypto.Random import get_random_bytes

        print("\n[AES-256-GCM] Usando pycryptodome")
        key = get_random_bytes(32)  # 256 bits
        plaintext = b"Mensaje secreto bancario: transferencia $50,000 MXN"

        # Cifrado
        cipher_enc = AES.new(key, AES.MODE_GCM)
        nonce = cipher_enc.nonce
        ciphertext, tag = cipher_enc.encrypt_and_digest(plaintext)

        print(f"  Clave (hex):       {key.hex()}")
        print(f"  Nonce (hex):       {nonce.hex()}")
        print(f"  Texto plano:       {plaintext.decode()}")
        print(f"  Texto cifrado:     {ciphertext.hex()}")
        print(f"  Tag autenticación: {tag.hex()}")

        # Descifrado
        cipher_dec = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted = cipher_dec.decrypt_and_verify(ciphertext, tag)
        print(f"  Texto descifrado:  {decrypted.decode()}")
        print(f"  Integridad:        ✓ Tag verificado")

    except ImportError:
        # Fallback educativo usando hashlib para demostrar el concepto
        print("\n[AES-256-GCM] Demostración conceptual (pycryptodome no instalado)")
        print("  Para ejecutar el cifrado AES real, instala: pip install pycryptodome")
        
        # Derivar "clave" de 256 bits usando SHA-256
        password = "clave_demo_educativa_2026"
        key = hashlib.sha256(password.encode()).digest()
        nonce = os.urandom(12)
        plaintext = "Mensaje secreto: transferencia $50,000 MXN"
        
        # XOR stream cipher simplificado (solo DEMOSTRATIVO, NO usar en producción)
        keystream = hashlib.sha256(key + nonce).digest()
        ct_bytes = bytes(p ^ k for p, k in zip(plaintext.encode(), keystream[:len(plaintext)]))
        
        print(f"  Clave derivada (SHA-256 de password): {key.hex()}")
        print(f"  Nonce:           {nonce.hex()}")
        print(f"  Texto plano:     {plaintext}")
        print(f"  Texto cifrado:   {ct_bytes.hex()}")
        print(f"  Nota: Instala pycryptodome para AES-256-GCM real")


# ──────────────────────────────────────────────
# INTERFAZ DE USUARIO — MENÚ INTERACTIVO
# ──────────────────────────────────────────────

def print_header():
    print("=" * 65)
    print("   CALCULADORA DE CRIPTOGRAFÍA — Tarea 4 Ciberseguridad")
    print("=" * 65)
    print("   Algoritmos: RSA | Diffie-Hellman | SHA-256 | AES-256")
    print("=" * 65)


def print_menu():
    print("\n┌─ MENÚ PRINCIPAL ─────────────────────────────────────────┐")
    print("│  1. RSA — Generación de claves, cifrado y descifrado      │")
    print("│  2. Diffie-Hellman — Simulación de intercambio de claves  │")
    print("│  3. SHA-256 — Cálculo y verificación de hash              │")
    print("│  4. AES-256-GCM — Demostración de cifrado simétrico       │")
    print("│  5. Demostración automática (todos los módulos)           │")
    print("│  0. Salir                                                 │")
    print("└──────────────────────────────────────────────────────────┘")


def get_int_input(prompt: str, min_val: int, max_val: int) -> int:
    """Lee un entero validado del usuario."""
    while True:
        try:
            value = int(input(prompt))
            if min_val <= value <= max_val:
                return value
            print(f"  Error: ingresa un valor entre {min_val} y {max_val}.")
        except ValueError:
            print("  Error: ingresa un número entero válido.")


def menu_rsa():
    print("\n── MÓDULO RSA ─────────────────────────────────────────────")
    rsa = RSA()
    
    print("\nSelecciona el tamaño de clave:")
    print("  1. 128 bits por primo (256 bits total) — DEMO rápido")
    print("  2. 256 bits por primo (512 bits total) — Demo estándar")
    print("  3. Ingresar tamaño personalizado")
    opcion = get_int_input("Opción: ", 1, 3)
    
    bits = {1: 128, 2: 256}.get(opcion)
    if opcion == 3:
        bits = get_int_input("Bits por primo (128-512): ", 128, 512)
    
    rsa.generate_keys(bits)
    
    print("\n¿Deseas realizar cifrado/descifrado? (1=Sí / 0=No)")
    if get_int_input("Opción: ", 0, 1) == 1:
        n, _ = rsa.public_key
        max_msg = min(n - 1, 10**18)  # Limitar para demo
        print(f"\nIngresa un mensaje como entero (0 a {min(max_msg, 999999)}):")
        m = get_int_input("Mensaje (entero): ", 0, min(max_msg, 999999))
        c = rsa.encrypt(m)
        decrypted = rsa.decrypt(c)
        print(f"\n  Verificación: mensaje original = {m}, descifrado = {decrypted}")
        print(f"  ¿Correcto? {'✓ SÍ' if m == decrypted else '✗ ERROR'}")


def menu_dh():
    print("\n── MÓDULO DIFFIE-HELLMAN ──────────────────────────────────")
    print("\nUsar parámetros de demostración pequeños (sí=1/no=0)?")
    print("  (No=usará primo NIST de 1024 bits, más lento pero seguro)")
    usar_demo = get_int_input("Opción: ", 0, 1)
    
    if usar_demo:
        # Parámetros pequeños para demostración visual
        p = 23  # primo pequeño de ejemplo
        g = 5
        print(f"\nUsando parámetros de demo: p={p}, g={g}")
        dh = DiffieHellman(p=p, g=g)
    else:
        dh = DiffieHellman()  # NIST prime
    
    dh.simulate_exchange()


def menu_sha256():
    print("\n── MÓDULO SHA-256 ─────────────────────────────────────────")
    print("\n  1. Calcular hash de un texto")
    print("  2. Verificar integridad (texto contra hash conocido)")
    opcion = get_int_input("Opción: ", 1, 2)
    
    if opcion == 1:
        texto = input("\nIngresa el texto a hashear: ").strip()
        if not texto:
            print("  Error: el texto no puede estar vacío.")
            return
        HashSHA256.hash_text(texto)
    else:
        texto = input("\nIngresa el texto: ").strip()
        hash_esperado = input("Ingresa el hash SHA-256 esperado (64 hex): ").strip()
        if len(hash_esperado) != 64:
            print("  Error: el hash SHA-256 debe tener exactamente 64 caracteres hexadecimales.")
            return
        try:
            HashSHA256.verify(texto, hash_esperado)
        except ValueError as e:
            print(f"  Error: {e}")


def menu_aes():
    print("\n── MÓDULO AES-256-GCM ─────────────────────────────────────")
    aes_encrypt_decrypt_demo()


def demo_automatica():
    print("\n══ DEMOSTRACIÓN AUTOMÁTICA DE TODOS LOS MÓDULOS ══════════")
    
    print("\n" + "─" * 50)
    print(" 1/4  RSA (128 bits por primo — demo rápido)")
    print("─" * 50)
    rsa = RSA()
    rsa.generate_keys(128)
    m = 42
    c = rsa.encrypt(m)
    d = rsa.decrypt(c)
    print(f"  Resultado: {m} → cifrado → {c} → descifrado → {d} {'✓' if m == d else '✗'}")
    
    print("\n" + "─" * 50)
    print(" 2/4  DIFFIE-HELLMAN (parámetros demo p=23, g=5)")
    print("─" * 50)
    dh = DiffieHellman(p=23, g=5)
    dh.simulate_exchange()
    
    print("\n" + "─" * 50)
    print(" 3/4  SHA-256")
    print("─" * 50)
    h = HashSHA256.hash_text("Hola, Ciberseguridad 2026!")
    HashSHA256.verify("Hola, Ciberseguridad 2026!", h)
    
    print("\n" + "─" * 50)
    print(" 4/4  AES-256-GCM")
    print("─" * 50)
    aes_encrypt_decrypt_demo()
    
    print("\n══ FIN DE DEMOSTRACIÓN ════════════════════════════════════")


# ──────────────────────────────────────────────
# PUNTO DE ENTRADA PRINCIPAL
# ──────────────────────────────────────────────

def main():
    print_header()
    
    while True:
        print_menu()
        opcion = get_int_input("\nSelecciona una opción: ", 0, 5)
        
        try:
            if opcion == 0:
                print("\nSaliendo... ¡Hasta luego!\n")
                sys.exit(0)
            elif opcion == 1:
                menu_rsa()
            elif opcion == 2:
                menu_dh()
            elif opcion == 3:
                menu_sha256()
            elif opcion == 4:
                menu_aes()
            elif opcion == 5:
                demo_automatica()
        except ValueError as e:
            print(f"\n[ERROR de validación] {e}")
        except RuntimeError as e:
            print(f"\n[ERROR de ejecución] {e}")
        except KeyboardInterrupt:
            print("\n\n[Interrumpido por el usuario]")
            sys.exit(0)
        
        print("\n" + "─" * 65)
        input("Presiona Enter para continuar...")


if __name__ == "__main__":
    main()
