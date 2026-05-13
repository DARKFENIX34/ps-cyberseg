#!/usr/bin/env python3
"""
=============================================================
  Práctica: Big O — Problema 1: Concurso de Rimas
  Ciberseguridad — Mayo 2026
=============================================================

ENUNCIADO:
  En un concurso de rimas se inscriben parejas para concursar.
  El objetivo es hacer la mayor cantidad de rimas posibles,
  solo que las rimas deben ser de exactamente 3 palabras y en
  cada rima cada concursante debe decir por lo menos una palabra.
  Dada la cantidad de palabras para cada concursante, encuentre
  la cantidad de rimas máximas que pueden hacer.

ANÁLISIS:
  - Cada rima tiene exactamente 3 palabras.
  - Cada concursante debe decir AL MENOS 1 palabra por rima.
  - Sea A = palabras del concursante 1, B = palabras del concursante 2.
  - En cada rima: concursante 1 dice 'a' palabras y concursante 2 dice 'b'
    donde a >= 1, b >= 1, a + b = 3.
  - Las posibles distribuciones por rima son: (1,2) o (2,1).
  - Si usamos distribución (1,2): rimas_posibles = min(A, B//2)
    (A limita por palabras del concursante 1, B//2 limita por el 2)
    Más precisamente: rimas = min(A, floor(B/2)) cuando cada rima usa 1 de A y 2 de B,
    pero hay que maximizar, entonces buscamos la distribución óptima.

  FORMULACIÓN CORRECTA:
  Queremos maximizar R (número de rimas) tal que:
    a_i >= 1, b_i >= 1, a_i + b_i = 3 para cada rima i
    Σ a_i <= A,   Σ b_i <= B
  
  Si en cada rima usamos exactamente (a, b) = (1,2) o (2,1):
  Caso 1: x rimas con (1,2), y rimas con (2,1), R = x + y
    x + 2y <= A   →   2x + y <= B... 
  
  SIMPLIFICACIÓN:
  Lo que realmente limita es que por cada rima se consumen 3 palabras totales.
  El total máximo de palabras disponibles = A + B.
  El máximo de rimas por palabras totales = floor((A+B) / 3).
  Pero también cada concursante necesita al menos 1 por rima:
    A >= R  y  B >= R  →  R <= min(A, B)
  
  RESPUESTA: R = min(floor((A+B)/3), min(A, B)) = min((A+B)//3, A, B)

  COMPLEJIDAD: O(1) — solución de fórmula directa.

=============================================================
"""

import sys


def max_rimas(palabras_a: int, palabras_b: int) -> int:
    """
    Calcula el número máximo de rimas de 3 palabras que puede hacer
    una pareja donde cada uno dice al menos 1 palabra por rima.

    Parámetros:
        palabras_a (int): número de palabras disponibles del concursante A
        palabras_b (int): número de palabras disponibles del concursante B

    Retorna:
        int: número máximo de rimas posibles

    Complejidad: O(1) — solución de fórmula cerrada.

    Razonamiento:
        - Cada rima requiere 3 palabras en total.
        - Cada concursante debe aportar >= 1 por rima.
        - Restricción 1 (palabras totales): R <= (A + B) // 3
        - Restricción 2 (concursante A): R <= A  (necesita >= 1 por rima)
        - Restricción 3 (concursante B): R <= B  (necesita >= 1 por rima)
        - Resultado: R = min((A+B)//3, A, B)
    """
    if palabras_a < 0 or palabras_b < 0:
        raise ValueError("Las palabras no pueden ser negativas.")
    if not isinstance(palabras_a, int) or not isinstance(palabras_b, int):
        raise TypeError("Las palabras deben ser números enteros.")

    return min((palabras_a + palabras_b) // 3, palabras_a, palabras_b)


def validate_inputs(a_str: str, b_str: str):
    """
    Valida y convierte las entradas del usuario.
    Retorna (a, b) como enteros o lanza ValueError con mensaje descriptivo.
    """
    try:
        a = int(a_str)
        b = int(b_str)
    except ValueError:
        raise ValueError("Ambos valores deben ser números enteros.")

    if a < 0 or b < 0:
        raise ValueError("El número de palabras no puede ser negativo.")

    return a, b


def main():
    print("=" * 55)
    print("  CONCURSO DE RIMAS — Máximo de rimas posibles")
    print("=" * 55)
    print()
    print("  Reglas:")
    print("  • Cada rima tiene exactamente 3 palabras.")
    print("  • Cada concursante dice al menos 1 palabra por rima.")
    print()
    print("  Ingresa 0 para ambos concursantes para salir.")
    print()

    while True:
        try:
            entrada_a = input("  Palabras del concursante A: ").strip()
            entrada_b = input("  Palabras del concursante B: ").strip()

            a, b = validate_inputs(entrada_a, entrada_b)

            if a == 0 and b == 0:
                print("\n  Saliendo. ¡Hasta luego!")
                break

            resultado = max_rimas(a, b)

            print()
            print(f"  A = {a}, B = {b}")
            print(f"  Restricción total:  (A+B)//3 = ({a}+{b})//3 = {(a+b)//3}")
            print(f"  Restricción A:      A = {a}")
            print(f"  Restricción B:      B = {b}")
            print(f"  ──────────────────────────────────────")
            print(f"  Rimas máximas: min({(a+b)//3}, {a}, {b}) = {resultado}")
            print()

        except ValueError as e:
            print(f"\n  [ERROR] {e}\n")
        except KeyboardInterrupt:
            print("\n\n  Interrumpido. ¡Hasta luego!")
            sys.exit(0)


if __name__ == "__main__":
    # Si hay argumentos de línea de comando, ejecutar modo batch
    if len(sys.argv) == 3:
        try:
            a, b = validate_inputs(sys.argv[1], sys.argv[2])
            print(max_rimas(a, b))
        except (ValueError, TypeError) as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        main()
