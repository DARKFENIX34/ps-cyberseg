from zope.interface import named

memoria = {}
def fibonacci_optimizado(n):
    if n <= 1:
        return n
    if n not in memoria:
        memoria[n] = fibonacci_optimizado(n - 1) + fibonacci_optimizado(n - 2)
    return memoria[n]
z= int(input("ingrese un numero"))
for i in range(z):
    resultado = fibonacci_optimizado(i)
    print(f"\nFibonacci optimizado {i}: {resultado}")