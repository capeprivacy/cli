import math


def isprime(n):
    if n < 2:
        return False
    if n == 2:
        return True
    for i in range(2, int(math.sqrt(n))):
        if n % i == 0:
            return False
    return True

def cape_handler(n):
    result = isprime(n)
    if result:
        print(f"{n} is prime")
    else:
        print(f"{n} is NOT prime")
    return result
