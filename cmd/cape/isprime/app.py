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

def cape_handler(arg):
    n = int(arg)
    result = isprime(n)
    if result:
        ret = f"{n} is prime"
    else:
        ret = f"{n} is NOT prime"
    return ret
