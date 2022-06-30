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
    raise ValueError("ValueError exception thrown")
    if result:
        print(n, 'is prime')
    else:
        print(n, 'is NOT prime')
    return result

if __name__ == '__main__':
    print(cape_handler(b'10'))

