################

## Euclid's algorithm, efficient implementation
def gcdEA(a, b):
  assert a >= 0 and b >= 0 and a + b > 0

  while a > 0 and b > 0:
    if a >= b:
      a = a % b
    else:
      b = b % a

  return max(a, b)

####################################################################
####################################################################

# Extended Euclid's Algorithm
def extendedGCD(a, b):
  try:
    assert a >= b and b >= 0 and a + b > 0

    if b == 0:
      gcd, x, y = a, 1, 0
    else:
      (gcd, p, q) = extendedGCD(b, a % b)
      x = q
      y = p - q * (a // b)

    assert a % gcd == 0 and b % gcd == 0
    assert gcd == a * x + b * y
    return (gcd, x, y)
  except:
    print("Some error occured!!")
    return False

