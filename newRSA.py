## essential libraries
from gcd import gcdEA, extendedGCD

## co-prime calc
def getCoPrime(K,N):
  if K > N:
    coPrimes = []
    checkNum = 2
    while checkNum < K:
      gotGcd, _, _ = extendedGCD(K, checkNum)
      CP = gotGcd if (gotGcd==1) else False
      if CP:
        coPrimes.append(checkNum)
      if len(coPrimes) == N:
        break
      else:
        checkNum += 1
    return coPrimes
  else:
    print(f"N can't be greater than {K}!! \nTry Again...")
    return False


## premitive root calc
def getPremRoot(num):
  R = 2
  # universal set
  universal = set([s for s in range(1, num)])
  newSet = []
  while R < num:
    for x in range(1, num):
      result = (R**x) % num
      newSet.append(result)
    newSet = set(newSet)
    #print(newSet)
    if universal == newSet:
      return R
    else:
      R += 1
      newSet = []
  return False

## alculate 'd' for RSA Key-pair
def getD(e, phi):
  thisD = 2
  while True:
    checkVal = e*thisD % phi
    if checkVal == 1:
      break
    else:
      thisD += 1
  return thisD

def getKeys(n, e, d):
  pubKey = [e, n]
  prvKey = [d, n]
  return pubKey, prvKey

############################

############################
#########    RSA   #########
############################
def RSA_keygen(k=3):
  try:
    # step 1
    p = int(input("Enter a value for 'p': "))
    q = int(input("Enter a value for 'q': "))
    n = p * q # step-2
    phi_n = (p-1) * (q-1) # step-3
    Es = getCoPrime(phi_n, k) # step-4
    e = int(input(f"Choose one among {Es}: ")) # step-4
    d = getD(e, phi_n) # step-5
    pubKey, prvKey = getKeys(n, e, d) #  step-6
    return pubKey, prvKey
  except:
    return False

# encryption using RSA
def encRSA(plainData, key):
  exp, n = key # prvKey
  ciphertext = plainData**exp % n
  return ciphertext

# decryption using RSA
def decRSA(hiddenData, key):
  exp, n = key # prvKey
  decrypted = hiddenData**exp % n
  return decrypted




#################################################
#################################################
class newRSA:
  def __init__(self, p, q, K=3):
    self.__p = p
    self.__q = q
    self.__K = K
    self.__pubKey = None
    self.__prvKey = None
    self.__RSA_keygen()
  
  ## co-prime calc
  def __getCoPrime(self, K, N):
    if K > N:
      coPrimes = []
      checkNum = 2
      while checkNum < K:
        gotGcd, _, _ = extendedGCD(K, checkNum)
        CP = gotGcd if (gotGcd==1) else False
        if CP:
          coPrimes.append(checkNum)
        if len(coPrimes) == N:
          break
        else:
          checkNum += 1
      return coPrimes
    else:
      print(f"N can't be greater than {K}!! \nTry Again...")
      return False

  ## alculate 'd' for RSA Key-pair
  def __getD(self, e, phi):
    thisD = phi//e # initially 'e*d' must be greater than phi(n)
    while True:
      checkVal = e*thisD % phi
      if checkVal == 1:
        break
      else:
        thisD += 1
    return thisD

  def __setKeys(self, n, e, d):
    self.__pubKey = [e, n]
    self.__prvKey = [d, n]
    return True

  def __RSA_keygen(self, k=None):
    try:
      if k is None:
        k=self.__K
      # step 1
      #p = int(input("Enter a value for 'p': "))
      #q = int(input("Enter a value for 'q': "))
      n = self.__p * self.__q # step-2
      phi_n = (self.__p-1) * (self.__q-1) # step-3
      Es = self.__getCoPrime(phi_n, k) # step-4
      if len(Es) > 1:
        e = int(input(f"Choose one among {Es}: ")) # step-4
      else:
        e = Es[0]
      if e <= 1:
        print("e must follow:  '1 < e < phi(n)'")
        return False
      d = self.__getD(e, phi_n) # step-5
      self.__setKeys(n, e, d) #  step-6
      return True
    except:
      return False
  
  ############################

  def getPublicKey(self):
    pubKey = self.__pubKey
    return pubKey
  
  # encryption using RSA
  def encrypt(self, plainData, key=None):
    if key is None:
      key = self.getPublicKey()
    # encryptaion
    exp, n = key # pubKey
    ciphertext = plainData**exp % n
    return ciphertext

  # decryption using RSA
  def decrypt(self, hiddenData, key=None):
    if key is None:
      key = self.__prvKey
    # decryption
    exp, n = key # prvKey
    decrypted = hiddenData**exp % n
    return decrypted


###

def largestOnes(N):
  updateBin = lambda c: int('1'*c, 2)
  ## start
  count = 1
  thisNum = updateBin(count)
  while True:
    if N <= thisNum:
      count -= 1
      thisNum = updateBin(count)
      break
    count += 1
    thisNum = updateBin(count)
  ## getting bin
  L = format(thisNum, '1b')
  return L
