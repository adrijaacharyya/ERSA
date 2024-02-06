## essential libraries
import base64
from newRSA import *
from essentials import essentials

e = essentials()

### update padding
def getPadSize(charStr, bufferSize):
  binLen = len(charStr) * 8
  count = 0
  reqSize = binLen
  while True:
    rem = reqSize % bufferSize
    if rem:
      count += 1
      reqSize = 8*count + binLen
    else:
      break
  padSize = (reqSize - binLen) // 8
  # handling NO padding
  padSize = reqSize if padSize==0 else padSize
  return padSize


def setBlockSize(key):
  # checking for bit-size of 'n'
  n = key[1]
  binN = largestOnes(n)
  # setting block and data size in bits
  dataLimitSize = len(binN) - 1 # size of largest msg int
  blockSize = len(binN) + 1 # size of 'n'
  return dataLimitSize, blockSize


def encString(RSA, data, pubKey):
  # setting block and data size in bits
  dataLimitSize, blockSize = setBlockSize(pubKey)
  #######################
  # base64 conversion
  data_BS64 = e.secretPostProcess(data)
  # padding processing
  padSize = getPadSize(data_BS64, dataLimitSize)
  paddedData = e.addPadding(data_BS64, padSize)
  ## get bin
  binData = e.strToBin(paddedData)
  ## split in blocks
  msgBlocks = [binData[i:i+dataLimitSize] for i in range(0, len(binData), dataLimitSize)] 
  #######################
  ## block-wise encryption using RSA
  encBlocks = []
  for block in msgBlocks:
    intBlock = int(block, 2)
    blockENC = RSA.encrypt(intBlock, pubKey)
    blockENC_Bin = format(blockENC, '0'+str(blockSize)+'b')
    encBlocks.append(blockENC_Bin)
  #######################
  ## final bin ciphertext
  cipherString = ''.join(encBlocks)
  return cipherString


def decString(RSA, enc, pvtKey):
  # setting block and data size in bits
  dataLimitSize, blockSize = setBlockSize(pvtKey)
  # split in blocks
  encBlocks = [enc[i:i+blockSize] for i in range(0, len(enc), blockSize)]
  ## block-wise decryption using RSA
  decBlocks = []
  for block in encBlocks:
    intBlock = int(block,2)
    blockDEC = RSA.decrypt(intBlock, pvtKey)
    blockDEC_Bin = format(blockDEC, '0'+str(dataLimitSize)+'b')
    decBlocks.append(blockDEC_Bin)
  ## final bin decryptedtext
  pt = ''.join(decBlocks)
  ## binary to string conversion
  strData = e.binToStr(pt)
  plainString = e.remPadding(strData)
  # base64 to byte conversion
  plainString = e.secretPreProcess(plainString)
  return plainString


#########     D-H Key Exchange      ##########

def setK(q, alpha, theirPub, yourPvt=None):
  if yourPvt is None: # step-3
    yourPvt = int(input("Enter your private key: "))
  yourPub = (alpha * yourPvt) % q # step-3
  print("Your public key is: ", yourPub)
  yourK = (theirPub * yourPvt) % q # step-4
  return yourK

def DH_KeyX(pvt1, pvt2, q=None):
  if q is None:
    q = int(input("Enter a prime number (keep small): ")) # step-1
  alpha = getPremRoot(q) # step-2
  #########################
  yourPub = (alpha ** xPvt) % q
  theirPub = (alpha ** yPvt) % q
  #########################
  K1 = setK(q, alpha, theirPub, pvt1)
  K2 = setK(q, alpha, yourPub, pvt2)
  print(f"K1: {K1} \tK2: {K2}")
  #########################
  result = 'successful!' if K1==K2 else 'NOT successful!'
  print(f"Key exchange was {result}")
  return


#############################################################################
#############################################################################


# inheriting essential classes
class dynamicRSA(essentials):
  def __init__(self, p, q, K=3):
    super().__init__()
    self.__p = p
    self.__q = q
    self.__K = K
    self.__z = self.crossover(p,q)
    self.__pubKey = None
    self.__prvKey = None
    self.__RSA_keygen()
  
  ###################################################
  def crossover(self, p: int, q:int):
    max = p if p > q else q
    min = p if p < q else q
    maxNew = self.decimal_to_base(max, min)
    prime = self.base_to_decimal(maxNew, 10)
    return prime
  
  def decimal_to_base(self,decimal_number, base):
    if not (isinstance(decimal_number, int) and isinstance(base, int)):
        raise ValueError("Both arguments must be integers")
    
    if base < 2 or base > 62:
        raise ValueError("Base must be between 2 and 62 inclusive")
    
    if decimal_number == 0:
        return '0'
    
    result = ''
    negative = False
    
    if decimal_number < 0:
        negative = True
        decimal_number = abs(decimal_number)
    
    digits = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    
    while decimal_number > 0:
        remainder = decimal_number % base
        result = digits[remainder] + result
        decimal_number //= base
    
    if negative:
        result = '-' + result
    
    return result
  
  def base_to_decimal(self,number, base):
    if not isinstance(number, str) or not isinstance(base, int):
        raise ValueError("Invalid input types. Number should be a string and base should be an integer.")

    if base < 2 or base > 62:
        raise ValueError("Base must be between 2 and 62 inclusive.")

    characters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    number = number[::-1]  # Reverse the number string for easier processing
    decimal_result = 0

    for i, digit in enumerate(number):
        if digit not in characters[:base]:
            raise ValueError(f"Invalid digit '{digit}' for base {base}.")

        decimal_result += characters.index(digit) * (base ** i)

    return decimal_result
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
      # step 1 : to get p and q
      n = self.__p * self.__q # step-2
      phi_n = (self.__p-1) * (self.__q-1) * (self.__z - 1) # step-3
      Es = self.__getCoPrime(phi_n, k) # step-4
      if len(Es) > 1:
        e = int(input(f"Choose a generator among {Es}: ")) # step-4
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
  # def RSA_keygen(self,p,q,z):
  #       n = p*q
  #       phi_n = (p-1)*(q-1)*(z-1)
  #       vals = self.getCoPrime(phi_n,3)
  #       while True:
  #           print(vals)
  #           ch = int(input('Choose among these: '))
  #           if ch not in vals:
  #               print('Choose a valid value.')
  #           else:
  #               break
  #       e = ch
  #       d = 2
  #       while True:
  #           checkval = e*d%phi_n
  #           if checkval == 1:
  #               break
  #           else:
  #               d+=1
  #       Public_Key = [e,n]
  #       Private_Key = [d,n]
  ###################################################

  ### updated
  def __getPadSize(self, charStr, bufferSize):
    BYTESIZE = 8
    binLen = len(charStr) * BYTESIZE
    count = 0
    reqSize = binLen
    while True:
      rem = reqSize % bufferSize
      if rem:
        count += 1
        reqSize = BYTESIZE*count + binLen
      else:
        break
    padSize = (reqSize - binLen) // BYTESIZE
    # handling NO padding
    padSize = reqSize if padSize==0 else padSize
    return padSize
  
  def __setBlockSize(self, key):
    # checking for bit-size of 'n'
    n = key[1]
    binN = largestOnes(n)
    # setting block and data size in bits
    dataLimitSize = len(binN) - 1 # size of largest msg int
    blockSize = len(binN) + 1 # size of 'n'
    return dataLimitSize, blockSize
  
  ###################################################
  
  def getPublicKey(self):
    pubKey = self.__pubKey
    return pubKey
  
  # encryption using RSA
  def encNumber(self, plainData, key=None):
    if key is None:
      key = self.getPublicKey()
    # encryption
    exp, n = key # pubKey
    ciphertext = plainData**exp % n
    return ciphertext

  # decryption using RSA
  def decNumber(self, hiddenData, key=None):
    if key is None:
      key = self.__prvKey
    # decryption
    exp, n = key # prvKey
    decrypted = hiddenData**exp % n
    return decrypted

  ####################################################

  def encrypt(self, data, pubKey=None):
    if pubKey is None:
      pubKey = self.getPublicKey()
    # setting block and data size in bits
    dataLimitSize, blockSize = self.__setBlockSize(pubKey)
    #######################
    # base64 conversion
    data_BS64 = self.secretPostProcess(data)
    # padding processing
    padSize = self.__getPadSize(data_BS64, dataLimitSize)
    paddedData = self.addPadding(data_BS64, padSize)
    ## get bin
    binData = self.strToBin(paddedData)
    ## split in blocks
    msgBlocks = [binData[i:i+dataLimitSize] for i in range(0, len(binData), dataLimitSize)] 
    #######################
    ## block-wise encryption using RSA
    encBlocks = []
    for block in msgBlocks:
      intBlock = int(block, 2)
      blockENC = self.encNumber(intBlock, pubKey)
      blockENC_Bin = format(blockENC, '0'+str(blockSize)+'b')
      encBlocks.append(blockENC_Bin)
    #######################
    ## final bin ciphertext
    cipherString = ''.join(encBlocks)
    return cipherString
  
  def decrypt(self, enc, pvtKey=None):
    if pvtKey is None:
      pvtKey = self.__prvKey
    # setting block and data size in bits
    dataLimitSize, blockSize = self.__setBlockSize(pvtKey)
    # split in blocks
    encBlocks = [enc[i:i+blockSize] for i in range(0, len(enc), blockSize)]
    ## block-wise decryption using RSA
    decBlocks = []
    for block in encBlocks:
      intBlock = int(block,2)
      blockDEC = self.decNumber(intBlock, pvtKey)
      blockDEC_Bin = format(blockDEC, '0'+str(dataLimitSize)+'b')
      decBlocks.append(blockDEC_Bin)
    ## final bin decryptedtext
    pt = ''.join(decBlocks)
    ## binary to string conversion
    strData = self.binToStr(pt)
    plainString = self.remPadding(strData)
    # base64 to byte conversion
    plainString = self.secretPreProcess(plainString)
    return plainString

test = dynamicRSA(5,17)
ct = test.encrypt('I am Adrija. My reg number is 221007.')
print(ct)
pt = test.decrypt(ct)
print(pt)