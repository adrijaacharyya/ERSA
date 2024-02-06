import base64

####
class essentials:
  def __init__(self, PAD='\x00'):
    self.BYTE_SIZE = 8
    self.PAD=PAD
    return
  
  # XOR of two integers
  def XOR(self, data1:int, data2: int):
    return data1^data2

  ########################################

  # padding plaintext, as per the key
  def getPadSize(self, plaintext:str, key:str):
    # size of padding
    rem = len(plaintext) % len(key)
    padSize = len(key) - rem
    return padSize

  def padInfo(self, plaintext:str, padSize:int):
    # appending the pad
    paddedData = plaintext + self.PAD*padSize
    return paddedData
  
  ###################
  def addPadding(self, plaintext:str, padSize:int):
    # appending the pad
    self.PAD = chr(0|(padSize))
    paddedData = plaintext + self.PAD*padSize
    return paddedData

  def remPadding(self, plaintext:str):
    padSize = ord(plaintext[-1])
    # removing the pad
    originalText = plaintext[:-padSize]
    return originalText
  ###################
  
  def setKey(self, keyString:str, keySize:int):
    # bit-size to byte-size
    keySize //= self.BYTE_SIZE  # GRABING INT VALUE
    # adding padding to short key
    if len(keyString) < keySize:
      keyString = self.padInfo(keyString, keySize-len(keyString))
    # cliping lengthy key
    elif len(keyString) > keySize:
      keyString = keyString[:keySize]
    # returning final key
    return keyString

  def secretPostProcess(self, data:str):
    if type(data) != bytes:
      # convert to bytes
      data = data.encode()
    # convert to printable char
    bs4Bytes = base64.b64encode(data)
    try:
      rawData = bs4Bytes.decode()
    except:
      rawData = bs4Bytes
    # returning processed Raw Data
    return rawData

  def secretPreProcess(self, rawData:str):
    if type(rawData) != bytes:
      # convert to bytes
      rawData = rawData.encode()
    # convert to printable char i.e. into Base-64 format
    rawBytes = base64.b64decode(rawData)
    try:
      data = rawBytes.decode()
    except:
      data = rawBytes
    # returning processed Raw Data
    return data

  def stringXOR(self, s1:str,s2:str):
    ciphertext = ""
    for i,j in zip(s1,s2):
      xorRes = self.XOR(ord(i),ord(j))
      ciphertext += chr(xorRes)
    return ciphertext
  
  def binXOR(self, binVal1, binVal2):
    # from previous weeks
    xr = self.stringXOR(binVal1,binVal2)
    # bytestring to bin-string
    xorBins = ''
    for val in xr:
      xorBins += format(ord(val),'01b')
    # return results
    return xorBins

  ## ascii to bin-str
  def strToBin(self, strData, bitSize=8):
    # if user gives int or other data
    strData = str(strData)
    # binary value holder
    binData = ''
    # scan each char of PT
    for ch in strData:
      # convert each char
      binCh = format(ord(ch), '0'+str(bitSize)+'b')  
      # add each char's bin value
      binData += binCh
    # return final binary translation
    return binData

  ## bin-str to ascii
  def binToStr(self, binStr):
    ## convert CT to readable ASCII string
    asciiStr = ''
    beg = 0
    BYTE_SIZE = 8
    for end in range(BYTE_SIZE, len(binStr)+1, BYTE_SIZE):
      charBin = binStr[beg:end]   # take binary byte (8 bits)
      intVal = int(charBin, 2)
      asciiStr += chr(intVal)
      # update beg
      beg = end
    ## final ascii str
    return asciiStr