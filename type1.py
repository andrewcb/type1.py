'''A Python module for generating Type 1 fonts.

'''

# $Id: type1.py,v 0.1 2000/06/27 08:39:23 acb Exp acb $

import string
import re
import random

# encode a number as a string of chars

def csEncodeNum(num):
  '''Given an integer, return a string of 1-5 characters representing its Type 1
     charstring encoding.'''
  if(num>=-107 and num<=107):
    return chr(num+139)
  elif(num>=108 and num<=1131):
    return chr(((num-108)>>8)+247)+chr((num-108)&0xff)
  elif(num>=-1131 and num<=-108):
    num = -num
    return chr(((num-108)>>8)+251)+chr((num-108)&0xff)
  elif(num>0):
    return chr(255)+chr(num>>24)+chr((num&0xffffff)>>16)+chr((num&0xffff)>>8)+chr(num&0xff)
  else:	# negative number
    num=(-num)-1
    return chr(255)+chr((num>>24)^0xff)+chr(((num&0xffffff)>>16)^0xff)+chr(((num&0xffff)>>8)^0xff)+chr((num&0xff)^0xff)

def csDecodeNum(str):
  '''Assuming that str starts with a Type 1 encoded numeric value, decodes
  this value to an integer and returns a tuple containing it and the rest
  of the string'''
  b = map(ord, str[:5])
  if b[0]<247:
    return (b[0]-139, str[1:])
  elif b[0]<251:
    return ((((b[0]-247)<<8) | b[1]) + 108, str[2:])
  elif b[0]<255:
    return (-(((b[0]-251)<<8) | b[1]) - 108, str[2:])
  elif b[0]==255:
    return (b[1]<<24 | b[2]<<16 | b[3]<<8 | b[4], str[5:])
  else:
    raise 'InternalError', "csDecodeNum called for non-numeric string"

charstring_cmd_encode = {
  'hstem'      : '\x01', 'vstem'      : '\x03', 'vmoveto'    : '\x04',
  'rlineto'    : '\x05', 'hlineto'    : '\x06', 'vlineto'    : '\x07',
  'rrcurveto'  : '\x08', 'closepath'  : '\x09', 'callsubr'   : '\x0a',
  'return'     : '\x0b', 'hsbw'       : '\x0d', 'endchar'    : '\x0e',
  'rmoveto'    : '\x15', 'hmoveto'    : '\x16', 'vhcurveto'  : '\x1e',
  'hvcurveto'  : '\x1f',
  'dotsection'      : '\x0c\x00', 'vstem3'          : '\x0c\x01',
  'hstem3'          : '\x0c\x02', 'seac'            : '\x0c\x06',
  'sbw'             : '\x0c\x07', 'div'             : '\x0c\x0c',
  'callothersubr'   : '\x0c\x10', 'pop'             : '\x0c\x11',
  'setcurrentpoint' : '\x0c\x21'
}

charstring_cmd_decode = {}
for name in charstring_cmd_encode.keys():
  charstring_cmd_decode[charstring_cmd_encode[name]] = name

# return a tuple containing a token and the rest of the string
def csDecodeToken(str):
  if charstring_cmd_decode.has_key(str[0]):
    return (charstring_cmd_decode[str[0]], str[1:])
  elif charstring_cmd_decode.has_key(str[0:2]):
    return (charstring_cmd_decode[str[0:2]], str[2:])
  elif ord(str[0])>=32:
    return csDecodeNum(str)
  else:
    raise ValueError, "invalid bytes in encoded charstring"

# Compile a charstring, from whitespace-separated text to a string of bytes
# This does not perform encryption.

t1_re_num = re.compile("\-?[0-9]+(\.[0-9]+)?")

def csCompile(source):
  result=''
  for token in re.split('[ \n\t]+', source):
    # print "Token: %s"%token
    if(charstring_cmd_encode.has_key(token)):
      result = result + charstring_cmd_encode[token];
    elif t1_re_num.match(token):	# we assume it's a number.
      result = result + csEncodeNum(string.atoi(token))
    else:
      raise SyntaxError, "%s is not a valid Type 1 operator"%token
  return result

# decode a charstring to a list of tokens

def csDecode(cs):
  'Translate an encoded (unencrypted) charstring to a list of tokens.'
  tokens = []
  while len(cs)>0:
    (tok, cs) = csDecodeToken(cs)
    tokens.append(tok)
  return tokens

# decode a charstring to a string of source

def csDecompile(cs):
  "Disassemble a compiled (unencrypted) charstring to its source code, in Type 1 code."
  
  return string.join(map(str, csDecode(cs)))
  

# internal: given a plaintext char and a key, return a cyphertext char and 
#           the next key.


#  we need a multiplication function that will handle 16-bit unsigned
#  values without the overflow that 32-bit signed values can suffer from.

def u16mult(a,b):
  return ((a*(b&0x0fff)&0xffff)+(((a*(b>>12))&0x000f)<<12))&0xffff

def encryptChar(ch,r):
  ch = ord(ch)
  cypher = ch ^ (r>>8)
  r = (u16mult((cypher+r),52845) + 22719)&0xffff
  return (chr(cypher),r)

def decryptChar(ch,r):
  ch = ord(ch)
  plain = ch ^ (r>>8)
  r = (u16mult((ch+r), 52845) + 22719)&0xffff
  return (chr(plain),r)


# encrypt a charstring

def encrypt(cs,salt,key):
  r = key
  cs = ('\0'*salt)+cs
  result = ''
  for plainch in cs:
    (cypher,r) = encryptChar(plainch,r)
    result = result + cypher
  return result;

def csEncrypt(cs,salt=4):
  return encrypt(cs,salt,4330)

# do the eexec encryption

def eEncrypt(text):
  return encrypt(text,4,55665)


# a utility function for compiling and encrypting a charstring

def csMake(src):
  'Compile and encrypt a charstring in one step.'
  return csEncrypt(csCompile(src))

# given a string, emit it as hexadecimal bytes, 32 to a line

def eHexDump(str):
  result = '';
  while(len(str)>0):
    (frame,str) = (str[:32],str[32:])
    for ch in frame:
      result = result + "%02X"%ord(ch)
    result = result + "\n"
  return result

# utility functions for emitting PostScript definitions

# mappings from dictionary keys to print functions for the contents

def fmtStr(s):  return "(%s)"%s
def fmtName(s): return "/%s"%s
def fmtInt(d):  return "%d"%d

t1DictFmtStrings = {
  'version'            : fmtStr,
  'FullName'           : fmtStr,
  'FamilyName'         : fmtStr,
  'Weight'             : fmtStr,
  'ItalicAngle'        : fmtInt,
  'isFixedPitch'       : lambda b: ['true','false'][b==0],
  'UnderlinePosition'  : fmtInt,
  'UnderlineThickness' : fmtInt,
  'FontName'           : fmtName,
  'PaintType'          : fmtInt,
  'FontType'           : fmtInt,
  'FontMatrix'         : lambda a: '['+string.join(map(lambda f:"%f"%f,a))+']',
  'FontBBox'           : lambda a: '{'+string.join(map(lambda d:"%d"%d,a))+'}',
  'UniqueID'           : fmtInt,
  'BlueValues'         : lambda a: '['+string.join(map(lambda d:"%d"%d,a))+']',
  'MinFeature'         : lambda a: '{'+string.join(map(lambda d:"%d"%d,a))+'}',
  'password'           : fmtInt,
}

def emitDictContents(d,attr='readonly '):
  result=''
  for k in d.keys():
    v = d[k]
    if t1DictFmtStrings.has_key(k):
      vf = (t1DictFmtStrings[k])(v)
    else:
      if type(v) == type(1):
        vf = "%d"%v
      else:  # be lazy and assume it's a string
        vf = "(%s)"%v
    # FIXME: add 'readonly'/'noaccess' where appropriate
    result = result + "/%s %s %sdef\n"%(k,vf,attr)
  return result
    

#  the Type 1 font object itself
#  We make member names identical wherever possible to the PostScript
#  symbols.

class Type1Font:
  '''A class representing the internal representation of a Type 1 font object.'''
  def __init__(self, name="untitled"):
    self.CharStrings = {}
    self.Subrs = []
    self.OtherSubrs = []
    self.Encoding = 'StandardEncoding'
	# we can make this an array if we like... Ghod, I love Python... :-)

    # main dictionary
    self.MainDict = {
      'FontName' : name,
      'PaintType' : 0,
      'FontType' : 1,
      'FontMatrix' : [0.001, 0, 0, 0.001, 0, 0],
      'FontBBox' : [0, 0, 0, 0],
      'UniqueID' : random.randint(4000000,4999999),
    }

    # FontInfo stuff
    self.FontInfo = {
      'version' : '001.001',
      'FullName' : name,
      'FamilyName' : name,
      'Weight' : 'Medium',
      'ItalicAngle' : 0,
      'isFixedPitch' : 0,
      'UnderlinePosition' :  -98,
      'UnderlineThickness' : 54,
    }

    # private stuff
    self.Private = {
      'BlueValues' : [],
      'MinFeature' : [16,16],
      'password' : 5839,
      'lenIV' : 4,
      'UniqueID' : self.MainDict['UniqueID'],
    }

  def setCharacter(self, name, src):
    '''Set a character string in the font.  Arguments are:
    - name: the name in the CharStrings dictionary of the character
    - src: the source code of the character, in the PostScript subset used for
      Type 1 charstrings.'''
    self.CharStrings[name] = csMake(src)

  def copyCharacter(self, ex, to):
    '''Copy a character definition to a new character.'''
    self.CharStrings[to] = self.CharStrings[ex]

  def addSubr(self, src):
    '''Add a new entry to Subrs, returning its index. Arguments are:
    - src: the source code of the subroutine, in Type 1 code.'''
    self.Subrs.append(csMake(src))
    return len(self.Subrs)-1

  def setSubr(self, index, src):
    '''Set the contents of a Subrs entry to a compiled charstring.'''
    if len(self.Subrs)>index:
      self.Subrs[index] = csMake(src)
    else:
      while len(self.Subrs)<index:
        # pad it out with a 'null' subroutine
        self.Subrs.append(csMake('return'))
      self.Subrs.append(csMake(src))

  def setUniqueID(self, uid): 
    '''Set the font's UniqueID.  The required argument is the new ID.'''
    self.MainDict['UniqueId']=self.Private['UniqueID'] = uid

  def setBBox(self, ax, ay, bx, by):
    self.MainDict['FontBBox'] = [ax, ay, bx, by]

  def genPrivate(self):
    '''Generate the private part of the Type 1 font file from the object's
    internal data, and return it as a string.  No encryption is performed at
    this stage.  Normally, this method would only be called from 
    generate.'''

    output = "dup /Private %d dict dup begin\n"%(len(self.Private)+5)
    output = output + "/RD {string currentfile exch readstring pop} executeonly def\n"
    output = output + "/ND {noaccess def} executeonly def\n"
    output = output + "/NP {noaccess put} executeonly def\n"
    output = output + emitDictContents(self.Private,'')

    output = output + "/Subrs %d array\n"%len(self.Subrs)
    for i in range(0,len(self.Subrs)):
      output = output + "dup %d %d RD %s NP\n"%(i,len(self.Subrs[i]),self.Subrs[i])
    output = output + "ND\n"
    output = output + "2 index /CharStrings %d dict dup begin\n"%len(self.CharStrings)
    for i in self.CharStrings.keys():
      output = output + "/%s %d RD %s ND\n"%(i, len(self.CharStrings[i]), self.CharStrings[i])
    output = output + "end\nend\nreadonly put\nnoaccess put\n"
    output = output + "dup /FontName get exch definefont pop\nmark currentfile closefile\n"
    return output

  def generate(self):
    '''Generate a Type 1 font file representing this object, and return it as
    a string.'''
    output = "%%!FontType1-1.0: %s %s\n"%(self.MainDict['FontName'], self.FontInfo['version'])
    # print "%%CreationDate: "
    output = output+"% generated by type1.py\n"
    output = output+"%d dict begin\n"%(len(self.MainDict)+2)

    # emit the FontInfo dict here
    output = output + "/FontInfo %d dict dup begin\n"%len(self.FontInfo)
    output = output + emitDictContents(self.FontInfo)
    output = output + "end readonly def\n"
    output = output + emitDictContents(self.MainDict)
    if type(self.Encoding) == type(''):
      output = output + '/Encoding %s def\n'%self.Encoding
    elif type(self.Encoding) == type([]):
      output = output + '/Encoding 256 array\n0 1 255 {1 index exch /.notdef put } for\n'
      for i in len(encoding):
        output = output + "dup %d /%s put\n"%(i,encoding[i])
      output = output + 'readonly def\n'

    output = output + 'currentdict end\ncurrentfile eexec\n';

    output = output + eHexDump(eEncrypt(self.genPrivate()))
    for i in range(0,3):
      output = output + '0'*64 + '\n'
    output = output + 'cleartomark'

    return output
      
