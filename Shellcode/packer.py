

def base16_packer(shellcode) :
 
  output = []
  for byte in shellcode :
    output.append( chr( ((ord(byte) >> 4) & 0xf) + 0x41))
    output.append( chr( (ord(byte) & 0xf) + 0x41 ))
  return output




