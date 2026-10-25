data = open(r'C:\Users\26346\Documents\deepseek-harness\default-workspace\axonskin_re\plaintext\axonlogin_patched.dll','rb').read()
seg = data[0x867E:0x8690]
print('0x867E-0x868F:', seg.hex())
print('Expected:      909090909033c990909090eb45')
print('Match:', seg.hex() == '909090909033c990909090eb45')
