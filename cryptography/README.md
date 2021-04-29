# Cryptography Challenges

### Index
___
1. [Nintendo Base64](#nintendo-base64)
2. [Phasestream](#phasestream)
3. [Phasestream2](#phasestream2)

### Nintendo Base64
> Aliens are trying to cause great misery for the human race by using our own cryptographic technology to encrypt all our games.
Fortunately, the aliens haven’t played CryptoHack so they’re making several noob mistakes. Therefore they’ve given us a chance to recover our games and find their flags. They’ve tried to scramble data on an N64 but don’t seem to understand that encoding and ASCII art are not valid types of encryption!

Analysing the contents of the zip file given we see the following output.
```shell
$ unzip crypto_nintendo_base64.zip
Archive:  crypto_nintendo_base64.zip
  inflating: output.txt
$ cat output.txt
            Vm                                                   0w               eE5GbFdWW         GhT            V0d4VVYwZ
            G9              XV                                   mx              yWk    ZOV       1JteD           BaV     WRH
                            YW                                   xa             c1              NsWl dS   M1   JQ WV       d4
S2RHVkljRm  Rp UjJoMlZrZH plRmRHV m5WaVJtUl hUVEZLZVZk   V1VrZFpWMU  pHVDFaV1Z  tSkdXazlXYW   twdl   Yx    Wm Fj  bHBFVWxWTlZ
Xdz     BWa 2M xVT     FSc  1d   uTl     hi R2h     XWW taS     1dG VXh     XbU ZTT     VdS elYy     cz     FWM    kY2VmtwV2
JU       RX dZ ak       Zr  U0   ZOc2JGWmlS a3       BY V1       d0 YV       lV MH       hj RVpYYlVaVFRWW  mF lV  mt       3V
lR       GV 01 ER       kh  Zak  5rVj   JFe VR       Ya Fdha   3BIV mpGU   2NtR kdX     bWx          oT   TB   KW VYxW   lNSM
Wx       XW kV kV       mJ  GWlRZ bXMxY2xWc 1V       sZ  FRiR1J5VjJ  0a1YySkdj   RVpWVmxKV           1V            GRTlQUT09


```
As hinted by the challenge name this is `base64` encoded text. To begin decoding we must first remove all the white spaces.
```shell
$ cat output.txt | tr -d ' ' | tr -d '\n'

Vm0weE5GbFdWWGhTV0d4VVYwZG9XVmxyWkZOV1JteDBaVWRHYWxac1NsWldSM1JQWVd4S2RHVkljRmRpUjJoMlZrZHplRmRHVm5WaVJtUlhUVEZLZVZkV1VrZFpWMUpHVDFaV1ZtSkdXazlXYWtwdlYxWmFjbHBFVWxWTlZXdzBWa2MxVTFSc1duTlhiR2hXWWtaS1dGVXhXbUZTTVdSelYyczFWMkY2VmtwV2JURXdZakZrU0ZOc2JGWmlSa3BYV1d0YVlVMHhjRVpYYlVaVFRWWmFlVmt3VlRGV01ERkhZak5rVjJFeVRYaFdha3BIVmpGU2NtRkdXbWxoTTBKWVYxWlNSMWxXWkVkVmJGWlRZbXMxY2xWc1VsZFRiR1J5VjJ0a1YySkdjRVpWVmxKV1VGRTlQUT09
```
We can decode this result with the following script.
```python
#!/usr/bin/python3

import base64

ciphertext = b'Vm0weE5GbFdWWGhTV0d4VVYwZG9XVmxyWkZOV1JteDBaVWRHYWxac1NsWldSM1JQWVd4S2RHVkljRmRpUjJoMlZrZHplRmRHVm5WaVJtUlhUVEZLZVZkV1VrZFpWMUpHVDFaV1ZtSkdXazlXYWtwdlYxWmFjbHBFVWxWTlZXdzBWa2MxVTFSc1duTlhiR2hXWWtaS1dGVXhXbUZTTVdSelYyczFWMkY2VmtwV2JURXdZakZrU0ZOc2JGWmlSa3BYV1d0YVlVMHhjRVpYYlVaVFRWWmFlVmt3VlRGV01ERkhZak5rVjJFeVRYaFdha3BIVmpGU2NtRkdXbWxoTTBKWVYxWlNSMWxXWkVkVmJGWlRZbXMxY2xWc1VsZFRiR1J5VjJ0a1YySkdjRVpWVmxKV1VGRTlQUT09'

while True:
    if ciphertext.startswith(b"CHTB"):
        break
    ciphertext = base64.b64decode(ciphertext)

print("Flag = {}".format(ciphertext.decode('utf-8')))
``` 
> Flag = CHTB{3nc0d1ng_n0t_3qu4l_t0_3ncrypt10n}

### Phasestream
> The aliens are trying to build a secure cipher to encrypt all our games called “PhaseStream”. They’ve heard that stream ciphers are pretty good. The aliens have learned of the XOR operation which is used to encrypt a plaintext with a key. They believe that XOR using a repeated 5-byte key is enough to build a strong stream cipher. Such silly aliens! Here’s a flag they encrypted this way earlier. Can you decrypt it (hint: what’s the flag format?) 2e313f2702184c5a0b1e321205550e03261b094d5c171f56011904

The given flag is `hex` encoded. Since it uses a repeated 5-byte XOR key and the flag format begins with `'CHTB{'`, we can obtain the 5-byte key  and the decrypted flag by the inherent properites of XOR (commutative, associative and inverse).
Thus, `key = xor("CHTB{", decode_hex("2e313f2702"))` and the `decrypted_flag = repeated_xor(key, decode_hex("2e313f2702184c5a0b1e321205550e03261b094d5c171f56011904"))`
```
#!/usr/bin/python3

def get_key(ciphertext, flag_format, num_bytes):
	key = ""
	for i in range(num_bytes):
		key += chr(ciphertext[i] ^ ord (flag_format[i]))
	return key.encode('utf-8')

def repeated_key_xor(plaintext, key):
    len_key = len(key)
    encoded = []

    for i in range(0, len(plaintext)):
        encoded.append(plaintext[i] ^ key[i % len_key])
    return bytes(encoded)

if __name__ == '__main__':
    ciphertext = bytes.fromhex("2e313f2702184c5a0b1e321205550e03261b094d5c171f56011904")
    print("Encrypted flag = {}".format(ciphertext))

    key = get_key(ciphertext, "CHTB{", 5)
    print("Key = {}".format(key))

    plaintext = repeated_key_xor(ciphertext, key)
    print("Decrypted flag = {}".format(plaintext.decode('utf-8')))
```
Executing the script gives us the following output.
```shell
$ ./phasestream.py
Encrypted flag = b".1?'\x02\x18LZ\x0b\x1e2\x12\x05U\x0e\x03&\x1b\tM\\\x17\x1fV\x01\x19\x04"
Key = b'mykey'
Decrypted flag = CHTB{u51ng_kn0wn_pl41nt3xt}
```
> Flag = CHTB{u51ng_kn0wn_pl41nt3xt}

### Phasestream2
> The aliens have learned of a new concept called “security by obscurity”. Fortunately for us they think it is a great idea and not a description of a common mistake. We’ve intercepted some alien comms and think they are XORing flags with a single-byte key and hiding the result inside 9999 lines of random data, Can you find the flag?

Let's take a look at the contents of the zip file.
```
$ unzip crypto_ps2.zip
Archive:  crypto_ps2.zip
  inflating: output.txt
$ head -n10 output.txt
3cc60a255dd328130e4203bb42f3be22d2935dbe5d9ebf498ce2
44e4088c49ce3aea69832d3c0a6cd43443ab1865daab8eab0fdc
bc0e3b0b7a600d5ff319ba661f6a077b058f1bd73c2c8f646c78
594a7cdfe5fe79edf5060c0ccd26304fd7bb9175f0ff6e6bc935
f807d7abd0cf8f82f56c22b59f1d22fcf1732163dcc4062a3f18
0d7fc2a812c0be988ef197bd7685876c8ff332f77dd5c8fb4ceb
5a04f0ecfa3b681930c29858f7e4f6f44f34c87f88533dd3ac17
93828080662b73d05deaf98e7a574b997f7e7c242619a541cb26
4b716313567479d19e64d0aa6794af8eac7d2e0c6f0475b7c0e6
947483e68b992c56db9bb7a9c89b1cee148539ed9745e9788512
```
Since this uses a single byte key we can use the same technique as the last task to obtain the key. Thus `key = xor("C", decode_hex(<line_from_file>))`
```python
#!/usr/bin/python3

from phasestream import *

if __name__ == "__main__":
	with open('output.txt', 'r') as f:
		for line in f:
			cipher = bytes.fromhex(f.readline())
			key = get_key(cipher, 'C', 1)
			plaintext = repeated_key_xor(cipher, key)
			if plaintext.startswith(b"CHTB"):
				print("Flag = {}".format(plaintext.decode('utf-8')))
                break
```
> Flag = CHTB{n33dl3_1n_4_h4yst4ck}
