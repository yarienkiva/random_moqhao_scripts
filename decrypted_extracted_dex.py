#!/usr/bin/env python3

import sys
import zipfile
import zlib

if len(sys.argv) != 2 or not zipfile.is_zipfile(sys.argv[1]):
    print(f'{__file__} moqhao.apk')
    exit()

z = zipfile.ZipFile(sys.argv[1])
d = [f.filename for f in z.filelist 
            if f.filename.startswith('assets/')][0]

d = z.extract(d, path='/tmp')

with open(d, 'rb') as f:
    enc_data = f.read()

sizeof_deflated_dex = (enc_data[8] << 16) + (enc_data[9] <<  8) + enc_data[10]

print(f'[+] Size of compressed dex : {hex(sizeof_deflated_dex)}')

key = enc_data[11]
print(f'[+] xor key = {hex(key)}')

deflated_data = bytes(b ^ key for b in enc_data[12:])
data = zlib.decompress(deflated_data)

dex_file = z.filename[:-4] + '-' + d.split('/')[-1] + '.dex'

with open(dex_file, 'wb') as f:
    f.write(data)

print(f'[+] Voili, voilou, allez voir "{dex_file}"')
