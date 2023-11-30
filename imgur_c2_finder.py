from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad
import requests
import base64, tqdm

URL = 'https://api.imgur.com/account/v1/accounts/shaoye{}?client_id=546c25a59c58ad7'

def remove_delimiter(url):
	for i in range(1, len(url)):
		if url.startswith(url[:i]) and url.endswith(url[:i]):
			maxi = i
	return url[maxi:-maxi]

def decrypt(url):
	key = bytes.fromhex('41 62 35 64 31 51 33 32')
	iv  = bytes.fromhex('41 62 35 64 31 51 33 32')
	cipher = DES.new(key, DES.MODE_CBC, iv=iv)
	url = unpad(cipher.decrypt(url), DES.block_size)
	return url

#for n in tqdm.tqdm(range(10_000)):

for length in range(1, 5):
	for i in range(10):

		n = str(i) * length

		r = requests.get(URL.format(n)).json()

		if 'bio' not in r:
			continue

		url = r['bio']
		print(f'[+] Found profile : shaoye{n}')

		url = remove_delimiter(url)
		url = base64.urlsafe_b64decode(url + '==') # https://stackoverflow.com/questions/2941995/python-ignore-incorrect-padding-error-when-base64-decoding

		url = decrypt(url)

		print('[+] Found a c2 :', url)
