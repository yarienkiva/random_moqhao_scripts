from bs4 import BeautifulSoup
from threading import Thread, Event
import signal
import hashlib
import os, subprocess, sys
import requests
import time, random

C2_URLS = [
	'http://gnsca.mohpd.com',
	'http://nostro.tbsdh.com',
	'http://coqrf.xpddg.com',
	'http://znjjq.udsuc.com',
	'http://gesee.udsuc.com',
	'http://bswhd.mrheu.com',
	'http://shbuf.bwdbu.com',
	'http://hnisi.zwrpy.com',
]
OUT_DIR = 'other_samples/'


verbose = False
def debug(*args, **kwargs):
	if verbose:
		print('[-]', *args, **kwargs)

def random_useragent() -> str:
	'''
	Return a random useragent corresponding to : 'Chrome 103 on Android XX' with model 'YYYYYYYYY'

		Returns:
			useragent (str): A random useragent
	'''
	base = 'Mozilla/5.0 (Linux; Android {}; {}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Mobile Safari/537.36'
	version = random.choice([10, 12])
	model   = random.choice(['SM-G991U', 'SM-S908U', 'SM-G998U', 'SM-G991B', 'SM-A326U', 'SM-G996U',
							 'SM-S901U', 'SM-G973U', 'SM-N986U', 'SM-G960U', 'SM-G781U', 'SM-N960U',
							 'moto g pure', 'Pixel 6 Pro', 'Pixel 6', 'K'])
	return base.format(version, model)


def apk_name_from_js(script: str) -> str:
	'''
	Decodes the path of the apk to download from the contents of the index.html page.
	Old version used to evaluate javascript locally and that's really bad.

	Example javascript:
        """
        <script>
            var arr = "43989,43992,43985,43974, [cut for the sake of brevity] , 43933,43919,43956".split(',').map(function(a){return a|0});
            var b = arr[arr.length-1];
            for(var i=0;i<arr.length-1;i++) {
                arr[i] =arr[i]^b;
            }
            arr.pop();
            eval(String.fromCharCode(...arr));
        </script>
        """"

        returns :
        """
        `alert("Afin d'avoir une meilleure expérience, veuillez mettre à jour votre navigateur Chrome à la dernière version");\n` +
          '        location.replace("/orqxpsxrmr.apk");'
        """

		Parameters:
			script (str): javascript code to parse

		Returns:
			path (str): path to malicious apk file

	'''

	arr = list(map(int, script.split('"')[1].split(',')))
	arr = [i ^ arr[-1] for i in arr[:-1]]
	apk = ''.join(list(map(chr, arr)))
	return apk.split('"')[-2][1:]



def wget(url: str, out: str) -> None:
	'''
	SECURITY WARNING: Better than evaluating attacker given code but still, not terrible.
	Downloads the malicious apk from the given url and saves it.
	For some reason it doesn't work in pure Python.

		Parameters:
			url (str): url of the malicious apk
			out (str): path to save the malware to 
	'''
	debug('wget: downloading', url, 'to', out)
	try:
		subprocess.check_output(['wget', '-qq', '--user-agent='+random_useragent(), url, '-O', out])
	except subprocess.CalledProcessError as e:
		pass


def hashfile(file: str) -> str:
	'''
	Return the SHA-256 checksum hash of a given file.

		Parameters:
			file (str): path of file to hash

		Returns:
			hash (str): SHA-256 of the file
	'''
	with open(file, 'rb') as f:
		dat = f.read()
	return hashlib.sha256(dat).hexdigest()


def downloader(c2_url: str) -> None:
	'''
	Polls the "malware CDN", downloads all malware and remove duplicates (by file hash).

		Parameters:
			c2_url (str): URL of "malware CDN"
	'''
	while not shutdown_event.is_set():

		try:
			r = requests.get(c2_url, headers={'User-Agent': random_useragent()})
			if not r.ok:
				raise ConnectionError
		except (OSError, ConnectionError):
			print('[+]', c2_url , 'is down, stopping thread')
			break

		soup = BeautifulSoup(r.text, features='lxml')

		script = soup.find('script').getText()

		apk = apk_name_from_js(script)

		if not apk.endswith('.apk'):
			print('[!]', apk)
			continue

		out = OUT_DIR + c2_url.split('://')[1] + '_' + apk + '.MAL'

		wget(c2_url + '/' + apk, out)

		h = hashfile(out)

		if h not in already_found:
			print('[+] Found a new APK !', c2_url, apk, h)
			already_found.append(h)
		else:
			print('[+] Already found', c2_url, apk, h)
			os.remove(out)

		time.sleep(random.randint(5, 10))


def sig_handler(signum, frame) -> None:
	'''
	Signal handler that tells all the threads to stop after the next iteration

	Parameters:
		signum (int): Signal number
		frame (stackframe): current stackframe
	'''
	debug("handling signal: %s\n" % signum)
	shutdown_event.set()


already_found = [
	hashfile(OUT_DIR + file) for file in os.listdir(OUT_DIR)
]

signal.signal(signal.SIGTERM, sig_handler)
signal.signal(signal.SIGINT,  sig_handler)
shutdown_event = Event()

threads = [Thread(target=downloader, args=(c2_url,), name='thread_'+c2_url.split('://')[1]) for c2_url in C2_URLS]

for t in threads:
	debug('starting thread', t.name)
	t.start()

while any(t.is_alive() for t in threads):
	for t in threads:
		if t.is_alive():
			t.join(timeout=0.5)
			debug('[-]', t.name, 'alive')
		else:
			debug('[-]', t.name, 'dead')

debug('All done!')
