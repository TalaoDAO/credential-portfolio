"""
initialisation des variables d'environnement
upload du fichier des private key de Talao, Relay et Talaogen
initialisation du provider
construction du registre nameservice
unlock des addresses du node
check de geth
"""

import json
import sys
import logging
import socket

logging.basicConfig(level=logging.INFO)


class currentMode() :

	def __init__(self, mychain, myenv):
		# mychain, myenv --> environment variables set in gunicornconf.py or manually if main.py is launched without Gunicorn
		self.admin = 'thierry.thevenet@talao.io'
		self.test = True
		self.myenv = myenv
		self.flaskserver = "127.0.0.1" # default value to avoid pb with aws
		self.port = 4000 #default value to avoid pb with aws
		self.talao_to_transfer = 101  # Vault deposit see Token Talao
		self.ipfs_gateway = 'https://talao.mypinata.cloud/ipfs/'

		# upload of main private keys. This file (keys.json) is not in the  github repo. Ask admin to get it !!!!!
		try :
			keys = json.load(open('./keys.json'))
		except :
			logging.error('open keys.json file problem')
			sys.exit()
		self.aes_public_key = keys['aes_public_key']
		self.relay_private_key = keys['relay_private_key']
		self.Talaogen_private_key = keys['talaogen_private_key']
		self.owner_talao_private_key = keys['talao_private_key']
		self.foundation_private_key = keys['foundation_private_key']
		self.talao_P256_private_key = keys['talao_P256_private_key']
		self.talao_Ed25519_private_key = keys['talao_Ed25519_private_key']

		# upload of main private passwords. This file (passwords.json) is not in the  github repo.
		try :
			passwords = json.load(open('./passwords.json'))
		except :
			logging.error('open passwords.json file problem')
			sys.exit()
		self.password = passwords['password']
		self.passbase = passwords['passbase']
		self.smtp_password = passwords['smtp_password'] # used in smtp.py
		self.pinata_api_key = passwords['pinata_api_key'] # used in Talao_ipfs.py
		self.pinata_secret_api_key = passwords['pinata_secret_api_key'] # used in Talao_ipfs.py
		self.sms_token = passwords['sms_token'] # used in sms.py
		self.github = passwords['github'] # used for test credeible
		self.deeplink = 'https://app.talao.co/'	
		self.altme_deeplink = 'https://app.altme.io/'		
		if self.myenv == 'aws':
			self.sys_path = '/home/admin'
		else :
			self.sys_path = '/home/thierry'

		self.keystore_path = self.sys_path + '/Talao/keystore/'
		self.Ed25519_path = self.sys_path + '/Talao/keystore_Ed25519/'
		self.P256_path = self.sys_path + '/Talao/keystore_P256/'
		self.db_path = self.sys_path + '/db/talaonet/'
		self.help_path = self.sys_path + '/Talao/templates/'
		self.uploads_path = self.sys_path + '/Talao/uploads/'
		self.verifiable_credentials = self.sys_path + '/Talao/verifiable_credentials/'

		# En Prod chez AWS avec Talaonet
		if self.myenv == 'aws':
			self.server = 'https://talao.co/'
			self.IP = '18.190.21.227' # talao.co
	
		elif self.myenv == 'local' :
			self.flaskserver = extract_ip()
			self.IP = extract_ip()
			self.server = 'http://' + self.flaskserver + ':3000/'
			self.port = 3000

		else :
			logging.error('environment variable problem')



		
def extract_ip():
    st = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:       
        st.connect(('10.255.255.255', 1))
        IP = st.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        st.close()
    return IP