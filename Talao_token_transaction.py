from web3.auto import w3
import constante
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import csv
import sys
import time
import Talao_ipfs
import hashlib
import json
import ipfshttpclient
from datetime import datetime
from eth_account.messages import encode_defunct


############################################################
# appel de ownersToContracts de la fondation
############################################################
#
# Owners (EOA) to contract addresses relationships.
#   mapping(address => address) public ownersToContracts;

def ownersToContracts(address) :

	contract=w3.eth.contract(constante.foundation_contract,abi=constante.foundation_ABI)
	workspace_address = contract.functions.ownersToContracts(address).call()
	return workspace_address



###############################################################
# read Talao profil
###############################################################
# return a dictionnaire {'givenName' ; 'Jean', 'familyName' ; 'Pascal'.....
# https://fr.wikibooks.org/wiki/Les_ASCII_de_0_%C3%A0_127/La_table_ASCII
# ord('a')=97...attention ajouté un 0 au dessus dessous de 99....


def readProfil (address) :
	# liste des claim topic , 
	givenName = 103105118101110078097109101
	familyName = 102097109105108121078097109101
	jobTitle = 106111098084105116108101
	worksFor = 119111114107115070111114
	workLocation = 119111114107076111099097116105111110
	url = 117114108
	email = 101109097105108
	description = 100101115099114105112116105111110
	
	topicvalue =[givenName, familyName, jobTitle, worksFor, workLocation, url, email, description]
	topicname =['givenName', 'familyName', 'jobTitle', 'worksFor', 'workLocation', 'url', 'email', 'description']
	
	workspace_contract=ownersToContracts(address)
	contract=w3.eth.contract(workspace_contract,abi=constante.workspace_ABI)
	profil=dict()
	index=0
	for i in topicvalue :
		claim=contract.functions.getClaimIdsByTopic(i).call()
		claimId=claim[0].hex()
		data = contract.functions.getClaim(claimId).call()
		profil[topicname[index]]=data[4].decode('utf-8')
		index=index+1
	return profil
	

############################################################
# Transfert de tokens  Talao depuis le portefeuille TalaoGen 
############################################################

def token_transfer(address_to, value) :

	contract=w3.eth.contract(constante.Talao_contract_address,abi=constante.Talao_Token_ABI)

	# calcul du nonce de l envoyeur de token . Ici le portefeuille TalaoGen
	nonce = w3.eth.getTransactionCount('0x84235B2c2475EC26063e87FeCFF3D69fb56BDE9b')  

	# Build transaction
	#chain ID = 4 sur rinkeby
	valueTalao=value*10**18	
	txn = contract.functions.transfer(address_to,valueTalao).buildTransaction({'chainId': constante.CHAIN_ID,'gas': 70000,'gasPrice': w3.toWei(constante.GASPRICE, 'gwei'),'nonce': nonce,})
	
	#sign transaction with TalaoGen wallet
	private_key_TalaoGen = '0xbbfea0f9ed22445e7f5fb1c4ca780e96c73da3c74fbce9a6972c45730a855460'
	signed_txn=w3.eth.account.signTransaction(txn,private_key_TalaoGen)
	
	# send transaction	
	w3.eth.sendRawTransaction(signed_txn.rawTransaction)  
	hash=w3.toHex(w3.keccak(signed_txn.rawTransaction))
	w3.eth.waitForTransactionReceipt(hash, timeout=2000)		
	return hash


###############################################################
# Transfert d'ether depuis le portefuille TalaoGen
#
# attention value est en millieme d ether
###############################################################

def ether_transfer(address_to, value) :
	
	# calcul du nonce de l envoyeur de token . Ici le portefeuille TalaoGen	
	talaoGen_nonce = w3.eth.getTransactionCount('0x84235B2c2475EC26063e87FeCFF3D69fb56BDE9b') 

	# build transaction
	eth_value=w3.toWei(str(value), 'milli')
	transaction = {'to': address_to,'value': eth_value,'gas': 50000,'gasPrice': w3.toWei(constante.GASPRICE, 'gwei'),'nonce': talaoGen_nonce,'chainId': constante.CHAIN_ID}

	#sign transaction with TalaoGen wallet
	key = '0xbbfea0f9ed22445e7f5fb1c4ca780e96c73da3c74fbce9a6972c45730a855460'
	signed_txn = w3.eth.account.sign_transaction(transaction, key)

	# send transaction
	w3.eth.sendRawTransaction(signed_txn.rawTransaction)  
	hash=w3.toHex(w3.keccak(signed_txn.rawTransaction))
	w3.eth.waitForTransactionReceipt(hash, timeout=2000)	
	return hash



###############################################################
# Balance d'un compte en token Talao
#
###############################################################

def token_balance(address) :

	contract=w3.eth.contract(constante.Talao_contract_address,abi=constante.Talao_Token_ABI)
	raw_balance = contract.functions.balanceOf(address).call()
	balance=raw_balance//10**18
	return balance




############################################################
# appel de createVaultAcces (uint price) 
############################################################

def createVaultAccess(address,private_key) :

	contract=w3.eth.contract(constante.Talao_contract_address,abi=constante.Talao_Token_ABI)

	# calcul du nonce de l envoyeur de token 
	nonce = w3.eth.getTransactionCount(address)  

	# Build transaction
	txn = contract.functions.createVaultAccess(0).buildTransaction({'chainId': constante.CHAIN_ID,'gas': 150000,'gasPrice': w3.toWei(constante.GASPRICE, 'gwei'),'nonce': nonce,})
	
	#sign transaction with caller wallet
	signed_txn=w3.eth.account.signTransaction(txn,private_key)
	
	# send transaction	
	w3.eth.sendRawTransaction(signed_txn.rawTransaction)  
	hash=w3.toHex(w3.keccak(signed_txn.rawTransaction))
	w3.eth.waitForTransactionReceipt(hash, timeout=2000, poll_latency=1)		
	return hash


############################################################
# creation d'un workspace
############################################################

# solidity function createWorkspace (
#        uint16 _category,
#        uint16 _asymetricEncryptionAlgorithm,
#        uint16 _symetricEncryptionAlgorithm,
#        bytes _asymetricEncryptionPublicKey,
#        bytes _symetricEncryptionEncryptedKey,
#        bytes _encryptedSecret,
#        bytes _email

def createWorkspace(address,private_key,bRSAPublicKey,bAESEncryptedKey,bsecret,bemail) :

	contract=w3.eth.contract(constante.workspacefactory_contract,abi=constante.Workspace_Factory_ABI)

	# calcul du nonce de l envoyeur de token . Ici le caller
	nonce = w3.eth.getTransactionCount(address)  

	# Build transaction
	txn=contract.functions.createWorkspace(1001,1,1,bRSAPublicKey,bAESEncryptedKey,bsecret,bemail).buildTransaction({'chainId': constante.CHAIN_ID,'gas': 6500000,'gasPrice': w3.toWei(constante.GASPRICE, 'gwei'),'nonce': nonce,})
	#sign transaction with caller wallet
	signed_txn=w3.eth.account.signTransaction(txn,private_key)
	
	# send transaction	
	w3.eth.sendRawTransaction(signed_txn.rawTransaction)
	hash= w3.toHex(w3.keccak(signed_txn.rawTransaction))
	w3.eth.waitForTransactionReceipt(hash, timeout=2000, poll_latency=1)	
	return hash
 




###################################################################
# Demande de partnership 630 000 gas
#
# 		0 identityInformation.creator = msg.sender;
#       1 identityInformation.category = _category;
#       2 identityInformation.asymetricEncryptionAlgorithm = _asymetricEncryptionAlgorithm;
#       3 identityInformation.symetricEncryptionAlgorithm = _symetricEncryptionAlgorithm;
#       4 identityInformation.asymetricEncryptionPublicKey = _asymetricEncryptionPublicKey;
#       5 identityInformation.symetricEncryptionEncryptedKey = _symetricEncryptionEncryptedKey;
#       6 identityInformation.encryptedSecret = _encryptedSecret;
###################################################################
def partnershiprequest(my_address, my_private_key, his_address) :

	#recuperer les 2 adresses de contrat
	my_contract=ownersToContracts(my_address)
	his_contract=ownersToContracts(his_address)

	print('my address =', my_address)	
	print('his address=', his_address)	
	print('my_contrat =' , my_contract)
	print('his contract =' ,his_contract)
	
	#recuperer ma cle AES cryptée
	contract=w3.eth.contract(my_contract,abi=constante.workspace_ABI)
	data = contract.functions.identityInformation().call()
	my_aes_encrypted=data[5]
	
	#recuperer sa cle RSA publique
	contract=w3.eth.contract(his_contract,abi=constante.workspace_ABI)
	data = contract.functions.identityInformation().call()
	his_rsa_key=data[4]

	# read ma cle privee RSA sur le fichier
	filename = "./RSA_key/"+constante.BLOCKCHAIN+'/'+str(my_address)+"_TalaoAsymetricEncryptionPrivateKeyAlgorithm1"+".txt"
	with open(filename,"r") as fp :
		my_rsa_key=fp.read()	
		fp.close()   

	# decoder ma cle AES cryptée avec ma cle RSA privée
	key = RSA.importKey(my_rsa_key)
	cipher = PKCS1_OAEP.new(key)	
	my_aes=cipher.decrypt(my_aes_encrypted)
	
	# encryption de ma cle AES avec sa cle RSA
	key=RSA.importKey(his_rsa_key)	
	cipher = PKCS1_OAEP.new(key)
	my_aes_encrypted_with_his_key = cipher.encrypt(my_aes_key)

	#envoyer la transaction sur mon contrat
	contract=w3.eth.contract(my_contract,abi=constante.workspace_ABI)

	# calcul du nonce de l envoyeur de token, ici my_address
	nonce = w3.eth.getTransactionCount(my_address)  

	# Build transaction
	txn = contract.functions.requestPartnership(his_contract, my_aes_encrypted).buildTransaction({'chainId': constante.CHAIN_ID,'gas': 800000,'gasPrice': w3.toWei(constante.GASPRICE, 'gwei'),'nonce': nonce,})	
	signed_txn=w3.eth.account.signTransaction(txn,my_private_key)
		
	# send transaction	
	w3.eth.sendRawTransaction(signed_txn.rawTransaction)  
	hash=w3.toHex(w3.keccak(signed_txn.rawTransaction))
	w3.eth.waitForTransactionReceipt(hash, timeout=2000, poll_latency=1)		
	return hash




###################################################################
# Création de document 250000 000 gas
# @data = dictionnaire = {"user": { "ethereum_account": '123' , "ethereum_contract": '234' ,"first_name" : 'Jean' ,"last_name" : 'Pierre' }}
# @encrypted = False ou True => AES
# location engine = 1 pour IPFS, doctypeversion = 1, expire =Null, 
###################################################################
#   function createDocument(
#        uint16 _docType,
#        uint16 _docTypeVersion,
#        uint40 _expires,
#        bytes32 _fileChecksum,
#        uint16 _fileLocationEngine,
#        bytes _fileLocationHash,
#        bool _encrypted
    

def createDocument(address, private_key, doctype, data, encrypted) :
	
	
	# lecture de l'adresse du workspace contract dans la fondation
	workspace_contract=ownersToContracts(address)

	#envoyer la transaction sur le contrat
	contract=w3.eth.contract(workspace_contract,abi=constante.workspace_ABI)

	# calcul du nonce de l envoyeur de token . Ici le portefeuille TalaoGen
	nonce = w3.eth.getTransactionCount(address)  

	# stocke sur ipfs (un dictionnaire)
	hash=Talao_ipfs.IPFS_add(data)
	
	# calcul du checksum en bytes des data, conversion du dictionnaire data en chaine str
	_data= json.dumps(data)
	checksum=hashlib.md5(bytes(_data, 'utf-8')).hexdigest()
	# la conversion inverse de bytes(data, 'utf-8') est XXX.decode('utf-8')

	# Build transaction
	txn = contract.functions.createDocument(doctype,1,0,checksum,1, bytes(hash, 'utf-8'), encrypted).buildTransaction({'chainId': constante.CHAIN_ID,'gas':500000,'gasPrice': w3.toWei(constante.GASPRICE, 'gwei'),'nonce': nonce,})
	
	#sign transaction
	signed_txn=w3.eth.account.signTransaction(txn,private_key)
	
	# send transaction	
	w3.eth.sendRawTransaction(signed_txn.rawTransaction)  
	hash=w3.toHex(w3.keccak(signed_txn.rawTransaction))
	w3.eth.waitForTransactionReceipt(hash)		
	return hash


 
############################################################
#  Mise a jour de la photo
############################################################
#
#  @picturefile : type str, nom fichier de la phooto avec path ex  './cvpdh.json'
# claim topic 105109097103101
    

def savepictureProfile(address, private_key, picturefile) :

	client = ipfshttpclient.connect('/dns/ipfs.infura.io/tcp/5001/https')
	response=client.add(picturefile)
	picturehash=response['Hash']	
	image= 105109097103101 
	workspace_contract=ownersToContracts(address)
	contract=w3.eth.contract(workspace_contract,abi=constante.workspace_ABI)

	# calcul du nonce de l envoyeur de token . Ici le caller
	nonce = w3.eth.getTransactionCount(address)  

	# Build transaction
	txn=contract.functions.addClaim(image,1,address, '0x', '0x01',picturehash ).buildTransaction({'chainId': constante.CHAIN_ID,'gas': 4000000,'gasPrice': w3.toWei(constante.GASPRICE, 'gwei'),'nonce': nonce,})
	
	#sign transaction with caller wallet
	signed_txn=w3.eth.account.signTransaction(txn,private_key)
	
	# send transaction	
	w3.eth.sendRawTransaction(signed_txn.rawTransaction)
	hash1= w3.toHex(w3.keccak(signed_txn.rawTransaction))
	w3.eth.waitForTransactionReceipt(hash1, timeout=2000, poll_latency=1)	
	return hash1

 
############################################################
#  Mise a jour du profil 2 000 000 gas
############################################################
#
# function updateSelfClaims(
#        uint256[] _topic,
#        bytes _data,
#        uint256[] _offsets

def saveworkspaceProfile(address, private_key, _givenName, _familyName, _jobTitle, _worksFor, _workLocation, _url, _email, _description) :

	givenName = 103105118101110078097109101
	familyName = 102097109105108121078097109101
	jobTitle = 106111098084105116108101
	worksFor = 119111114107115070111114
	workLocation = 119111114107076111099097116105111110
	url = 117114108
	email = 101109097105108
	description = 100101115099114105112116105111110
	topic =[givenName, familyName, jobTitle, worksFor, workLocation, url, email, description]
	image= 105109097103101
   
#_givenName='Jean'
#_familyName='Pascal'
#_jobTitle ='Developper'
#_worksFor = 'Talao'
#_workLocation ='St Ouen, Frnace'
#_url='Talao.io'
#_email='talaogen.jean.pascal@talao.io'
#_description ='Ceci est une description'

	chaine=_givenName+_familyName+_jobTitle+_worksFor+_workLocation+_url+_email+_description
	bchaine=bytes(chaine, 'utf-8')

	offset=[len(_givenName), len(_familyName), len(_jobTitle), len(_worksFor), len(_workLocation), len(_url), len(_email), len(_description)]

#address ='0x9A1D7ee6CcF5588c7f74E34a49308da9AbC27Bf8'
#private_key='0xb152e156901c7b0d24607aede258aab6c2d72572c4ed766294e8a36fa1f7959b'
#workspace_contract='0xec3edBe26fe78dBEe44942F961Ef8D968564AB3C'

	workspace_contract=ownersToContracts(address)
	contract=w3.eth.contract(workspace_contract,abi=constante.workspace_ABI)

	# calcul du nonce de l envoyeur de token . Ici le caller
	nonce = w3.eth.getTransactionCount(address)  

	# Build transaction
	txn=contract.functions.updateSelfClaims(topic, bchaine,offset).buildTransaction({'chainId': constante.CHAIN_ID,'gas': 4000000,'gasPrice': w3.toWei(constante.GASPRICE, 'gwei'),'nonce': nonce,})
	
	#sign transaction with caller wallet
	signed_txn=w3.eth.account.signTransaction(txn,private_key)
	
	# send transaction	
	w3.eth.sendRawTransaction(signed_txn.rawTransaction)
	hash1= w3.toHex(w3.keccak(signed_txn.rawTransaction))
	w3.eth.waitForTransactionReceipt(hash1, timeout=2000, poll_latency=1)	
	return hash1


 
############################################################
#  Read workspace Info
############################################################
#	0 identityInformation.creator = msg.sender;
#       1 identityInformation.category = _category;
#       2 identityInformation.asymetricEncryptionAlgorithm = _asymetricEncryptionAlgorithm;
#       3 identityInformation.symetricEncryptionAlgorithm = _symetricEncryptionAlgorithm;
#       4 identityInformation.asymetricEncryptionPublicKey = _asymetricEncryptionPublicKey;
#       5 identityInformation.symetricEncryptionEncryptedKey = _symetricEncryptionEncryptedKey;
#       6 identityInformation.encryptedSecret = _encryptedSecret;

def readWorkspaceInfo (address) : 

	# read la cle privee RSA sur le fichier
	filename = "./RSA_key/"+constante.BLOCKCHAIN+'/'+str(address)+"_TalaoAsymetricEncryptionPrivateKeyAlgorithm1"+".txt"
	with open(filename,"r") as fp :
		rsa_private_key=fp.read()	
		fp.close()   	
	# lecture de l'adresse du workspace contract dans la fondation
	workspace_contract=ownersToContracts(address)
	print('Adresse du Workspace', workspace_contract)

	# recuperation du login du backend sur le workspace
	contract=w3.eth.contract(workspace_contract,abi=constante.workspace_ABI)
	claim=contract.functions.getClaimIdsByTopic(101109097105108).call()
	claimId=claim[0].hex()
	data = contract.functions.getClaim(claimId).call()
	login=data[4].decode('utf-8')
	print('login = ', login)

	#recuperer le secret crypté (password du backend)
	contract=w3.eth.contract(workspace_contract,abi=constante.workspace_ABI)
	data = contract.functions.identityInformation().call()
	secret_encrypted=data[6]
	
	# decoder le secret cryptée avec la cle RSA privée
	key = RSA.importKey(rsa_private_key)
	cipher = PKCS1_OAEP.new(key)	
	SECRET=cipher.decrypt(secret_encrypted)			
	password = SECRET.hex()
	print('password = ', password)
	
	#recuperer la clé AES cryptée 
	contract=w3.eth.contract(workspace_contract,abi=constante.workspace_ABI)
	data = contract.functions.identityInformation().call()
	aes_encrypted=data[5]
	
	# decoder le secret cryptée avec la cle RSA privée
	key = RSA.importKey(rsa_private_key)
	cipher = PKCS1_OAEP.new(key)	
	aes=cipher.decrypt(secret_encrypted)				
	print('AES key = ', aes)
	
	return workspace_contract, login, password, aes 

 
############################################################
#  Create and publish experience in one step
############################################################
def createandpublishExperience(address, private_key, experience ) :

	# recuperer les infos du compte sur le workspace
	(workspace_contract,_email, _password, aes)=readWorkspaceInfo(address)
	
	# recuperer les info du profil
	profile=readProfil(address)
	#	topicname =['givenName', 'familyName', 'jobTitle', 'worksFor', 'workLocation', 'url', 'email', 'description']
	_familyName=profile["familyName"]
	_givenName=profile["givenName"]
	_jobTitle=profile["jobTitle"]

	#recuperer le kolen sur le backend
	conn = http.client.HTTPConnection(constante.ISSUER)
	if constante.BLOCKCHAIN == 'ethereum' :
		conn = http.client.HTTPSConnection(constante.ISSUER)
	headers = {'Accept': 'application/json','Content-type': 'application/json'}
	payload = {"email" : _email ,"password" : _password}
	data = json.dumps(payload)
	conn.request('POST', '/login',data, headers)
	response = conn.getresponse()
	res=response.read()
	token= json.loads(res)["token"]

	# creation experience sur le backend
	headers = {'Accept': 'application/json','Content-type': 'application/json',  'Authorization':'Bearer '+token}
	#experience={ 'experience':{'title': _experienceTitle, 'description': _experienceDescription, 'from': _fromdate, 'to': _todate, 'location': '', 'remote': True, 'organization_name': 'Talao','skills': [] }}
	payload = experience
	data = json.dumps(payload)
	conn.request('POST', '/experiences',data, headers)
	response= conn.getresponse()
	res=response.read()
	experience_id= json.loads(res)['experience']['id']	
	conn.close()

	# publish experience sur ipfs et la blockchain
	data={"documentType":50000,"version":2,
	"recipient":{"givenName":_givenName,"familyName":_familyName,"title": _jobTitle,"email":_email[5:],"ethereum_account": address,"ethereum_contract": workspace_contract},
	"issuer":{"organization":{"email":"","url":"","image":"","ethereum_account":"","ethereum_contract":""},"responsible":{"name":"","title":"","image":""},"partner":{"name":"","text":""}},
	"certificate":{"title":_experienceTitle,"description":_experienceDescription,"from":_fromdate,"to":_todate,"skills":[],"ratings":[]}}

	Talao_token_transaction.createDocument(address, private_key, 50000, data, False)

	# recuperer l iD du document sur le dernier event DocumentAdded
	mycontract=w3.eth.contract(workspace_contract,abi=constante.workspace_ABI)
	myfilter = mycontract.events.DocumentAdded.createFilter(fromBlock= 5800000,toBlock = 'latest')
	eventlist = myfilter.get_all_entries()
	l=len(eventlist)
	document_id=eventlist[l-1]['args']['id']

	# update de l experience sur la backend . on change le status et on donne le numero du doc 
	token=Talao_backend_transaction.login(_email, _password)
	headers = {'Accept': 'application/json','Content-type': 'application/json',  'Authorization':'Bearer '+token}
	payload ={"experience":{"blockchain_experience_id":document_id,"blockchain_status":1},"action":"SET_DRAFT"}
	data = json.dumps(payload)
	conn.request('PUT', '/experiences/'+str(experience_id),data, headers)
	response= conn.getresponse()
	res=response.read()
	print(json.loads(res))	
	conn.close()
	return
	
	
#########################################################	
# read Talao experience or diploma index
#########################################################
# @_doctype = int (40000 = Diploma, 50000 = experience)
# return Int
# attention cela retourne le nombre de doc mais pas les docuements actifs !!!!

def getDocumentIndex(address, _doctype) :
	workspace_contract=ownersToContracts(address)
	contract=w3.eth.contract(workspace_contract,abi=constante.workspace_ABI)
	docindex=contract.functions.getDocuments().call()
	index=0
	for i in docindex :
		doc=contract.functions.getDocument(i).call()
		if doc[0]==_doctype :
			index=index+1			
	return index

######################################################	
# read Talao experience or diploma
######################################################
# @_doctype = integer, 40000 = Diploma, 50000 = experience, 60000 certificate
# return dictionnaire

def getDocument(address, _doctype,_index) :
	workspace_contract=ownersToContracts(address)
	contract=w3.eth.contract(workspace_contract,abi=constante.workspace_ABI)
	docindex=contract.functions.getDocuments().call()
	index=0
	for i in docindex :
		doc=contract.functions.getDocument(i).call()
		if doc[0] ==_doctype :
			if index==_index :
				ipfs_hash=doc[6].decode('utf-8')
				return Talao_ipfs.IPFS_get(ipfs_hash)
			else :
				index=index+1				


#####################################
#authentication d'un json de type str
#####################################
def authenticate(docjson, address, private_key) :
# @docjson : type str au format json
# @address, @private_key  : le Creator est celui qui signe
# return le str json authentifié
# pour decoder :
# message = encode_defunct(text=msg)
# address=w3.eth.account.recover_message(message, signature=signature)
#
# cf : https://web3py.readthedocs.io/en/stable/web3.eth.account.html#sign-a-message


	# conversion en Dict python
	objectdata=json.loads(docjson)

	# mise a jour du Dict avec les infos d authentication
	objectdata.update({'Authentication' : 
	{'@context' : 'this Key can be used to authenticate the creator of this doc. Ownernership of did can be checked at https://rinkeby.etherscan.io/address/0xde4cf27d1cefc4a6fa000a5399c59c59da1bf253#readContract',
	'type' : 'w3.eth.account.sign_message',
	'PublicKey' : address,
	'Created' : str(datetime.today()),
	"Creator" : address,
	'message' : 'to be added',
	'signature' : 'to be added' }
	}) 
	
	# upload et pin sur ipfs
	client = ipfshttpclient.connect('/dns/ipfs.infura.io/tcp/5001/https')
	response=client.add_json(objectdata)
	client.pin.add(response)

	# le lien sur le fichier IPFS est le message	
	msg='https://ipfs.io/ipfs/'+response
	message = encode_defunct(text=msg)
	# signature du messaga avec web3 compatible avce solidity erocover 
	signed_message = w3.eth.account.sign_message(message, private_key=private_key)
	signature=signed_message.signature.hex()
	
	# complement du Dict
	objectdata["Authentication"]["message"]=msg
	objectdata["Authentication"]["signature"]=signature
	
	# conversion du Dict en str json
	auth_docjson=json.dumps(objectdata,indent=4)
		
	return auth_docjson

#################################################
#  addclaim
#################################################
# @data : bytes	
# topicname : type str , 'contact'
# ipfs hash = str exemple  b'qlkjglgh'.decode('utf-8') 

def addclaim(workspace_contract, private_key, topicname, issuer, data, ipfshash) :
	
	topicvalue=constante.topic[topicname]
	
	# calcul du nonce de l envoyeur de token . Ici le caller
	nonce = w3.eth.getTransactionCount(address)  

	# Build transaction
	txn=contract.functions.addClaim(topicvalue,1,issuer, '0x', '0x01',ipfshash ).buildTransaction({'chainId': constante.CHAIN_ID,'gas': 4000000,'gasPrice': w3.toWei(constante.GASPRICE, 'gwei'),'nonce': nonce,})
	
	#sign transaction with caller wallet
	signed_txn=w3.eth.account.signTransaction(txn,private_key)
	
	# send transaction	
	w3.eth.sendRawTransaction(signed_txn.rawTransaction)
	hash1= w3.toHex(w3.keccak(signed_txn.rawTransaction))
	w3.eth.waitForTransactionReceipt(hash1, timeout=2000, poll_latency=1)	
	return hash1
