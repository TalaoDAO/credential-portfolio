#import http.client, urllib.parse
from flask import Flask, jsonify, session
from flask import request, redirect, url_for
from flask_api import FlaskAPI
from Crypto.Random import get_random_bytes
import json

import GETdata
import GETresolver
import GETresume
import nameservice
import Talao_message
import createidentity
import constante
import Talao_backend_transaction
import environment

from flask import render_template
# https://flask.palletsprojects.com/en/1.1.x/quickstart/

# SETUP
mode=environment.currentMode('test', 'rinkeby')

app = FlaskAPI(__name__)
#app = Flask(__name__)
app.config["SECRET_KEY"] = "OCML3BRawWEUeaxcuKHLpw"
tabcode = dict()




@app.route('/talao/api/<data>', methods=['GET'])
def Main(data) :
	return GETdata.getdata(data, register,mode)

#####################################################
#   RESOLVER
#####################################################

# API
@app.route('/talao/api/resolver/<did>', methods=['GET'])
def DID_document(did) :
	return GETresolver.getresolver(did,mode)

# HTML
@app.route('/resolver/')
def DID_document_html() :
	return render_template("home_resolver.html")
@app.route('/resolver/did/', methods=['POST'])
def DID_document_html_1() :
	did = request.form['did']
	return GETresolver.getresolver(did,mode)

#####################################################
#   AUTRES API
#####################################################

@app.route('/talao/api/data/<data>', methods=['GET'])
def Data(data) :
	return GETdata.getdata(data, register,mode)

@app.route('/talao/api/resume/<did>', methods=['GET'])
def Resume_resolver(did) :
	return GETresume.getresume(did,mode)

#####################################################
#   Talent Connect cf oAUTH2
#####################################################
# 1) "connectez vous avec le Talent Connect" -> appel de la mire de login avec id et jwt de la societe RH
# 2) "entrez votre did et checkez votre email" -> envoi d'un message avec code secret
# 3) "entrez le code correspondant a votre souhait" 
# 4) retour d'information a la société RH
# https://orange.developpez.com/tutoriels/authentification-3-legged/


# API
@app.route('/talent_connect/api/<data>', methods=['GET'])
def talentconnect(data) :
	return GETresume.getresume(did, register,mode)

#####################################################
#   CREATION IDENTITE ONLINE (html) pour le site talao.io
#####################################################
"""
le user reçoit par email les informations concernant son identité
Talao dispose d'une copie de la clé
On test si l email existe dans le back end
"""

@app.route('/talao/register/')
def authentification() :
	return render_template("home.html",message='Aucun')

### recuperation de l email
@app.route('/talao/register/', methods=['POST'])
def POST_authentification_1() :
	global tabcode
	
	# verification de l email dans le backend
	email = request.form['email']
	session['lastname']=request.form['lastname']
	session['firstname']=request.form['firstname']
	session['email']=email
	print('email = ', email)
	check_backend=Talao_backend_transaction.canregister(email,mode)
	print('check backend =',check_backend) 
	if check_backend == False :
		return render_template("home.html", message = 'Email already in Backend')
	
	# envoi du code secret par email
	code = get_random_bytes(3).hex()
	print('code secret = ', code)
	tabcode[email]=code
		
	# envoi message de control du code
	Talao_message.messageAuth(email, code)
	print('message envoyé à ', email)
	print('name = ', request.form['lastname'])
	print('firstname =', request.form['firstname'])

	return render_template("home2.html", message = 'email avec code envoyé')

# recuperation du code saisi
@app.route('/talao/register/code/', methods=['POST'])
def POST_authentification_2() :
	email=session.get('email')
	lastname=session.get('lastname')
	firstname=session.get('firstname')
	mycode = request.form['mycode']
	print(firstname, '  ', lastname, '   ', email)
	print('code retourné = ', mycode)
	if mycode == tabcode[email] :
		print('appel de createidentity avec firtsname = ', firstname, ' name = ', lastname, ' email = ', email)
		#(address, eth_p, SECRET, workspace_contract,backend_Id, email, SECRET, AES_key) = createidentity.creationworkspacefromscratch(firstname, name, email)	
		mymessage = 'workspace will be available within a couple of minutes. You will receive your Ethereum private key and RSA key to connect with my.Freedapp http://vault.talao.io:4011/' 
	else :
		mymessage = 'false code'
	return render_template("home3.html", message = mymessage)

@app.route('/talao/register/code/', methods=['GET'])
def POST_authentification_3() :
	return redirect(url_for('authentification'))


#######################################################
#   Name Service
#######################################################

# API
@app.route('/nameservice/api/<name>', methods=['GET'])
def GET_nameservice(name) :
	a= nameservice.address(name,mode)
	if a== None :
		return {"CODE" : "601"}
	else :
		return {"did" : "did:talao:rinkeby:"+a[2:]}

@app.route('/nameservice/api/reload/', methods=['GET'])
def GET_nameservice_reload() :
	nameservice.buildregister(mode)
	return {"CODE" : "reload done"}


# HTML name -> did
@app.route('/nameservice/')
def GET_nameservice_html() :
	return render_template("home_nameservice.html")

@app.route('/nameservice/name/', methods=['POST'])
def DID_nameservice_html_1() :
	name = request.form['name']
	a= nameservice.address(name,register)
	if a == None :
		mymessage='Il n existe pas de did avec cet identifiant' 
	else :
		mymessage="did:talao:rinkeby:"+a[2:]
	return render_template("home_nameservice2.html", message = mymessage, name=name)

@app.route('/nameservice/name/', methods=['GET'])
def POST_nameservice_html_2() :
	return redirect(url_for('GET_nameservice_html'))


#######################################################
#                        MAIN, server launch
#######################################################
# setup du registre nameservice
print('debut de la creation du registre')
register=nameservice.buildregister(mode)
print('initialisation du serveur')

if __name__ == '__main__':
	
	if mode.env == 'production' :
		app.run(host = mode.IP, port= mode.port, debug=True)
	elif mode.env =='test' :
		app.run(debug=True)
	else :
		print("Erreur d'environnement")
