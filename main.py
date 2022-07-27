
import os
import time
import json
from flask_babel import Babel, _, refresh
from flask import Flask, redirect, jsonify, request, session
from flask_session import Session
from datetime import timedelta
from flask_cors import CORS
from flask_qrcode import QRcode
import redis
import sys
import logging
from components import privatekey
from signaturesuite import helpers
import environment


logging.basicConfig(level=logging.INFO)
logging.info("python version : %s", sys.version)


# Environment variables set in gunicornconf.py  and transfered to environment.py
mychain = os.getenv('MYCHAIN')
myenv = os.getenv('MYENV')
if not myenv :
   myenv='local'
mychain = 'talaonet'

logging.info('start to init environment')
mode = environment.currentMode(mychain,myenv)
logging.info('end of init environment')

# Redis init red = redis.StrictRedis()
red= redis.Redis(host='localhost', port=6379, db=0)

# Centralized  routes : modules in ./routes
from routes import web_tiar


#BUNNEY Calum <calum.bunney@nexusgroup.com>
# Server Release
VERSION = '1.67'
logging.info('Talao version : %s', VERSION)

# Framework Flask and Session setup
app = Flask(__name__)
app.jinja_env.globals['Version'] = VERSION
app.jinja_env.globals['Created'] = time.ctime(os.path.getctime('main.py'))
app.jinja_env.globals['Chain'] = mychain.capitalize()
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_COOKIE_NAME'] = 'talao'
app.config['SESSION_TYPE'] = 'redis' # Redis server side session
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=360) # cookie lifetime
app.config['SESSION_FILE_THRESHOLD'] = 100
app.config['SECRET_KEY'] = "OCML3BRawWEUeaxcuKHLpw" + mode.password
app.config["ALLOWED_IMAGE_EXTENSIONS"] = ["jpeg", "jpg", "png", "gif"]
babel = Babel(app)
sess = Session()
sess.init_app(app)
qrcode = QRcode(app)
CORS(app)

@app.errorhandler(403)
def page_abort(e):
    """
    we set the 403 status explicitly
    """
    logging.warning('abort 403')
    return redirect(mode.server + 'login/')


LANGUAGES = ['en', 'fr']
@babel.localeselector
def get_locale():
    if not session.get('language') :
        session['language'] = request.accept_languages.best_match(LANGUAGES)
    else :
        refresh()
    return session['language']


"""
https://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-xiii-i18n-and-l10n
pybabel extract -F babel.cfg -o messages.pot .
pybabel update -i messages.pot -d translations -l fr
pybabel compile -d translations
"""

@app.route('/language', methods=['GET'], defaults={'mode': mode})
def user_language(mode) :
    session['language'] = request.args['lang']
    refresh()
    return redirect (request.referrer)

logging.info('start init routes')
# Centralized @route
web_tiar.init_app(app)


logging.info('end init routes')

@app.route('/login' , methods=['GET']) 
@app.route('/' , methods=['GET']) 
def login2() :
    return redirect('/sandbox')


# Google universal link
@app.route('/.well-known/assetlinks.json' , methods=['GET']) 
def assetlinks(): 
    document = json.load(open('assetlinks.json', 'r'))
    return jsonify(document)


# Apple universal link
@app.route('/.well-known/apple-app-site-association' , methods=['GET']) 
def apple_app_site_association(): 
    document = json.load(open('apple-app-site-association', 'r'))
    return jsonify(document)


# .well-known DID API 
@app.route('/.well-known/did-configuration.json', methods=['GET']) 
def well_known_did_configuration () :
    document = json.load(open('./verifiable_credentials/well_known_did_configuration.jsonld', 'r'))
    return jsonify(document)


# openid configuration with credential manifest
@app.route('/.well-known/openid-configuration', methods=['GET'])
def openid_configuration():
    document = json.load(open('./credential_manifest.json', 'r'))
    return jsonify(document)


# .well-known DID API
@app.route('/.well-known/did.json', methods=['GET'], defaults={'mode' : mode})
def well_known_did (mode) :
    """ did:web
    https://w3c-ccg.github.io/did-method-web/
    https://identity.foundation/.well-known/resources/did-configuration/#LinkedDomains
    """
    address = mode.owner_talao 
    # secp256k
    pvk = privatekey.get_key(address, 'private_key', mode)
    key = helpers.ethereum_to_jwk256k(pvk)
    ec_public = json.loads(key)
    del ec_public['d']
    del ec_public['alg']
    DidDocument = did_doc(ec_public)
    return jsonify(DidDocument)


def did_doc(ec_public) :
    return  {
                "@context": [
                    "https://www.w3.org/ns/did/v1",
                    {
                        "@id": "https://w3id.org/security#publicKeyJwk",
                        "@type": "@json"
                    }
                ],
                "id": "did:web:talao.co",
                "verificationMethod": [
                    {
                        "id": "did:web:talao.co#key-1",
                        "controller" : "did:web:talao.co",
                        "type": "EcdsaSecp256k1VerificationKey2019",
                        "publicKeyJwk": ec_public
                    },
                    {
                        "id": "did:web:talao.co#key-2",
                        "type": "JwsVerificationKey2020",
                        "controller": "did:web:talao.co",
                        "publicKeyJwk": {
                            "e":"AQAB",
                            "kid":"did:web:talao.co#key-2",
                            "kty":"RSA",
                            "n":"mIPHiLUlfIwj9udZARJg5FlyXuqMsyGHucbA-CqpJh98_17Qvd51SAdg83UzuCihB7LNYXEujnzEP5J5mAWsrTi0G3CRFk-pU_TmuY8p57M_NXvB1EJsOrjuki5HmcybzfkJMtHydD7gVotPoe-W4f8TxWqB54ve4YiFczG6A43yB3lLCYZN2wEWfwKD_FcaC3wKWdHFxqLkrulD4pVZQ_DwMNuf2XdCvEzpC33ZsU3DB6IxtcSbVejGCyq5EXroIh1-rp6ZPuCGExg8CjiLehsWvOmBac9wO74yfo1IF6PIrQQNkFA3vL2YWjp3k8SO0PAaUMF44orcUI_OOHXYLw"
                        }
                    },
                    {
                        "id": "did:web:talao.co#key-3",
                        "type": "JwsVerificationKey2020",
                        "controller": "did:web:talao.co",
                        "publicKeyJwk": {
                            "crv": "P-256",
                            "kty" : "EC",
                            "x" : "Bls7WaGu_jsharYBAzakvuSERIV_IFR2tS64e5p_Y_Q",
                            "y" : "haeKjXQ9uzyK4Ind1W4SBUkR_9udjjx1OmKK4vl1jko"
                        }
                    },
                    {
                        "id": "did:web:talao.co#key-4",
                        "type": "JwsVerificationKey2020",
                        "controller": "did:web:talao.co",
                        "publicKeyJwk": {
                            "crv":"Ed25519",
                            "kty":"OKP",
                            "x":"FUoLewH4w4-KdaPH2cjZbL--CKYxQRWR05Yd_bIbhQo"
                        }
                    },
                ],
                "authentication" : [
                    "did:web:talao.co#key-1",
                ],
                "assertionMethod" : [
                    "did:web:talao.co#key-1",
                    "did:web:talao.co#key-2",
                    "did:web:talao.co#key-3",
                    "did:web:talao.co#key-4"
                ],
                "keyAgreement" : [
                    "did:web:talao.co#key-3",
                    "did:web:talao.co#key-4"
                ],
                "capabilityInvocation":[
                    "did:web:talao.co#key-1"
                ],

                "service": [
                    {
                        "id": 'did:web:talao.co#domain-1',
                        "type" : 'LinkedDomains',
                        "serviceEndpoint": "https://talao.co"
                    }
                ]
            }


# MAIN entry point for test
if __name__ == '__main__':
    # info release
    logging.info('flask test serveur run with debug mode')
    app.run(host = mode.flaskserver, port= mode.port, debug = mode.test, threaded=True)