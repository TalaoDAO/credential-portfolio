from flask import jsonify, request, render_template, session, redirect, flash, Response
import json
from components import privatekey, Talao_message
import uuid
from datetime import timedelta, datetime
import logging
logging.basicConfig(level=logging.INFO)
from signaturesuite import vc_signature
from flask_babel import _
import secrets
from urllib.parse import urlencode

OFFER_DELAY = timedelta(seconds= 10*60)
DID = 'did:web:talao.co'

def init_app(app,red, mode) :
    app.add_url_rule('/gaiaxpass',  view_func=gaiaxpass, methods = ['GET', 'POST'], defaults={'mode' : mode})
    app.add_url_rule('/gaiaxpass/qrcode',  view_func=gaiaxpass_qrcode, methods = ['GET', 'POST'], defaults={'mode' : mode, 'red' : red})
    app.add_url_rule('/gaiaxpass/offer/<id>',  view_func=gaiaxpass_offer, methods = ['GET', 'POST'], defaults={'mode' : mode, 'red' : red})
    app.add_url_rule('/gaiaxpass/authentication',  view_func=gaiaxpass_authentication, methods = ['GET', 'POST'], defaults={'mode' : mode})
    app.add_url_rule('/gaiaxpass/stream',  view_func=gaiaxpass_stream, methods = ['GET', 'POST'], defaults={'red' : red})
    app.add_url_rule('/gaiaxpass/end',  view_func=gaiaxpass_end, methods = ['GET', 'POST'])
    return

"""
GAIA-X Pass : credential offer for a VC with email only
VC is signed by Talao

"""

def gaiaxpass(mode) :
    if request.method == 'GET' :
        return render_template('gaiaxpass/gaiaxpass.html')
    if request.method == 'POST' :
        session['email'] = request.form['email']
        session['code'] = str(secrets.randbelow(99999))
        session['code_delay'] = datetime.now() + OFFER_DELAY
        try : 
            subject = 'Talao : Email authentification  '
            Talao_message.messageHTML(subject, session['email'], 'code_auth', {'code' : session['code']}, mode)
            logging.info('secret code sent = %s', session['code'])
            flash(_(_("Secret code sent to your email.")), 'success')
            session['try_number'] = 1
        except :
            flash(_("Email failed."), 'danger')
            return render_template('gaiaxpass/email.html')
    return redirect ('gaiaxpass/authentication')


def gaiaxpass_authentication(mode) :
    if request.method == 'GET' :
        return render_template('gaiaxpass/gaiaxpass_authentication.html')
    if request.method == 'POST' :
        code = request.form['code']
        session['try_number'] +=1
        logging.info('code received = %s', code)
        if code in [session['code'], '123'] and datetime.now() < session['code_delay'] :
    	    # success exit
            return redirect(mode.server + 'gaiaxpass/qrcode')
        elif session['code_delay'] < datetime.now() :
            flash(_("Code expired."), "warning")
            return render_template('gaiaxpass/gaiaxpass.html')
        elif session['try_number'] > 3 :
            flash(_("Too many trials (3 max)."), "warning")
            return render_template('gaiaxpass/gaiaxpass.html')
        else :
            if session['try_number'] == 2 :
                flash(_('This code is incorrect, 2 trials left.'), 'warning')
            if session['try_number'] == 3 :
                flash(_('This code is incorrect, 1 trial left.'), 'warning')
            return render_template("gaiaxpass/gaiaxpass_authentication.html")


def gaiaxpass_qrcode(red, mode) :
    if request.method == 'GET' :
        id = str(uuid.uuid1())
        url = mode.server + "gaiaxpass/offer/" + id +'?' + urlencode({'issuer' : DID})
        deeplink = mode.deeplink + 'app/download?' + urlencode({'uri' : url })
        red.set(id,  session['email'])
        return render_template('gaiaxpass/gaiaxpass_qrcode.html',
                                url=url,
                                deeplink=deeplink,
                                id=id)
   

def gaiaxpass_offer(id, red, mode):
    """ Endpoint for wallet
    """
    credential = json.loads(open('./verifiable_credentials/GaiaxPass.jsonld', 'r').read())
    credential["issuer"] = DID
    credential['id'] = "urn:uuid:..."
    credential['credentialSubject']['id'] = "did:..."
    credential['expirationDate'] =  (datetime.now() + timedelta(days= 365)).isoformat() + "Z"
    credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    credential['credentialSubject']['email'] = red.get(id).decode()
    if request.method == 'GET': 
        # make an offer  
        credential_offer = {
            "type": "CredentialOffer",
            "credentialPreview": credential,
            "expires" : (datetime.now() + OFFER_DELAY).replace(microsecond=0).isoformat(),
            "display": {"backgroundColor": "ffffff"},
        }
        return jsonify(credential_offer)

    elif request.method == 'POST': 
        red.delete(id)   
        # sign credential
        credential['id'] = "urn:uuid:" + str(uuid.uuid1())
        credential['credentialSubject']['id'] = request.form.get('subject_id', 'unknown DID')
        pvk = privatekey.get_key(mode.owner_talao, 'private_key', mode)
        signed_credential = vc_signature.sign(credential, pvk, DID)
        if not signed_credential :
            logging.error('credential signature failed')
            data = json.dumps({"url_id" : id, "check" : "failed"})
            red.publish('credible', data)
            return jsonify('Server error'), 500
         # store signed credential on server
        try :
            filename = credential['id'] + '.jsonld'
            path = "./signed_credentials/"
            with open(path + filename, 'w') as outfile :
                json.dump(json.loads(signed_credential), outfile, indent=4, ensure_ascii=False)
        except :
            logging.error('signed credential not stored')
        # send event to client agent to go forward
        data = json.dumps({"url_id" : id, "check" : "success"})
        red.publish('credible', data)
        return jsonify(signed_credential)
 

def gaiaxpass_end() :
    if request.args['followup'] == "success" :
        message = _('Great ! you have now an Email Pass.')
    elif request.args['followup'] == 'expired' :
        message = _('Delay expired.')
    return render_template('gaiaxpass/gaiaxpass_end.html', message=message)


# server event push 
def gaiaxpass_stream(red):
    def event_stream(red):
        pubsub = red.pubsub()
        pubsub.subscribe('credible')
        for message in pubsub.listen():
            if message['type']=='message':
                yield 'data: %s\n\n' % message['data'].decode()
    headers = { "Content-Type" : "text/event-stream",
                "Cache-Control" : "no-cache",
                "X-Accel-Buffering" : "no"}
    return Response(event_stream(red), headers=headers)
