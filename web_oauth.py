"""
Scope list

OIDC
'sub', 'name', 'given_name', 'family_name', 'middle_name', 'nickname',
        'preferred_username', 'profile', 'picture', 'website', 'email',
        'email_verified', 'gender', 'birthdate', 'zoneinfo', 'locale',
        'phone_number', 'phone_number_verified', 'address', 'updated_at'


CLIENT CREDENTIAL 
create_person_identity
create_company_identity

issue_experience
issue_skill



"""


import os
import time
from flask import request, session, url_for, Response, abort, flash
from flask import render_template, redirect, jsonify
from werkzeug.security import gen_salt
from authlib.integrations.flask_oauth2 import current_token, client_authenticated
from authlib.oauth2 import OAuth2Error, OAuth2Request
from models import db, User, OAuth2Client
from oauth2 import authorization, require_oauth
import json
from urllib.parse import urlencode, parse_qs, urlparse
import random

import ns
import environment
import constante
from protocol import read_profil, contractsToOwners, add_key, partnershiprequest, authorize_partnership, has_key_purpose, Document, get_image, is_partner, get_partner_status
import createidentity
import createcompany
import privatekey

def check_login() :
	""" check if the user is correctly logged. This function is called everytime a user function is called """
	if session.get('username') is None :
		abort(403)
	else :
		return session['username']

def current_user():
    if 'id' in session:
        uid = session['id']
        return User.query.get(uid)
    return None

def split_by_crlf(s):
    return [v for v in s.splitlines() if v]

def get_client_workspace(client_id, mode) :
    client = OAuth2Client.query.filter_by(client_id=client_id).first()
    client_username = json.loads(client._client_metadata)['client_name']
    return ns.get_data_from_username(client_username, mode).get('workspace_contract')

def get_user_workspace(user_id, mode):
    user = User.query.get(user_id)
    user_username = user.username
    return  ns.get_data_from_username(user_username, mode).get('workspace_contract')

#@bp.route('/api/v1', methods=('GET', 'POST'))
def home():
    check_login()
    if request.method == 'POST':
        username = request.form.get('username')
        user = User.query.filter_by(username=username).first()
        if not user:
            user = User(username=username)
            db.session.add(user)
            db.session.commit()
        session['id'] = user.id
        # if user is not just to log in, but need to head back to the auth page, then go for it
        next_page = request.args.get('next')
        if next_page:
            return redirect(next_page)
        return redirect('/api/v1')
    user = current_user()
    if user:
        clients = OAuth2Client.query.filter_by(user_id=user.id).all()
    else:
        clients = []
    return render_template('/oauth/home.html', user=user, clients=clients)

#@bp.route('/api/v1/oauth_logout')
def oauth_logout():
    check_login()
    post_logout = request.args.get('post_logout_redirect_uri')
    #session.clear()
    return redirect(post_logout)


#@bp.route('/api/v1/oauth_login')
def oauth_login(mode):
    if request.method == 'GET' :
        session['url'] = request.args.get('next')
        return render_template('/oauth/oauth_login.html')
    if request.method  == 'POST' :
        url = session.get('url')
        if url is None :
            return 'Session lost'
        username = request.form.get('username')
        if not ns.username_exist(username, mode)  :
            flash('Username not found', "warning")
            return redirect(url)
        if not ns.check_password(username, request.form['password'].lower(), mode)  :
            flash('Wrong password', "warning")
            return redirect(url)
        # if secret code wrong redirect to url
        user = User.query.filter_by(username=username).first()
        if not user:
            user = User(username=username)
            db.session.add(user)
            db.session.commit()
        session['id'] = user.id
        print('User logged in Talao.co')
        #session['username']=username
    return redirect(url)


#@bp.route('/api/v1/create_client', methods=('GET', 'POST'))
""" gestion des grant client 
"""
def create_client():
    check_login()
    user = current_user()
    if not user:
        return redirect('/api/v1')
    if request.method == 'GET':
        return render_template('/oauth/create_client.html')
    client_id = gen_salt(24)
    client_id_issued_at = int(time.time())
    client = OAuth2Client(
        client_id=client_id,
        client_id_issued_at=client_id_issued_at,
        user_id=user.id,
    )
    form = request.form
    client_metadata = {
        "client_name": form["client_name"],
        "client_uri": form["client_uri"],
        "grant_types": split_by_crlf(form["grant_type"]),
        "redirect_uris": split_by_crlf(form["redirect_uri"]),
        "response_types": split_by_crlf(form["response_type"]),
        "scope": form["scope"],
        "token_endpoint_auth_method": form["token_endpoint_auth_method"]
    }
    client.set_client_metadata(client_metadata)
    if form['token_endpoint_auth_method'] == 'none':
        client.client_secret = ''
    else:
        client.client_secret = gen_salt(48)
    db.session.add(client)
    db.session.commit()
    return redirect('/api/v1')

#@bp.route('/oauth/revoke', methods=['POST'])
def revoke_token():
    check_login()
    return authorization.create_endpoint_response('revocation')

#@bp.route('/api/v1/oauth/token', methods=['POST'])
def issue_token():
    response = authorization.create_token_response()
    return response

# AUTHORIZATION CODE
#@route('/api/v1/authorize', methods=['GET', 'POST'])
def authorize(mode):
    user = current_user()
    scope_list=['openid', 'profile', 'resume', 'partner', 'referent', 'proof_of_identity', 'birthdate', 'email', 'phone', 'about']
    # if user log status is not true (Auth server), then to log it in
    if not user:
        return redirect(url_for('oauth_login', next=request.url))
    # GET
    if request.method == 'GET':
        try:
            grant = authorization.validate_consent_request(end_user=user)
        except OAuth2Error as error:
            return error.error
        checkbox = {key: 'checked' if key in grant.request.scope else ""  for key in scope_list}
        #ask for consent
        return render_template('/oauth/oauth_authorize.html', user=user, grant=grant,**checkbox)
    # POST
    if not user and 'username' in request.form:
        username = request.form.get('username')
        user = User.query.filter_by(username=username).first()
    if 'reject' in request.form :
        grant_user = None
        return authorization.create_authorization_response(grant_user=grant_user)
    # update scopes after consent
    query_dict = parse_qs(request.query_string.decode("utf-8"))
    my_scope = "openid "
    for scope in scope_list :
        if request.form.get(scope) == "on" :
            my_scope = my_scope + scope + " "
    query_dict["scope"] = my_scope
    # we setup a custom Oauth2Request as we have changed the scope in the query_dict
    req = OAuth2Request("POST", request.base_url + "?" + urlencode(query_dict, doseq=True))
    return authorization.create_authorization_response(grant_user=user, request=req)


#  AUTHORIZATION CODE ENDPOINT

#route('/api/v1/user_info')
@require_oauth('openid profile email phone birthdate address proof_of_identity about resume', 'OR')
def user_info(mode):
    user_id = current_token.user_id
    user_workspace_contract = get_user_workspace(user_id,mode)
    user_info = dict()
    profile = read_profil(user_workspace_contract, mode, 'full')[0]
    user_info['sub'] = 'did:talao:' + mode.BLOCKCHAIN +':' + user_workspace_contract[2:]
    if 'profile' in current_token.scope :
        user_info['given_name'] = profile.get('firstname')
        user_info['family_name'] = profile.get('lastname')
        user_info['gender'] = profile.get('gender')
    if 'email' in current_token.scope :
        user_info['email']= profile.get('contact_email') if profile.get('contact_email') != 'private' else None
    if 'phone' in current_token.scope :
        user_info['phone']= profile.get('contact_phone') if profile.get('contact_phone') != 'private' else None
    if 'birthdate' in current_token.scope :
        user_info['birthdate'] = profile.get('birthdate') if profile.get('birthdate') != 'private' else None
    if 'address' in current_token.scope :
        user_info['address'] = profile.get('address') if profile.get('address') != 'private' else None
    if 'resume' in current_token.scope :
        user_info['resume'] = 'Not implemented yet'
    if 'proof_of_identity' in current_token.scope :
        user_info['proof_of_identity'] = 'Not implemented yet'
    if 'about' in current_token.scope :
        user_info['about'] = profile.get('about') if profile.get('about') != 'private' else None

    # setup response
    response = Response(json.dumps(user_info), status=200, mimetype='application/json')
    return response


#route('/api/v1/user_accepts_company_referent')
@require_oauth('user_manages_referent')
def user_accepts_company_referent(mode):
    user_id = current_token.user_id
    user_workspace_contract = get_user_workspace(user_id,mode)
    user_address = contractsToOwners(user_workspace_contract, mode)
    client_id = current_token.client_id
    client_workspace_contract = get_client_workspace(client_id, mode)
    client_address = contractsToOwners(client_workspace_contract, mode)
    # add key 20002
    if 'referent' in current_token.scope and not has_key_purpose(user_workspace_contract, client_address, 20002, mode) :
        relay_private_key = privatekey.get_key(mode.relay_address,'private_key', mode)
        add_key(mode.relay_address, mode.relay_workspace_contract, user_address, user_workspace_contract, relay_private_key, client_address, 20002 , mode, synchronous=False)
        referent = True
    referent = has_key_purpose(user_workspace_contract, client_address, 20002, mode)
    # setup response
    response = Response(json.dumps({'referent' : referent}), status=200, mimetype='application/json')
    return response



#route('/api/v1/user_accepts_company_partnership')
@require_oauth('user_manages_partner')
def user_accepts_company_partnership(mode):
    user_id = current_token.user_id
    user_workspace_contract = get_user_workspace(user_id,mode)
    user_address = contractsToOwners(user_workspace_contract, mode)
    client_id = current_token.client_id
    client_workspace_contract = get_client_workspace(client_id, mode)
    client_address = contractsToOwners(client_workspace_contract, mode)

    # client requests partnership to user
    if "partner" in current_token.scope and not is_partner(user_address, client_workspace_contract, mode) :
        client_address = contractsToOwners(client_workspace_contract, mode)
        relay_private_key = privatekey.get_key(mode.relay_address,'private_key', mode)
        client_rsa_key = privatekey.get_key(client_address,'rsa_key', mode)
        partnershiprequest(mode.relay_address, mode.relay_workspace_contract, client_address, client_workspace_contract, relay_private_key, user_workspace_contract, client_rsa_key, mode, synchronous=False) 

    # user accepts client request for partnership if not already partner
    if 'partner' in current_token.scope and not is_partner(client_address, user_workspace_contract,mode) :
        relay_private_key = privatekey.get_key(mode.relay_address,'private_key', mode)
        user_rsa_key = privatekey.get_key(user_address, 'rsa_key', mode)
        authorize_partnership(mode.relay_address, mode.relay_workspace_contract, user_address, user_workspace_contract, relay_private_key, client_workspace_contract, user_rsa_key, mode, synchronous=True)

    partnership_in_identity,partnership_in_partner  = get_partner_status(user_address, client_workspace_contract,mode)
    # setup response
    response = Response(json.dumps({'partnership_in_identity' : partnership_in_identity, 'partnership_in_partner' : partnership_in_partner}), status=200, mimetype='application/json')
    return response





# issue a certificates on behalf of user
#@route('/api/v1/user_issues_certificate')
@require_oauth('user_issues_certificate')
def oauth_user_issues_certificate(mode):
    user_id = current_token.user_id
    issued_by_workspace_contract = get_user_workspace(user_id,mode)
    issued_by_address = contractsToOwners(issued_by_workspace_contract, mode)
    #client_id=current_token.client_id
    #client_workspace_contract = get_client_workspace(client_id, mode)
    #client_address = contractsToOwners(client_workspace_contract, mode)
    data = json.loads(request.data.decode("utf-8"))
    try :
        issued_to_workspace_contract = '0x' + data['did_issued_to'].split(':')[3]
        issued_to_address = contractsToOwners(issued_to_workspace_contract, mode)
        issued_by_private_key = privatekey.get_key(issued_by_address,'private_key', mode)
        certificate = data['certificate']
        certificate_type = data['certificate_type']
    except :
        response_dict = {'detail' : 'did or request malformed '}
        response = Response(json.dumps(response_dict), status=400, mimetype='application/json')
        return response
    if not issued_to_address or not issued_by_address :
        response_dict = {'detail' : 'did does not exist'}
        response = Response(json.dumps(response_dict), status=400, mimetype='application/json')
        return response
    issued_to_profil, c = read_profil(issued_to_workspace_contract, mode, 'full')
    issued_by_profil, c = read_profil(issued_by_workspace_contract, mode, 'full')
    certificate['type'] = certificate_type
    certificate['version'] = 1
    certificate["issued_by"]  = {
		"name" : issued_by_profil['name'],
		"postal_address" : issued_by_profil['postal_address'],
		"siret" : issued_by_profil['siret'],
		"logo" :get_image(issued_by_workspace_contract, 'logo', mode),
		"signature" : get_image(issued_by_workspace_contract, 'signature', mode),
        "manager" : "Director",
		}
    certificate["issued_to"]  = {
		"name" : issued_to_profil['name'],
		"postal_address" : issued_to_profil['postal_address'],
		"siret" : issued_to_profil['siret'],
		"logo" : get_image(issued_to_workspace_contract, 'logo', mode),
		"signature" : get_image(issued_to_workspace_contract, 'signature', mode),
		}
    my_certificate = Document('certificate')
    document_id, ipfs_hash, transaction_hash = my_certificate.add(issued_by_address,
                        issued_by_workspace_contract,
                        issued_to_address,
                        issued_to_workspace_contract,
                        issued_by_private_key,
                        certificate,
                        mode,
                        mydays=0,
                        privacy='public')
    if not document_id :
        response_dict = {'detail' : 'transaction failed, check if companies have correct referent status'}
        response = Response(json.dumps(response_dict), status=400, mimetype='application/json')
        return response
    response_dict = {'link' : mode.server + 'certificate/?certificate_id=did:talao:' + mode.BLOCKCHAIN + ':' + issued_by_workspace_contract[2:] + ':document:' + str(document_id),
                      **certificate, 'ipfs hash' : ipfs_hash, 'transaction hash' : transaction_hash}
    response = Response(json.dumps(response_dict), status=200, mimetype='application/json')
    return response

############################################ CLIENT CREDENTIAL ENDPOINT ######################################################################

# create a person identity with a key2002 key and partnership
#@route('/api/v1/create_person_identity')
@require_oauth('create_person_identity')
def oauth_create_person_identity(mode):
    # creation d'une identité"
    client_id = current_token.client_id
    client_workspace_contract = get_client_workspace(client_id, mode)
    data = json.loads(request.data.decode("utf-8"))
    if data.get('email') is None or data.get('firstname') is None or data.get('lastname')is None :
        response_dict = {'detail' : 'request malformed'}
        response = Response(json.dumps(response_dict), status=400, mimetype='application/json')
        return response
    creator = None if client_workspace_contract is None else contractsToOwners(client_workspace_contract, mode)
    identity_username = ns.build_username(data.get('firstname'), data.get('lastname'), mode)
    try :
        identity_workspace_contract = createidentity.create_user(identity_username, data.get('email'), mode, creator=creator, partner=True)[2]
    except :
        response_dict = {'detail' : 'Blockchain failure, contact Talao support '}
        response = Response(json.dumps(response_dict), status=400, mimetype='application/json')
        return response
    # createidentity other problems
    if identity_workspace_contract is None :
        response_dict = {'detail' : 'Create Identity failure, contact Talao support '}
        response = Response(json.dumps(response_dict), status=400, mimetype='application/json')
        return response
    response_dict = {'did' : 'did:talao:' + mode.BLOCKCHAIN + ':' + identity_workspace_contract[2:], 'username' : identity_username, **data}
    response = Response(json.dumps(response_dict), status=200, mimetype='application/json')
    return response

# create a company identity with key20002 and partnership
#@route('/api/v1/create_company_identity')
@require_oauth('create_company_identity')
def oauth_create_company_identity(mode):
    # creation d'une identité"
    client_id = current_token.client_id
    client_workspace_contract = get_client_workspace(client_id, mode)
    data = json.loads(request.data.decode("utf-8"))
    if not data.get('email') or not data.get('name') :
        response_dict = {'detail' : 'request malformed'}
        response = Response(json.dumps(response_dict), status=400, mimetype='application/json')
        return response
    creator = None if not client_workspace_contract else contractsToOwners(client_workspace_contract, mode)
    identity_username = data.get('name').lower()
    if ns.username_exist(identity_username, mode)   :
        identity_username = identity_username + str(random.randint(1, 100))
    try :
        identity_workspace_contract = createcompany.create_company(identity_username, data.get('email'), mode, creator=creator, partner=True)[2]
    except :
        response_dict = {'detail' : 'Blockchain failure, contact Talao support '}
        response = Response(json.dumps(response_dict), status=400, mimetype='application/json')
        return response
    # createidentity other problems
    if not identity_workspace_contract :
        response_dict = {'detail' : 'Create Identity failure, contact Talao support '}
        response = Response(json.dumps(response_dict), status=400, mimetype='application/json')
        return response
    response_dict = {'did' : 'did:talao:' + mode.BLOCKCHAIN + ':' + identity_workspace_contract[2:], 'username' : identity_username, **data}
    response = Response(json.dumps(response_dict), status=200, mimetype='application/json')
    return response

"""
# request partnership
#@route('/api/v1/request_partnership')
@require_oauth(None)
def oauth_request_partnership(mode):
    client_id=current_token.client_id
    client_workspace_contract = get_client_workspace(client_id, mode)
    client_address = contractsToOwners(client_workspace_contract, mode)
    relay_private_key = privatekey.get_key(mode.relay_address,'private_key', mode)
    client_rsa_key = privatekey.get_key(client_address,'rsa_key', mode)
    data = json.loads(request.data.decode("utf-8"))
    user_workspace_contract = ns.get_data_from_username(data['username'], mode).get('workspace_contract')
    if not partnershiprequest(mode.relay_address, mode.relay_workspace_contract, client_address, client_workspace_contract, relay_private_key, user_workspace_contract, client_rsa_key, mode) :
        response_dict = {'detail' : 'Failed to request parnership, contact Talao support '}
        response = Response(json.dumps(response_dict), status=400, mimetype='application/json')
        return response
    else :
        response_dict = {'did' : 'did:talao:' + mode.BLOCKCHAIN + ':' + user_workspace_contract[2:], **data}
    response = Response(json.dumps(response_dict), status=200, mimetype='application/json')
    return response
"""


# get status
#@route('/api/v1/get_status')
@require_oauth(None)
def oauth_get_status(mode):
    client_id=current_token.client_id
    client_workspace_contract = get_client_workspace(client_id, mode)
    client_address = contractsToOwners(client_workspace_contract, mode)
    data = json.loads(request.data.decode("utf-8"))
    try :
        user_workspace_contract = '0x' + data['did'].split(':')[3]
        user_address = contractsToOwners(user_workspace_contract, mode)
        referent = has_key_purpose(user_workspace_contract, client_address, 20002, mode)
        partnership_in_identity,partnership_in_partner  = get_partner_status(user_address, client_workspace_contract,mode)
    except :
        response_dict = {'detail' : 'did or request malformed '}
        response = Response(json.dumps(response_dict), status=400, mimetype='application/json')
        return response
    response_dict = {'partnernship_in_identity' : partnership_in_identity , 'partnership_in_partner_identity' : partnership_in_partner, 'referent' : referent}
    response = Response(json.dumps(response_dict), status=200, mimetype='application/json')
    return response


# issue experience certificates
#@route('/api/v1/issue_experience')
@require_oauth('experience')
def oauth_issue_experience(mode):
    client_id=current_token.client_id
    client_workspace_contract = get_client_workspace(client_id, mode)
    client_address = contractsToOwners(client_workspace_contract, mode)
    client_private_key = privatekey.get_key(client_address,'private_key', mode)
    data = json.loads(request.data.decode("utf-8"))
    try :
        user_workspace_contract = '0x' + data['did'].split(':')[3]
        user_address = contractsToOwners(user_workspace_contract, mode)
        certificate = data['certificate']
    except :
        response_dict = {'detail' : 'did or request malformed '}
        response = Response(json.dumps(response_dict), status=400, mimetype='application/json')
        return response
    if user_address is None :
        response_dict = {'detail' : 'did does not exist'}
        response = Response(json.dumps(response_dict), status=400, mimetype='application/json')
        return response
    certificate['type'] = 'experience'
    certificate['version'] = 1
    certificate['logo'] = get_image(client_workspace_contract, 'logo', mode)
    certificate['signature'] = get_image(client_workspace_contract, 'signature', mode)
    certificate['manager'] = 'Director'
    certificate['reviewer'] = ''
    my_certificate = Document('certificate')
    document_id, ipfs_hash, transaction_hash = my_certificate.add(client_address,
                        client_workspace_contract,
                        user_address,
                        user_workspace_contract,
                        client_private_key,
                        certificate,
                        mode,
                        mydays=0,
                        privacy='public')
    if document_id is None :
        response_dict = {'detail' : 'transaction failed'}
        response = Response(json.dumps(response_dict), status=400, mimetype='application/json')
        return response
    response_dict = {'link' : mode.server + 'certificate/?certificate_id=did:talao:' + mode.BLOCKCHAIN + ':' + user_workspace_contract[2:] + ':document:' + str(document_id),
                      **certificate, 'ipfs hash' : ipfs_hash, 'transaction hash' : transaction_hash}
    response = Response(json.dumps(response_dict), status=200, mimetype='application/json')
    return response



# issue an agrement certificates
#@route('/api/v1/issue_agreement')
@require_oauth('agreement')
def oauth_issue_agreement(mode):
    client_id=current_token.client_id
    client_workspace_contract = get_client_workspace(client_id, mode)
    client_address = contractsToOwners(client_workspace_contract, mode)
    client_private_key = privatekey.get_key(client_address,'private_key', mode)
    data = json.loads(request.data.decode("utf-8"))
    print('client private key = ', client_private_key)
    print('client address = ', client_address)
    print('client workspace contract = ', client_workspace_contract)
    try :
        user_workspace_contract = '0x' + data['did'].split(':')[3]
        user_address = contractsToOwners(user_workspace_contract, mode)
        certificate = data['certificate']
    except :
        response_dict = {'detail' : 'did or request malformed '}
        response = Response(json.dumps(response_dict), status=400, mimetype='application/json')
        return response
    if user_address is None :
        response_dict = {'detail' : 'did does not exist'}
        response = Response(json.dumps(response_dict), status=400, mimetype='application/json')
        return response
    user_profil, c = read_profil(user_workspace_contract, mode, 'full')
    client_profil, c = read_profil(client_workspace_contract, mode, 'full')
    certificate['type'] = 'agreement'
    certificate['version'] = 1
    certificate["issued_by"]  = {
		"name" : client_profil['name'],
		"postal_address" : client_profil['postal_address'],
		"siret" : client_profil['siret'],
		"logo" :get_image(client_workspace_contract, 'logo', mode),
		"signature" : get_image(client_workspace_contract, 'signature', mode),
        "manager" : "Director",
		}
    certificate["issued_to"]  = {
		"name" : user_profil['name'],
		"postal_address" : user_profil['postal_address'],
		"siret" : user_profil['siret'],
		"logo" : get_image(user_workspace_contract, 'logo', mode),
		"signature" : get_image(user_workspace_contract, 'signature', mode),
		}
    my_certificate = Document('certificate')
    document_id, ipfs_hash, transaction_hash = my_certificate.add(client_address,
                        client_workspace_contract,
                        user_address,
                        user_workspace_contract,
                        client_private_key,
                        certificate,
                        mode,
                        mydays=0,
                        privacy='public')
    if document_id is None :
        response_dict = {'detail' : 'transaction failed'}
        response = Response(json.dumps(response_dict), status=400, mimetype='application/json')
        return response
    response_dict = {'link' : mode.server + 'certificate/?certificate_id=did:talao:' + mode.BLOCKCHAIN + ':' + user_workspace_contract[2:] + ':document:' + str(document_id),
                      **certificate, 'ipfs hash' : ipfs_hash, 'transaction hash' : transaction_hash}
    response = Response(json.dumps(response_dict), status=200, mimetype='application/json')
    return response



# issue a reference certificates
#@route('/api/v1/issue_reference')
@require_oauth('reference')
def oauth_issue_reference(mode):
    client_id=current_token.client_id
    client_workspace_contract = get_client_workspace(client_id, mode)
    client_address = contractsToOwners(client_workspace_contract, mode)
    client_private_key = privatekey.get_key(client_address,'private_key', mode)
    data = json.loads(request.data.decode("utf-8"))
    try :
        user_workspace_contract = '0x' + data['did'].split(':')[3]
        user_address = contractsToOwners(user_workspace_contract, mode)
        certificate = data['certificate']
    except :
        response_dict = {'detail' : 'did or request malformed '}
        response = Response(json.dumps(response_dict), status=400, mimetype='application/json')
        return response
    if user_address is None :
        response_dict = {'detail' : 'did does not exist'}
        response = Response(json.dumps(response_dict), status=400, mimetype='application/json')
        return response
    user_profil, c = read_profil(user_workspace_contract, mode, 'full')
    client_profil, c = read_profil(client_workspace_contract, mode, 'full')
    certificate['type'] = 'reference'
    certificate['version'] = 1
    certificate["issued_by"]  = {
		"name" : client_profil['name'],
		"postal_address" : client_profil['postal_address'],
		"siret" : client_profil['siret'],
		"logo" :get_image(client_workspace_contract, 'logo', mode),
		"signature" : get_image(client_workspace_contract, 'signature', mode),
        "manager" : "Director",
		}
    certificate["issued_to"]  = {
		"name" : user_profil['name'],
		"postal_address" : user_profil['postal_address'],
		"siret" : user_profil['siret'],
		"logo" : get_image(user_workspace_contract, 'logo', mode),
		"signature" : get_image(user_workspace_contract, 'signature', mode),
		}
    my_certificate = Document('certificate')
    document_id, ipfs_hash, transaction_hash = my_certificate.add(client_address,
                        client_workspace_contract,
                        user_address,
                        user_workspace_contract,
                        client_private_key,
                        certificate,
                        mode,
                        mydays=0,
                        privacy='public')
    if document_id is None :
        response_dict = {'detail' : 'transaction failed, check if this your company is a referent'}
        response = Response(json.dumps(response_dict), status=400, mimetype='application/json')
        return response
    response_dict = {'link' : mode.server + 'certificate/?certificate_id=did:talao:' + mode.BLOCKCHAIN + ':' + user_workspace_contract[2:] + ':document:' + str(document_id),
                      **certificate, 'ipfs hash' : ipfs_hash, 'transaction hash' : transaction_hash}
    response = Response(json.dumps(response_dict), status=200, mimetype='application/json')
    return response


# get a list of certificate
#@route('/api/v1/get_certificate_list')
@require_oauth(None)
def oauth_get_certificate_list(mode):
    client_id=current_token.client_id
    client_workspace_contract = get_client_workspace(client_id, mode)
    client_address = contractsToOwners(client_workspace_contract, mode)
    data = json.loads(request.data.decode("utf-8"))
    try :
        user_workspace_contract = '0x' + data['did'].split(':')[3]
        user_address = contractsToOwners(user_workspace_contract, mode)
        certificate_type = data['certificate_type']
    except :
        response_dict = {'detail' : 'did or request malformed '}
        response = Response(json.dumps(response_dict), status=400, mimetype='application/json')
        return response
    if user_address is None :
        response_dict = {'detail' : 'did does not exist'}
        response = Response(json.dumps(response_dict), status=400, mimetype='application/json')
        return response
    # check if client is in the partner list of identity
    if not is_partner(client_address, user_workspace_contract, mode):
        response_dict = {'detail' : 'Your company is not in the partner list of this Identity'}
        response = Response(json.dumps(response_dict), status=400, mimetype='application/json')
        return response
    contract = mode.w3.eth.contract(user_workspace_contract,abi = constante.workspace_ABI)
    certificate_list = list()
    for doc_id in contract.functions.getDocuments().call() :
        if contract.functions.getDocument(doc_id).call()[0] == 20000 :
            certificate = Document('certificate')
            if certificate.relay_get(user_workspace_contract, doc_id, mode, loading='light') :
                if certificate.type == certificate_type :
                    certificate_list.append(data['did'] + ':document:' + str(doc_id))
    response_dict = {'certificate_list' : certificate_list}
    response = Response(json.dumps(response_dict), status=200, mimetype='application/json')
    return response