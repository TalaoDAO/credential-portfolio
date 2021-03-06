from flask import jsonify
import logging

logging.basicConfig(level=logging.INFO)
DID_WEB = 'did:web:talao.co'
DID_ETHR = 'did:ethr:0xee09654eedaa79429f8d216fa51a129db0f72250'
DID_TZ2 = 'did:tz:tz2NQkPq3FFA3zGAyG8kLcWatGbeXpHMu7yk'
DID_KEY = 'did:key:zQ3shWBnQgxUBuQB2WGd8iD22eh7nWC4PTjjTjEgYyoC3tjHk'
DID_PLAYGROUND = "did:ethr:0xd6008c16068c40c05a5574525db31053ae8b3ba7"
DID_TZ1 = "did:tz:tz1NyjrTUNxDpPaqNZ84ipGELAcTWYg6s5Du"
DID_ISSUER = "did:tz:tz2UFjbN9ZruP5pusKoAKiPD3ZLV49CBG9Ef"

LIST_TRUSTED_ISSUER_REGISTRY_API = 'https://tmd.list.lu:1234/tmd/get_data_issuer/'

def init_app(app) :
    app.add_url_rule('/trusted-issuers-registry/v1/issuers/<did>',  view_func=tir_api, methods = ['GET'])
    return

def tir_api(did) :
    """
    Issuer Registry public JSON API GET:
    https://ec.europa.eu/cefdigital/wiki/display/EBSIDOC/1.3.2.4.+Trusted+Registries+ESSIF+v2#id-1.3.2.4.TrustedRegistriesESSIFv2-TrustedIssuerRegistryEntry-TIR(generic)
    https://ec.europa.eu/cefdigital/wiki/display/EBSIDOC/Trusted+Issuers+Registry+API

    """
    logging.info("Registry look up for DID = %s", did)
    
    if did in [DID_WEB, DID_ETHR, DID_TZ2, DID_KEY, DID_TZ1, DID_PLAYGROUND, DID_ISSUER] :
        logging.info("Great ! This is a Talao trusted issuer")
        return jsonify({
            "issuer": {
                "preferredName": "Talao",
                "did": ["did:web:talao.co",
                        "did:ethr:0xee09654eedaa79429f8d216fa51a129db0f72250",
                        "did:tz:tz2NQkPq3FFA3zGAyG8kLcWatGbeXpHMu7yk",
                        "did:ethr:0xd6008c16068c40c05a5574525db31053ae8b3ba7",
                        "did:tz:tz1NyjrTUNxDpPaqNZ84ipGELAcTWYg6s5Du",
                        "did:tz:tz2UFjbN9ZruP5pusKoAKiPD3ZLV49CBG9Ef"],
                "eidasCertificatePem": [{}],
                "serviceEndpoints": [{}, {}],
                "organizationInfo": {
                    "id": "837674480",
                    "legalName": "Talao SAS",
                    "currentAddress": "Talao, 16 rue de Wattignies, 75012 Paris, France",
                    "vatNumber": "FR26837674480",
                    "website": "https://talao.co",
                    "issuerDomain" : ["talao.co",
                                     "issuer.talao.co",
                                  "talao.io",
                                   "tezotopia.talao.co",
                                    "playground.talao.co",
                                     "api.generator.talao.co",
                                     "generator.talao.co",
                                     "api.issuer.tezotopia.altme.io"]
                }
            }
        })
    elif did in ["did:tz:tz1RuLH4TvKNpLy3AqQMui6Hys6c1Dvik8J5",
                  "did:tz:tz2X3K4x7346aUkER2NXSyYowG23ZRbueyse",
                  "did:ethr:0x61fb76ff95f11bdbcd94b45b838f95c1c7307dbd"] :
        return jsonify({
            "issuer": {
                "preferredName": "Tezotopia issuer",
                "did": ["did:tz:tz1RuLH4TvKNpLy3AqQMui6Hys6c1Dvik8J5",
                 "did:tz:tz2X3K4x7346aUkER2NXSyYowG23ZRbueyse",
                  "did:ethr:0x61fb76ff95f11bdbcd94b45b838f95c1c7307dbd"],
                "eidasCertificatePem": [{}],
                "serviceEndpoints": [{}, {}],
                "organizationInfo": {
                    "id": "837674480",
                    "legalName": "Tezotopia issuer",
                    "currentAddress": "",
                    "vatNumber": "",
                    "website": "https://tezotopia.com/app",
                    "issuerDomain" : ["api.issuer.tezotopia.altme.io"]
                }
            }
        })
    elif did in ["did:ethr:0x6Ad8372F03d2b16701c9989d3043fE27C1f8e2FE".lower(), "did:tz:tz2CWTBwgUbs1BMXAjzUvrEk8gRhS6eLqzRD"] :
        return jsonify({
            "issuer": {
                "preferredName": "Wallet test",
                "did": ["did:ethr:0x6Ad8372F03d2b16701c9989d3043fE27C1f8e2FE".lower()],
                "eidasCertificatePem": [{}],
                "serviceEndpoints": [{}, {}],
                "organizationInfo": {
                    "id": "837674480",
                    "legalName": "Demo for wallet",
                    "currentAddress": "16 rue de Bessieres, 75010 Paris",
                    "vatNumber": "FR26837677777",
                    "website": "https://demo.talap.co",
                    "issuerDomain" : ["demo.talao.co"]
                }
            }
        })
    else :
        logging.warning("Issuer not found in the Talao registry")
        return jsonify("Issuer not found") , 404
        

