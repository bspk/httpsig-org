import json
try:
    from http_parser.parser import HttpParser
except ImportError:
    from http_parser.pyparser import HttpParser

import http_sfv
from urllib.parse import parse_qs

from Cryptodome.Signature import pss
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Signature import DSS
from Cryptodome.Hash import SHA512
from Cryptodome.Hash import SHA256
from Cryptodome.Hash import HMAC
from Cryptodome.PublicKey import RSA
from Cryptodome.PublicKey import ECC
from Cryptodome import Random
from Cryptodome.IO import PEM
from Cryptodome.IO import PKCS8
from Cryptodome.Signature.pss import MGF1
from Cryptodome.Util.asn1 import DerOctetString
from Cryptodome.Util.asn1 import DerBitString
from Cryptodome.Util.asn1 import DerSequence
from nacl.signing import SigningKey
from nacl.signing import VerifyKey

import base64

from httpsig import *

# used with RSA-PSS and jose PS512
mgf512 = lambda x, y: MGF1(x, y, SHA512)
# used with jose PS384
mgf384 = lambda x, y: MGF1(x, y, SHA384)
# used with jose PS256
mgf256 = lambda x, y: MGF1(x, y, SHA256)

def cors(event, controller):
    return {
        'statusCode': 200,
        'headers': {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "OPTIONS,POST,GET"
        }
    }

def parse(event, context):
    if 'body' not in event:
        return {
            'statusCode': 400,
            'headers': {
                "Access-Control-Allow-Origin": "*"
            },
            'body': json.dumps({
                'error': 'No input to parse'
            })
        }
    
    msg = event['body'].encode('utf-8')
    response = parse_components(msg)
    return {
        'statusCode': 200,
        'headers': {
            "Access-Control-Allow-Origin": "*"
        },
        'body': json.dumps(response)
    }

def base(event, context):
    if 'body' not in event:
        return {
            'statusCode': 400,
            'headers': {
                "Access-Control-Allow-Origin": "*"
            },
            'body': json.dumps({
                'error': 'No input to process'
            })
        }
    
    data = json.loads(event['body'])
    #print(data)
    msg = data['msg'].encode('utf-8')
    # re-parse the input message (TODO: should we send the parsed components instead?)
    components = parse_components(msg)
    
    params = data['params']
    
    response = generate_input(
        components,
        data['coveredComponents'],
        params
    )

   #print(base)
    return {
        'statusCode': 200,
        'headers': {
            "Access-Control-Allow-Origin": "*"
        },
        'body': json.dumps(response)
    }
    
def sign(event, context):
    if 'body' not in event:
        return {
            'statusCode': 400,
            'headers': {
                "Access-Control-Allow-Origin": "*"
            },
            'body': json.dumps({
                'error': 'No input to sign'
            })
        }
    
    data = json.loads(event['body'])

    siginput = data['signatureInput']
    sigparams = data['signatureParams']
    signingKeyType = data['signingKeyType']
    alg = data['alg']
    label = data['label']
    
    key = None
    sharedKey = None
    jwk = None
    
    if signingKeyType == 'x509':
        key = parseKeyX509(data['signingKeyX509'])
    elif signingKeyType == 'shared':
        if alg != 'hmac-sha256':
            # shared key type only good for hmac
            return {
                'statusCode': 400,
                'headers': {
                    "Access-Control-Allow-Origin": "*"
                },
                'body': json.dumps({
                    'error': 'Shared key with bad algorithm: ' + alg
                })
            }
        
        sharedKey = data['signingKeyShared'].encode('utf-8')
    elif signingKeyType == 'jwk':
        key, jwk, sharedKey = parseKeyJwk(data['signingKeyJwk'])
    else:
        # unknown key type
        return {
            'statusCode': 400,
            'headers': {
                "Access-Control-Allow-Origin": "*"
            },
            'body': json.dumps({
                'error': 'Unknown key type: ' + signingKeyType
            })
        }
    
    if alg == 'jose' and signingKeyType != 'jwk':
        # JOSE-driven algorithm choice only available for JWK formatted keys
        return {
            'statusCode': 400,
            'headers': {
                "Access-Control-Allow-Origin": "*"
            },
            'body': json.dumps({
                'error': 'JOSE algorithm requires JWK formatted key, not ' + signingKeyType
            })
        }
        
    if alg == 'rsa-pss-sha512':
        h = SHA512.new(siginput.encode('utf-8'))
        signer = pss.new(key, mask_func=mgf512, salt_bytes=64)

        signed = http_sfv.Item(signer.sign(h))
    elif alg == 'rsa-v1_5-sha256':
        h = SHA256.new(siginput.encode('utf-8'))
        signer = pkcs1_15.new(key)
    
        signed = http_sfv.Item(signer.sign(h))
    elif alg == 'ecdsa-p256-sha256':
        h = SHA256.new(siginput.encode('utf-8'))
        signer = DSS.new(key, 'fips-186-3')
    
        signed = http_sfv.Item(signer.sign(h))
    elif alg == 'hmac-sha256':
        signer = HMAC.new(sharedKey, digestmod=SHA256)
        signer.update(siginput.encode('utf-8'))
        
        signed = http_sfv.Item(signer.digest())
    elif alg == 'ed25519':
        h = siginput.encode('utf-8')
        signed = http_sfv.Item(key.sign(h).signature)
    elif alg == 'jose':
        # we're doing JOSE algs based on the key value
        if (not 'alg' in jwk) or (jwk['alg'] == 'none'):
            # unknown algorithm
            return {
                'statusCode': 400,
                'headers': {
                    "Access-Control-Allow-Origin": "*"
                },
                'body': json.dumps({
                    'error': 'JWK algorithm not found'
                })
            }
        elif jwk['alg'] == 'RS256':
            h = SHA256.new(siginput.encode('utf-8'))
            signer = pkcs1_15.new(key)
        
            signed = http_sfv.Item(signer.sign(h))
        elif jwk['alg'] == 'RS384':
            h = SHA384.new(siginput.encode('utf-8'))
            signer = pkcs1_15.new(key)
        
            signed = http_sfv.Item(signer.sign(h))
        elif jwk['alg'] == 'RS512':
            h = SHA512.new(siginput.encode('utf-8'))
            signer = pkcs1_15.new(key)
        
            signed = http_sfv.Item(signer.sign(h))
        elif jwk['alg'] == 'PS256':
            h = SHA256.new(siginput.encode('utf-8'))
            signer = pss.new(key, mask_func=mgf256, salt_bytes=32)
        
            signed = http_sfv.Item(signer.sign(h))
        elif jwk['alg'] == 'PS384':
            h = SHA384.new(siginput.encode('utf-8'))
            signer = pss.new(key, mask_func=mgf384, salt_bytes=48)
        
            signed = http_sfv.Item(signer.sign(h))
        elif jwk['alg'] == 'PS512':
            h = SHA512.new(siginput.encode('utf-8'))
            signer = pss.new(key, mask_func=mgf512, salt_bytes=64)
        
            signed = http_sfv.Item(signer.sign(h))
        elif jwk['alg'] == 'HS256':
            signer = HMAC.new(sharedKey, digestmod=SHA256)
            signer.update(siginput.encode('utf-8'))
        
            signed = http_sfv.Item(signer.digest())
        elif jwk['alg'] == 'HS384':
            signer = HMAC.new(sharedKey, digestmod=SHA384)
            signer.update(siginput.encode('utf-8'))
        
            signed = http_sfv.Item(signer.digest())
        elif jwk['alg'] == 'HS256':
            signer = HMAC.new(sharedKey, digestmod=SHA512)
            signer.update(siginput.encode('utf-8'))
        
            signed = http_sfv.Item(signer.digest())
        elif jwk['alg'] == 'ES256':
            h = SHA256.new(siginput.encode('utf-8'))
            signer = DSS.new(key, 'fips-186-3')

            signed = http_sfv.Item(signer.sign(h))
        elif jwk['alg'] == 'ES384':
            h = SHA384.new(siginput.encode('utf-8'))
            signer = DSS.new(key, 'fips-186-3')

            signed = http_sfv.Item(signer.sign(h))
        elif jwk['alg'] == 'ES512':
            h = SHA512.new(siginput.encode('utf-8'))
            signer = DSS.new(key, 'fips-186-3')

            signed = http_sfv.Item(signer.sign(h))
        else:
            # unknown algorithm
            return {
                'statusCode': 400,
                'headers': {
                    "Access-Control-Allow-Origin": "*"
                },
                'body': json.dumps({
                    'error': 'Unknown JWK algorithm: ' + jwk['alg']
                })
            }
    else:
        # unknown algorithm
        return {
            'statusCode': 400,
            'headers': {
                "Access-Control-Allow-Origin": "*"
            },
            'body': json.dumps({
                'error': 'Unknown algorithm: ' + alg
            })
        }

    if not signed:
        return {
            'statusCode': 500,
            'headers': {
                "Access-Control-Allow-Origin": "*"
            },
            'body': json.dumps({
                'error': 'Failed to generate signature'
            })
        }
    
    
    # by here, we know that we have the signed blob
    #http_sfv.Item(signed)
    encoded = base64.b64encode(signed.value)
    
    sigparamheader = http_sfv.InnerList()
    sigparamheader.parse(sigparams.encode('utf-8'))
    
    siginputheader = http_sfv.Dictionary()
    siginputheader[label] = sigparamheader
    
    sigheader = http_sfv.Dictionary()
    sigheader[label] = signed
    
    headers = ''
    headers += 'Signature-Input: ' + str(siginputheader)
    headers += '\n'
    headers += 'Signature: ' + str(sigheader)
    
    response = {
        'signatureOutput': encoded.decode('utf-8'),
        'headers': headers
    }
    
    return {
        'statusCode': 200,
        'headers': {
            "Access-Control-Allow-Origin": "*"
        },
        'body': json.dumps(response)
    }

def verify(event, context):
    if not event['body']:
        return {
            'statusCode': 400,
            'headers': {
                "Access-Control-Allow-Origin": "*"
            },
            'body': json.dumps({
                'error': 'No input to verify'
            })
        }
    
    data = json.loads(event['body'])

    msg = data['httpMsg']
    siginput = data['signatureInput']
    sigparams = data['signatureParams']
    signingKeyType = data['signingKeyType']
    alg = data['alg']
    signature = http_sfv.Item()
    signature.parse(data['signature'].encode('utf-8')) # the parser needs to be called explicitly in this way or else this is treated as a string
    
    key = None
    sharedKey = None
    jwk = None
    
    if signingKeyType == 'x509':
        key = parseKeyX509(data['signingKeyX509'])
    elif signingKeyType == 'shared':
        if alg != 'hmac-sha256':
            # shared key type only good for hmac
            return {
                'statusCode': 400,
                'headers': {
                    "Access-Control-Allow-Origin": "*"
                },
                'body': json.dumps({
                    'error': 'Shared key used with invalid algorithm: ' + alg
                })
            }
        
        sharedKey = data['signingKeyShared'].encode('utf-8')
    elif signingKeyType == 'jwk':
        key, jwk, sharedKey = parseKeyJwk(data['signingKeyJwk'])
    else:
        # unknown key type
        return {
            'statusCode': 400,
            'headers': {
                "Access-Control-Allow-Origin": "*"
            },
            'body': json.dumps({
                'error': 'Unknown key type' + signingKeyType
            })
        }
    
    if alg == 'jose' and signingKeyType != 'jwk':
        # JOSE-driven algorithm choice only available for JWK formatted keys
        return {
            'statusCode': 400,
            'headers': {
                "Access-Control-Allow-Origin": "*"
            },
            'body': json.dumps({
                'error': 'JOSE signing algorithm requires JWK formatted key'
            })
        }
    
    try:
        verified = False
        if alg == 'rsa-pss-sha512':
            h = SHA512.new(siginput.encode('utf-8'))
            verifier = pss.new(key, mask_func=mgf512, salt_bytes=64)

            verifier.verify(h, signature.value)
            verified = True
        elif alg == 'rsa-v1_5-sha256':
            h = SHA256.new(siginput.encode('utf-8'))
            verifier = pkcs1_15.new(key)
    
            verifier.verify(h, signature.value)
            verified = True
        elif alg == 'ecdsa-p256-sha256':
            h = SHA256.new(siginput.encode('utf-8'))
            verifier = DSS.new(key, 'fips-186-3')
    
            verifier.verify(h, signature.value)
            verified = True
        elif alg == 'hmac-sha256':
            verifier = HMAC.new(sharedKey, digestmod=SHA256)
            verifier.update(siginput.encode('utf-8'))
        
            verified = (verifier.digest() == signature.value)
        elif alg == 'ed25519':
            h = siginput.encode('utf-8')
            verified = key.verify(h, signed.value)
        elif alg == 'jose':
            # we're doing JOSE algs based on the key value
            if (not 'alg' in jwk) or (jwk['alg'] == 'none'):
                # unknown algorithm
                return {
                    'statusCode': 400,
                    'headers': {
                        "Access-Control-Allow-Origin": "*"
                    },
                    'body': json.dumps({
                        'error': 'Algorithm not found in JWK'
                    })
                }
            elif jwk['alg'] == 'RS256':
                h = SHA256.new(siginput.encode('utf-8'))
                verifier = pkcs1_15.new(key)
    
                verifier.verify(h, signature.value)
                verified = True
            elif jwk['alg'] == 'RS384':
                h = SHA384.new(siginput.encode('utf-8'))
                verifier = pkcs1_15.new(key)
    
                verifier.verify(h, signature.value)
                verified = True
            elif jwk['alg'] == 'RS512':
                h = SHA512.new(siginput.encode('utf-8'))
                verifier = pkcs1_15.new(key)
    
                verifier.verify(h, signature.value)
                verified = True
            elif jwk['alg'] == 'PS256':
                h = SHA256.new(siginput.encode('utf-8'))
                verifier = pss.new(key, mask_func=mgf256, salt_bytes=32)

                verifier.verify(h, signature.value)
                verified = True
            elif jwk['alg'] == 'PS384':
                h = SHA384.new(siginput.encode('utf-8'))
                verifier = pss.new(key, mask_func=mgf384, salt_bytes=48)

                verifier.verify(h, signature.value)
                verified = True
            elif jwk['alg'] == 'PS512':
                h = SHA512.new(siginput.encode('utf-8'))
                verifier = pss.new(key, mask_func=mgf512, salt_bytes=64)

                verifier.verify(h, signature.value)
                verified = True
            elif jwk['alg'] == 'HS256':
                verifier = HMAC.new(sharedKey, digestmod=SHA256)
                verifier.update(siginput.encode('utf-8'))
        
                verified = (verifier.digest() == signature.value)
            elif jwk['alg'] == 'HS384':
                verifier = HMAC.new(sharedKey, digestmod=SHA384)
                verifier.update(siginput.encode('utf-8'))
        
                verified = (verifier.digest() == signature.value)
            elif jwk['alg'] == 'HS512':
                verifier = HMAC.new(sharedKey, digestmod=SHA512)
                verifier.update(siginput.encode('utf-8'))
        
                verified = (verifier.digest() == signature.value)
            elif jwk['alg'] == 'ES256':
                h = SHA256.new(siginput.encode('utf-8'))
                verifier = DSS.new(key, 'fips-186-3')
    
                verifier.verify(h, signature.value)
                verified = True
            elif jwk['alg'] == 'ES384':
                h = SHA384.new(siginput.encode('utf-8'))
                verifier = DSS.new(key, 'fips-186-3')
    
                verifier.verify(h, signature.value)
                verified = True
            elif jwk['alg'] == 'ES512':
                h = SHA512.new(siginput.encode('utf-8'))
                verifier = DSS.new(key, 'fips-186-3')
    
                verifier.verify(h, signature.value)
                verified = True
            else:
                # unknown algorithm
                return {
                    'statusCode': 400,
                    'headers': {
                        "Access-Control-Allow-Origin": "*"
                    },
                    'body': json.dumps({
                        'error': 'Unknown JWK algorithm: ' + jwk['alg']
                    })
                }
        else:
            # unknown algorithm
            return {
                'statusCode': 400,
                'headers': {
                    "Access-Control-Allow-Origin": "*"
                },
                'body': json.dumps({
                    'error': 'Unknown algorithm: ' + alg
                })
            }
    except (ValueError, TypeError) as err:
        verified = False

    response = {
        'signatureVerified': verified
    }
    
    return {
        'statusCode': 200,
        'headers': {
            "Access-Control-Allow-Origin": "*"
        },
        'body': json.dumps(response)
    }


def parseKeyJwk(signingKey):
    
    jwk = json.loads(signingKey)
    key = None
    sharedKey = None
    
    if jwk['kty'] == 'RSA':
        if 'd' in jwk:
            # private key
            if 'q' in jwk and 'p' in jwk:
                # CRT
                key = RSA.construct((
                    b64ToInt(jwk['n']),
                    b64ToInt(jwk['e']),
                    b64ToInt(jwk['d']),
                    b64ToInt(jwk['p']),
                    b64ToInt(jwk['q'])
                ))
            else:
                # no CRT
                key = RSA.construct((
                    b64ToInt(jwk['n']),
                    b64ToInt(jwk['e']),
                    b64ToInt(jwk['d'])
                ))
        else:
            # public key
            key = RSA.construct((
                b64ToInt(jwk['n']),
                b64ToInt(jwk['e'])
            ))
    elif jwk['kty'] == 'oct':
        sharedKey = base64.urlsafe_b64decode(jwk['k'] + '===')
    elif jwk['kty'] == 'EC':
        if 'd' in jwk:
            # private key
            key = ECC.construct(
                curve = jwk['crv'],
                d = b64ToInt(jwk['d']),
                point_x = b64ToInt(jwk['x']),
                point_y = b64ToInt(jwk['y'])
            )
        else:
            # public key
            key = ECC.construct(
                curve = jwk['crv'],
                point_x = b64ToInt(jwk['x']),
                point_y = b64ToInt(jwk['y'])
            )
    elif jwk['kty'] == 'OKP':
        return (None, None, None)
    else:
        return (None, None, None)
    
    return (key, jwk, sharedKey)

def b64ToInt(s):
    # convert string to integer
    if s:
        return int.from_bytes(base64.urlsafe_b64decode(s + '==='), 'big')
    else:
        return None

def parseKeyX509(signingKey):
    # try parsing a few different key formats

    key = None
    #print(1)
    # PKCS8 Wrapped Key
    try:
        #print(2)
        decoded = PEM.decode(signingKey)[0]
        #print(12)
        unwrapped = PKCS8.unwrap(decoded)[1]
        #print(3)
        try:
            # RSA first
            key = RSA.import_key(unwrapped)
            #print(4)
            
        except (ValueError, IndexError, TypeError):
            try:
                # EC if possible
                key = ECC.import_key(unwrapped)
                #print(5)
                
            except (ValueError, IndexError, TypeError):
                
                try:
                    # edDSA Key
                    der = DerOctetString()
                    der.decode(PKCS8.unwrap(PEM.decode(signingKey)[0])[1])
                    key = SigningKey(der.payload)
                except (ValueError) as err:
                    print(err)
                    key = None
                    #print(6)
                
    except (ValueError, IndexError, TypeError) as err:
        #print(err)
        key = None
        #print(7)
        
    
    # if we successfully parsed a key, return it
    if key:
        #print(8)
        
        return key
        
    # if there's no key yet, try an unwrapped certificate
    try:
        # Plain RSA Key
        key = RSA.import_key(signingKey)
        #print(9)
        
    except (ValueError, IndexError, TypeError):
        # plain EC key
        try:
            key = ECC.import_key(signingKey)
            #print(13)
        except (ValueError, IndexError, TypeError) as err:
            
            try:
                # edDSA key:
                # sequence of ID and BitString
                ds = DerSequence()
                ds.decode(PEM.decode(signingKey)[0])
                bs = DerBitString()
                bs.decode(ds[1])
                # the first byte of the bitstring is "0" for some reason??
                key = VerifyKey(bs.payload[1:])
            except (ValueError) as err:
                print(err)
                key = None
                #print(10)

    #print(11)
    return key
    