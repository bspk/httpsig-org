import json
try:
    from http_parser.parser import HttpParser
except ImportError:
    from http_parser.pyparser import HttpParser

import http_sfv
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
import base64

# used with RSA-PSS
mgf512 = lambda x, y: MGF1(x, y, SHA512)

def cors(event, controller):
    return {
        'statusCode': 200,
        'headers': {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "OPTIONS,POST,GET"
        }
    }

def parse(event, context):
    if not event['body']:
        return {
            'statusCode': 400,
            'headers': {
                "Access-Control-Allow-Origin": "*"
            }
        }
    
    msg = event['body'].encode('utf-8')
    p = HttpParser()
    p.execute(msg, len(msg))
    
    headers = [h.lower() for h in p.get_headers()]
    
    response = {
        'headers': headers
    }

    if 'signature-input' in p.get_headers():
        # existing signatures, parse the values
        siginputheader = http_sfv.Dictionary()
        siginputheader.parse(p.get_headers()['signature-input'].encode('utf-8'))
        siginputs = {}
        for (k,v) in siginputheader.items():
            siginput = {
                'coveredContent': [c.value for c in v], # todo: handle parameters
                'params': {p:pv for (p,pv) in v.params.items()},
                'value': str(v)
            }
            siginputs[k] = siginput
            
        response['signatureInput'] = siginputs

    if p.get_status_code():
        # response
        response['response'] = {
            'statusCode': p.get_status_code()
        }
    else:
        # request
        requestTarget = p.get_method().lower() + ' ' + p.get_path()
        if p.get_query_string():
            requestTarget += '?' + p.get_query_string()
        
        response['request'] = {
            'requestTarget': requestTarget,
            'method': p.get_method().upper(),
            'path': p.get_path(),
            'query': p.get_query_string()
        }
        
    return {
        'statusCode': 200,
        'headers': {
            "Access-Control-Allow-Origin": "*"
        },
        'body': json.dumps(response)
    }
    
def input(event, context):
    if not event['body']:
        return {
            'statusCode': 400,
            'headers': {
                "Access-Control-Allow-Origin": "*"
            }
        }
    
    data = json.loads(event['body'])
    
    msg = data['msg'].encode('utf-8')
    p = HttpParser()
    p.execute(msg, len(msg))
    
    sigparams = http_sfv.InnerList()
    base = '';
    for c in data['coveredContent']:
        if c == '@request-target':
            i = http_sfv.Item(c)
            sigparams.append(i)
            base += str(i)
            base += ': '
            requestTarget = p.get_method().lower() + ' ' + p.get_path()
            if p.get_query_string():
                requestTarget += '?' + p.get_query_string()
            base += requestTarget
            base += "\n"
        elif c == '@status-code':
            i = http_sfv.Item(c)
            sigparams.append(i)
            base += str(i)
            base += ': '
            base += str(p.get_status_code())
            base += "\n"
        elif not c.startswith('@'):
            i = http_sfv.Item(c.lower())
            sigparams.append(i)
            base += str(i)
            base += ': '
            base += p.get_headers()[c].strip() # TODO: normalize headers better
            base += "\n"
        else:
            print('Bad content identifier: ' + c)
            return {
                'statusCode': 400,
                'headers': {
                    "Access-Control-Allow-Origin": "*"
                },
            }

    if 'created' in data:
        sigparams.params['created'] = data['created']
    
    if 'expires' in data:
        sigparams.params['expires'] = data['expires']
    
    if 'keyid' in data:
        sigparams.params['keyid'] = data['keyid']
    
    if 'alg' in data:
        sigparams.params['alg'] = data['alg']

    sigparamstr = ''
    sigparamstr += str(http_sfv.Item("@signature-params"))
    sigparamstr += ": "
    sigparamstr += str(sigparams)
    
    base += sigparamstr
    
    response = {
        'signatureInput': base,
        'signatureParams': str(sigparams)
    }
    
    return {
        'statusCode': 200,
        'headers': {
            "Access-Control-Allow-Origin": "*"
        },
        'body': json.dumps(response)
    }
    
def sign(event, context):
    if not event['body']:
        return {
            'statusCode': 400,
            'headers': {
                "Access-Control-Allow-Origin": "*"
            }
        }
    
    data = json.loads(event['body'])

    msg = data['httpMsg']
    siginput = data['signatureInput']
    sigparams = data['signatureParams']
    signingKeyType = data['signingKeyType']
    alg = data['alg']
    label = data['label']
    
    if signingKeyType == 'x509':
        key = parseKeyX509(data['signingKeyX509'])
    elif signingKeyType == 'shared':
        if alg != 'hmac-sha256':
            # shared key type only good for hmac
            return {
                'statusCode': 400,
                'headers': {
                    "Access-Control-Allow-Origin": "*"
                }
            }
        
        sharedKey = data['signingKeyShared'].encode('utf-8')
    else:
        # unknown key type
        return {
            'statusCode': 400,
            'headers': {
                "Access-Control-Allow-Origin": "*"
            }
        }
    
    if alg == 'jose' and signingKeyType != 'jwk':
        # JOSE-driven algorithm choice only available for JWK formatted keys
        return {
            'statusCode': 400,
            'headers': {
                "Access-Control-Allow-Origin": "*"
            }
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
    else:
        # unknown algorithm
        return {
            'statusCode': 400,
            'headers': {
                "Access-Control-Allow-Origin": "*"
            }
        }

    if not signed:
        return {
            'statusCode': 500,
            'headers': {
                "Access-Control-Allow-Origin": "*"
            }
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
            #print(err)
            key = None
            #print(10)

    #print(11)
    return key
    