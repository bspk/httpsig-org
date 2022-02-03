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

structuredFields = {
    'accept': 'list',
    'accept-encoding': 'list',
    'accept-language': 'list',
    'accept-patch': 'list',
    'accept-ranges': 'list',
    'access-control-allow-credentials': 'item',
    'access-control-allow-headers': 'list',
    'access-control-allow-methods': 'list',
    'access-control-allow-origin': 'item',
    'access-control-expose-headers': 'list',
    'access-control-max-age': 'item',
    'access-control-request-headers': 'list',
    'access-control-request-method': 'item',
    'age': 'item',
    'allow': 'list',
    'alpn': 'list',
    'alt-svc': 'dict',
    'alt-used': 'item',
    'cache-control': 'dict',
    'connection': 'list',
    'content-encoding': 'list',
    'content-language': 'list',
    'content-length': 'list',
    'content-type': 'item',
    'cross-origin-resource-policy': 'item',
    'expect': 'item',
    'expect-ct': 'dict',
    'host': 'item',
    'keep-alive': 'dict',
    'origin': 'item',
    'pragma': 'dict',
    'prefer': 'dict',
    'preference-applied': 'dict',
    'retry-after': 'item',
    'surrogate-control': 'dict',
    'te': 'list',
    'timing-allow-origin': 'list',
    'trailer': 'list',
    'transfer-encoding': 'list',
    'vary': 'list',
    'x-content-type-options': 'item',
    'x-frame-options': 'item',
    'x-xss-protection': 'list',
    "cache-status": "list",
    "proxy-status": "list",
    "variant-key": "list",
    "variants": "dict",
    "signature": "dict",
    "signature-input": "dict",
    "priority": "dict",
    "x-dictionary": "dict",
    "x-list": "list",
    "x-list-a": "list",
    "x-list-b": "list",
    "accept-ch": "list",
    "example-list": "list",
    "example-dict": "dict",
    "example-integer": "item",
    "example-decimal": "item",
    "example-string": "item",
    "example-token": "item",
    "example-bytesequence": "item",
    "example-boolean": "item",
    "cdn-cache-control": "dict"
}


def parse_components(msg):
    p = HttpParser()
    p.execute(msg, len(msg))
    
    response = {}
    
    response['fields'] = []
    for h in p.get_headers():
        cid = http_sfv.Item(h.lower())
        response['fields'].append(
            {
                'id': cid.value,
                'cid': str(cid),
                'val': p.get_headers()[h] # Note: this normalizes the header value for us
            }
        )
        # see if this is a known structured field
        if h and h.lower() in structuredFields:
            if structuredFields[h.lower()] == 'dict':
                sv = http_sfv.Dictionary()
                sv.parse(p.get_headers()[h].encode('utf-8'))
            
                for k in sv:
                    cid = http_sfv.Item(h.lower())
                    cid.params['key'] = k
                    response['fields'].append(
                        {
                            'id': cid.value,
                            'cid': str(cid),
                            'key': k,
                            'val': str(sv[k])
                        }
                    )
            
                cid = http_sfv.Item(h.lower())
                cid.params['sf'] = True
                response['fields'].append(
                    {
                        'id': cid.value,
                        'cid': str(cid),
                        'sf': True,
                        'val': str(sv)
                    }
                )
            elif structuredFields[h.lower()] == 'list':
                sv = http_sfv.List()
                sv.parse(p.get_headers()[h].encode('utf-8'))
            
                cid = http_sfv.Item(h.lower())
                cid.params['sf'] = True
                response['fields'].append(
                    {
                        'id': cid.value,
                        'cid': str(cid),
                        'sf': True,
                        'val': str(sv)
                    }
                )
            elif structuredFields[h.lower()] == 'item':
                sv = http_sfv.Item()
                sv.parse(p.get_headers()[h].encode('utf-8'))
        
                cid = http_sfv.Item(h.lower())
                cid.params['sf'] = True
                response['fields'].append(
                    {
                        'id': cid.value,
                        'cid': str(cid),
                        'sf': True,
                        'val': str(sv)
                    }
                )

    if p.get_status_code():
        # response
        response['derived'] = [
            {
                'id': '@status',
                'cid': str(http_sfv.Item('@status')),
                'val': str(p.get_status_code())
            }
        ]
    else:
        # request
        response['derived'] = [
            {
                'id': '@method',
                'cid': str(http_sfv.Item('@method')),
                'val': p.get_method()
            },
            {
                'id': '@target-uri',
                'cid': str(http_sfv.Item('@target-uri')),
                'val': 
                'https://' # TODO: this always assumes an HTTP connection for demo purposes
                    + p.get_headers()['host'] # TODO: this library assumes HTTP 1.1
                    + p.get_url()
            },
            {
                'id': '@authority',
                'cid': str(http_sfv.Item('@authority')),
                'val':  p.get_headers()['host'] # TODO: this library assumes HTTP 1.1
            },
            {
                'id': '@scheme',
                'cid': str(http_sfv.Item('@scheme')),
                'val':  'https' # TODO: this always assumes an HTTPS connection for demo purposes
            },
            {
                'id': '@request-target',
                'cid': str(http_sfv.Item('@request-target')),
                'val':  p.get_url()
            },
            {
                'id': '@path',
                'cid': str(http_sfv.Item('@path')),
                'val':  p.get_path()
            },
            {
                'id': '@query',
                'cid': str(http_sfv.Item('@query')),
                'val':  '?' + p.get_query_string()
            }
        ]

        qs = parse_qs(p.get_query_string())
        for q in qs:
            v = qs[q]
            if len(v) == 1:
                cid = http_sfv.Item('@query-param')
                cid.params['name'] = q
                response['derived'].append(
                    {
                        'id': cid.value,
                        'cid': str(cid),
                        'name': q,
                        'val': v[0]
                    }
                )
            elif len(v) > 1:
                # Multiple values, undefined behavior?
                for i in range(len(v)):
                    cid = http_sfv.Item('@query-param')
                    cid.params['name'] = q
                    response['derived'].append(
                        {
                            'id': cid.value,
                            'cid': str(cid),
                            'name': q,
                            'val': v[i],
                            'idx': i
                        }
                    )

    if 'signature-input' in p.get_headers():
        # existing signatures, parse the values
        siginputheader = http_sfv.Dictionary()
        siginputheader.parse(p.get_headers()['signature-input'].encode('utf-8'))
        
        sigheader = http_sfv.Dictionary()
        sigheader.parse(p.get_headers()['signature'].encode('utf-8'))
        
        siginputs = {}
        for (k,v) in siginputheader.items():
            
            existingComponents = []
            for c in v:
                cc = { # holder object
                    'id': c.value,
                    'cid': str(c)
                }
                if not cc['id'].startswith('@'):
                    # it's a header, try to get the existing value
                    fields = (f for f in response['fields'] if f['id'] == cc['id'])
                    if 'sf' in c.params:
                        cc['sf'] = c.params['sf']
                        cc['val'] = next((f['val'] for f in fields if f['sf'] == c.params['sf']), None)
                    elif 'key' in c.params:
                        cc['key'] = i.params['key']
                        cc['val'] = next((f['val'] for f in fields if f['key'] == c.params['key']), None)
                    else:
                        cc['val'] = next((f['val'] for f in fields if ('key' not in f and 'sf' not in f)), None)
                else:
                    # it's derived
                    derived = (d for d in response['derived'] if d['id'] == cc['id'])
                    
                    if cc['id'] == '@query-param' and 'name' in c.params:
                        cc['name'] = c.params['name']
                        cc['val'] = next((d['val'] for d in derived if d['name'] == c.params['name']), None)
                    else:
                        cc['val'] = next((d['val'] for d in derived if ('name' not in d)), None)

                existingComponents.append(cc)
            
            siginput = {
                'coveredComponents': existingComponents,
                'params': {p:pv for (p,pv) in v.params.items()},
                'value': str(v),
                'signature': str(sigheader[k])
            }
            siginputs[k] = siginput
            
        response['inputSignatures'] = siginputs

    return response
    
def generate_input(event, context):
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
    # re-parse the input message
    components = parse_components(msg)
    #print(components)
    sigparams = http_sfv.InnerList()
    base = '';
    
    for cc in data['coveredComponents']:
        c = cc['id']
        if not c.startswith('@'):
            # it's a header
            i = http_sfv.Item(c.lower())

            if 'key' in cc:
                # try a dictionary header value
                i.params['key'] = cc['key']
                comp = next((x for x in components['fields'] if 'key' in x and x['id'] == c and x['key'] == cc['key']), None)
                                
                sigparams.append(i)
                base += str(i)
                base += ': '
                base += comp['val']
                base += "\n"
            elif 'sf' in cc:
                i.params['sf'] = True
                comp = next((x for x in components['fields'] if x['id'] == c), None)
                sigparams.append(i)
                base += str(i)
                base += ': '
                base += comp['val']
                base += "\n"
            else:
                comp = next((x for x in components['fields'] if x['id'] == c), None)
                sigparams.append(i)
                base += str(i)
                base += ': '
                base += comp['val']
                base += "\n"
        else:
            # it's a derived value
            i = http_sfv.Item(c)
            if 'key' in cc and c == '@request-response':
                # request-response has a 'key' field
                i.params['key'] = cc['key']
                comp = next((x for x in components['derived'] if 'key' in x and x['id'] == c and x['key'] == cc['key']), None)
                                
                sigparams.append(i)
                base += str(i)
                base += ': '
                base += comp['val']
                base += "\n"
            elif 'name' in cc and c == '@query-param':
                # query-param has a 'name' field
                i.params['name'] = cc['name']
                comp = next((x for x in components['derived'] if 'name' in x and x['id'] == c and x['name'] == cc['name']), None)
                                
                sigparams.append(i)
                base += str(i)
                base += ': '
                base += comp['val']
                base += "\n"
            else:
                comp = next((x for x in components['derived'] if x['id'] == c), None)

                sigparams.append(i)
                base += str(i)
                base += ': '
                base += comp['val']
                base += "\n"

    if 'created' in data:
        sigparams.params['created'] = data['created']
    
    if 'expires' in data:
        sigparams.params['expires'] = data['expires']
    
    if 'keyid' in data:
        sigparams.params['keyid'] = data['keyid']
    
    if 'nonce' in data:
        sigparams.params['nonce'] = data['nonce']
    
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
    