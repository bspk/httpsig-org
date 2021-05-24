import json
try:
    from http_parser.parser import HttpParser
except ImportError:
    from http_parser.pyparser import HttpParser

import http_sfv
import M2Crypto
import hashlib


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

    if p.get_status_code():
        # response
        response['response'] = {
            'status-code': p.get_status_code()
        }
    else:
        # this is request-only for now
        requestTarget = p.get_method().lower() + ' ' + p.get_path()
        if p.get_query_string():
            requestTarget += '?' + p.get_query_string()
        
        response['request'] = {
            'request-target': requestTarget,
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
        'signature-input': base,
        'signature-params': str(sigparams)
    }
    
    return {
        'statusCode': 200,
        'headers': {
            "Access-Control-Allow-Origin": "*"
        },
        'body': json.dumps(response)
    }
    