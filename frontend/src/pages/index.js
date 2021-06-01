import React, {memo} from 'react';
import Moment from 'react-moment';
import Layout from '../components/layout';

import { decodeItem, decodeList, decodeDict, encodeItem, encodeList, encodeDict} from 'structured-field-values';

import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faClock, faPlusSquare, faTrash } from '@fortawesome/fontawesome-free-solid';



import { Button, ButtonGroup, Tabs, Container, Section, Level, Form, Columns, Content, Heading, Box, Icon } from 'react-bulma-components';

const api = 'https://y2dgwjj82j.execute-api.us-east-1.amazonaws.com/dev'

class HttpSigForm extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      httpMsg: '',
      availableContent: [],
      coveredContent: [],
      signatureInput: '',
      algParam: '',
      alg: '',
      keyid: undefined,
      created: undefined,
      expires: undefined,
      signatureInput: undefined,
      signatureParams: undefined,
      inputSignatures: undefined,
      existingSignature: undefined,
      signingKeyType: 'x509',
      signingKeyX509: '',
      signingKeyJwk: '',
      signingKeyShared: '',
      signatureOutput: '',
      signatureHeaders: '',
      label: 'sig',
      signatureParams: undefined
    };
  }
  
  setHttpMsg = (e) => {
    this.setState({
      httpMsg: e.target.value
    });
  }
  
  loadExampleRequest = (e) => {
    this.setState({
      httpMsg: `POST /foo?param=value&pet=dog HTTP/1.1
Host: example.com
Date: Tue, 20 Apr 2021 02:07:55 GMT
Content-Type: application/json
Digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
Content-Length: 18

{"hello": "world"}`
    });
  }

  loadExampleResponse = (e) => {
    this.setState({
      httpMsg: `HTTP/1.1 200 OK
Date: Tue, 20 Apr 2021 02:07:56 GMT
Content-Type: application/json
Digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=
Content-Length: 18

{"hello": "world"}`
    });
  }

  
  parseHttpMsg = (e) => {
    e.preventDefault();
    fetch(api + '/parse', {
      method: 'POST',
      body: this.state.httpMsg
    }).then(response => {
      return response.json()
    }).then(data => {
      var availableContent = data['headers'];
      if (data['request']) {
        availableContent.unshift('@request-target');
      }
      if (data['response']) {
        availableContent.unshift('@status-code');
      }
      this.setState({
        availableContent: availableContent,
        coveredContent: [],
        inputSignatures: data['signatureInput']
      }, () => {
        document.getElementById('params').scrollIntoView({behavior: 'smooth'});
      });
    });
  }
  
  setCoveredContent = (value) => (e) => {
    //e.preventDefault();
    var covered = new Set(this.state.coveredContent);
    if (covered.has(value)) {
      covered.delete(value);
    } else {
      covered.add(value);
    }
    this.setState({
      coveredContent: [...covered]
    });
  }
  
  setAlgParam = (e) => {
    this.setState({
      algParam: e.target.value
    });
  }
  
  setAlg = (e) => {
    this.setState({
      alg: e.target.value
    });
  }
  
  setKeyid = (e) => {
    this.setState({
      keyid: e.target.value
    });
  }
  
  setCreated = (e) => {
    if (!e.target.value) {
      this.setState({
        created: undefined
      });
    } else {
      var i = parseInt(e.target.value);
      if (Number.isInteger(i)) {
        this.setState({
          created: i
        });
      }
    }
  }
  
  setCreatedToNow = (e) => {
    var now = Math.floor(Date.now() / 1000);
    this.setState({
      created: now
    });
  }
  
  clearCreated = (e) => {
    this.setState({
      created: undefined
    });
  }
  
  setExpires = (e) => {
    if (!e.target.value) {
      this.setState({
        expires: undefined
      });
    } else {
      var i = parseInt(e.target.value);
      if (Number.isInteger(i)) {
        this.setState({
          expires: i
        });
      }
    }
  }
  
  addTimeToExpires = (e) => {
    if (!this.state.expires) {
      // expiration isn't set
      if (this.state.created) {
        // creation is set, expires 5 min from creation
        var expires = this.state.created + 5 * 60;
        this.setState({
          expires: expires
        });
      } else {
        // creation isn't set, expires 5 min from now
        var expires = Math.floor(Date.now() / 1000) + 5 * 60;
        this.setState({
          expires: expires
        });
      }
    } else {
      // expiration is set, add 5 min
      var expires = this.state.expires + 5 * 60;
      this.setState({
        expires: expires
      });
    }
  }
  
  clearExpires = (e) => {
    this.setState({
      expires: undefined
    });
  }
  
  generateSignatureInput = (e) => {
    e.preventDefault();
    
    var body = {
      msg: this.state.httpMsg,
      coveredContent: this.state.coveredContent,
      alg: this.state.algParam ? this.state.algParam : undefined,
      keyid: this.state.keyid,
      created: this.state.created,
      expires: this.state.expires
    };
    
    fetch(api + '/input', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(body)
    }).then(response => {
      return response.json()
    }).then(data => {
      this.setState({
        signatureInput: data['signatureInput'],
        signatureParams: data['signatureParams']
      }, () => {
        document.getElementById('material').scrollIntoView({behavior: 'smooth'});
      });
    });
  }
  
  setSignatureInput = (e) => {
    this.setState({
      signatureInput: e.target.value
    });
  }

  selectExistingSignature = (e) => {
    var sel = e.target.value;
    if (sel && sel != this.state.existingSignature) {
      var sig = this.state.inputSignatures[sel];
      var coveredContent = sig['coveredContent'];
      var alg = sig['params']['alg'];
      var created = sig['params']['created'];
      var expires = sig['params']['expires'];
      var keyid = sig['params']['keyid'];
    
      this.setState({
        coveredContent: coveredContent,
        algParam: alg,
        created: created,
        expires: expires,
        keyid: keyid,
        existingSignature: sel
      });
    } else {
      this.setState({
        coveredContent: [],
        algParam: undefined,
        created: undefined,
        expires: undefined,
        keyid: undefined,
        existingSignature: undefined
      });
    }
  }
  
  loadRsaPssPrivate = (e) => {
    this.setState({
      signingKeyX509: `-----BEGIN PRIVATE KEY-----
MIIEvgIBADALBgkqhkiG9w0BAQoEggSqMIIEpgIBAAKCAQEAr4tmm3r20Wd/Pbqv
P1s2+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry5
3mm+oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7Oyr
FAHqgDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUA
AN5WUtzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw
9lq4aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oy
c6XI2wIDAQABAoIBAQCUB8ip+kJiiZVKF8AqfB/aUP0jTAqOQewK1kKJ/iQCXBCq
pbo360gvdt05H5VZ/RDVkEgO2k73VSsbulqezKs8RFs2tEmU+JgTI9MeQJPWcP6X
aKy6LIYs0E2cWgp8GADgoBs8llBq0UhX0KffglIeek3n7Z6Gt4YFge2TAcW2WbN4
XfK7lupFyo6HHyWRiYHMMARQXLJeOSdTn5aMBP0PO4bQyk5ORxTUSeOciPJUFktQ
HkvGbym7KryEfwH8Tks0L7WhzyP60PL3xS9FNOJi9m+zztwYIXGDQuKM2GDsITeD
2mI2oHoPMyAD0wdI7BwSVW18p1h+jgfc4dlexKYRAoGBAOVfuiEiOchGghV5vn5N
RDNscAFnpHj1QgMr6/UG05RTgmcLfVsI1I4bSkbrIuVKviGGf7atlkROALOG/xRx
DLadgBEeNyHL5lz6ihQaFJLVQ0u3U4SB67J0YtVO3R6lXcIjBDHuY8SjYJ7Ci6Z6
vuDcoaEujnlrtUhaMxvSfcUJAoGBAMPsCHXte1uWNAqYad2WdLjPDlKtQJK1diCm
rqmB2g8QE99hDOHItjDBEdpyFBKOIP+NpVtM2KLhRajjcL9Ph8jrID6XUqikQuVi
4J9FV2m42jXMuioTT13idAILanYg8D3idvy/3isDVkON0X3UAVKrgMEne0hJpkPL
FYqgetvDAoGBAKLQ6JZMbSe0pPIJkSamQhsehgL5Rs51iX4m1z7+sYFAJfhvN3Q/
OGIHDRp6HjMUcxHpHw7U+S1TETxePwKLnLKj6hw8jnX2/nZRgWHzgVcY+sPsReRx
NJVf+Cfh6yOtznfX00p+JWOXdSY8glSSHJwRAMog+hFGW1AYdt7w80XBAoGBAImR
NUugqapgaEA8TrFxkJmngXYaAqpA0iYRA7kv3S4QavPBUGtFJHBNULzitydkNtVZ
3w6hgce0h9YThTo/nKc+OZDZbgfN9s7cQ75x0PQCAO4fx2P91Q+mDzDUVTeG30mE
t2m3S0dGe47JiJxifV9P3wNBNrZGSIF3mrORBVNDAoGBAI0QKn2Iv7Sgo4T/XjND
dl2kZTXqGAk8dOhpUiw/HdM3OGWbhHj2NdCzBliOmPyQtAr770GITWvbAI+IRYyF
S7Fnk6ZVVVHsxjtaHy1uJGFlaZzKR4AGNaUTOJMs6NadzCmGPAxNQQOCqoUjn4XR
rOjr9w349JooGXhOxbu8nOxX
-----END PRIVATE KEY-----
`,
      alg: 'rsa-pss-sha512',
      signingKeyType: 'x509'
    });
  }

  loadRsaPssPublic = (e) => {
    this.setState({
      signingKeyX509: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr4tmm3r20Wd/PbqvP1s2
+QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry53mm+
oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7OyrFAHq
gDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUAAN5W
Utzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw9lq4
aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oyc6XI
2wIDAQAB
-----END PUBLIC KEY-----
`,
      alg: 'rsa-pss-sha512',
      signingKeyType: 'x509'
    });
  }
  
  loadEccPrivate = (e) => {
    this.setState({
      signingKey: `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFKbhfNZfpDsW43+0+JjUr9K+bTeuxopu653+hBaXGA7oAoGCCqGSM49
AwEHoUQDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lfw0EkjqF7xB4FivAxzic30tMM
4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==
-----END EC PRIVATE KEY-----
      `,
      alg: 'ecdsa-p256-sha256',
      signingKeyType: 'x509'
    });
  }

  setSigningKeyType = (e) => {
    this.setState({
      signingKeyType: e.target.value
    });
  }
  
  setSigningKeyX509 = (e) => {
    this.setState({
      signingKeyX509: e.target.value
    });
  }
  
  setSigningKeyJwk = (e) => {
    this.setState({
      signingKeyJwk: e.target.value
    });
  }
  
  setSigningKeyShared = (e) => {
    this.setState({
      signingKeyShared: e.target.value
    });
  }
  
  setLabel = (e) => {
    this.setState({
      label: e.target.value
    });
  }
  
  signInput = (e) => {
    e.preventDefault();
    
    var body = {
      signatureInput: this.state.signatureInput,
      signingKeyType: this.state.signingKeyType,
      signingKeyX509: this.state.signingKeyX509,
      signingKeyJwk: this.state.signingKeyJwk,
      signingKeyShared: this.state.signingKeyShared,
      alg: this.state.alg,
      label: this.state.label,
      httpMsg: this.state.httpMsg,
      signatureParams: this.state.signatureParams
    };
    
    fetch(api + '/sign', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(body)
    }).then(response => {
      return response.json()
    }).then(data => {
      this.setState({
        signatureOutput: data['signatureOutput'],
        signatureHeaders: data['headers']
      }, () => {
        document.getElementById('output').scrollIntoView({behavior: 'smooth'});
      });
    });
  }
  
  setSignatureOutput = (e) => {
    this.setState({
      signatureOutput: e.target.value
    });
  }
  
  setSignatureHeaders = (e) => {
    this.setState({
      signatureHeaders: e.target.value
    });
  }

  render = () => {
    return (
      <>
      <Box id="input">
        <Heading>Input</Heading>
        <Section>
      		<Form.Label>HTTP Message</Form.Label>
          <Button onClick={this.loadExampleRequest}>Example Request</Button>
          <Button onClick={this.loadExampleResponse}>Example Response</Button>
      		<Form.Field>
      			<Form.Control>
  		        <Form.Textarea rows={10} spellCheck={false} onChange={this.setHttpMsg} value={this.state.httpMsg} />
      			</Form.Control>
      		</Form.Field>
            <Button onClick={this.parseHttpMsg}>Parse</Button>
        </Section>
      </Box>
      <Box id="params">
        <Heading>Signature Parameters</Heading>
        <Section>
          <Form.Field>
            <Form.Label>Use parameters from existing signature</Form.Label>
            <Form.Control>
              <Form.Select value={this.state.existingSignature} onChange={this.selectExistingSignature}>
                <option value="">None</option>
                {this.state.inputSignatures && (
                  Object.entries(this.state.inputSignatures).map(([k, v], i) => (
                    <option value={k}>{k}</option>
                  ))
                )}
              </Form.Select>
            </Form.Control>
          </Form.Field>
          <CoveredContent coveredContent={this.state.coveredContent} availableContent={this.state.availableContent} setCoveredContent={this.setCoveredContent} />
          <Form.Field>
            <Form.Label>Explicit Signature Algorithm</Form.Label>
            <Form.Control>
      				<Form.Select onChange={this.setAlgParam} value={this.state.algParam}>
                <option value="">Not Speficied</option>
                <option value="rsa-pss-sha512">RSA PSS</option>
                <option value="ecdsa-p256-sha256">EC</option>
                <option value="hmac-sha256">HMAC</option>
                <option value="rsa-v1_5-sha256">RSA 1.5</option>
      				</Form.Select>
            </Form.Control>
          </Form.Field>
          <Form.Field>
            <Form.Label>Key ID</Form.Label>
            <Form.Control>
      				<Form.Input onChange={this.setKeyid} value={this.state.keyid ? this.state.keyid : ''} />
            </Form.Control>
          </Form.Field>
          <Form.Label>Creation Time</Form.Label>
          <Form.Field kind="addons">
            <Form.Control>
      				<Form.Input onChange={this.setCreated} value={this.state.created ? String(this.state.created) : ''} />
              {this.state.created && (
                <Form.Help>
                  <Moment>{this.state.created * 1000}</Moment>
                </Form.Help>
              )}
            </Form.Control>
            <Form.Control>
              <Button onClick={this.setCreatedToNow}>
                <Icon>
                  <FontAwesomeIcon icon={faClock} />
                </Icon>
              </Button>
            </Form.Control>
            <Form.Control>
              <Button onClick={this.clearCreated}>
                <Icon>
                  <FontAwesomeIcon icon={faTrash} />
                </Icon>
              </Button>
            </Form.Control>
          </Form.Field>
          <Form.Label>Expiration Time</Form.Label>
          <Form.Field kind="addons">
            <Form.Control>
      				<Form.Input onChange={this.setExpires} value={this.state.expires ? String(this.state.expires) : ''} />
              {this.state.expires && (
                <Form.Help>
                  <Moment>{this.state.expires * 1000}</Moment>
                </Form.Help>
              )}
            </Form.Control>
            <Form.Control>
              <Button onClick={this.addTimeToExpires}>
                <Icon>
                  <FontAwesomeIcon icon={faPlusSquare} />
                </Icon>
              </Button>
            </Form.Control>
            <Form.Control>
              <Button onClick={this.clearExpires}>
                <Icon>
                  <FontAwesomeIcon icon={faTrash} />
                </Icon>
              </Button>
            </Form.Control>
          </Form.Field>
          <Button onClick={this.generateSignatureInput}>Generate Signature Input</Button>
        </Section>
      </Box>
      <Box id="material">
        <Heading>Signature Material</Heading>
        <Section>
      		<Form.Label>Signature Input String</Form.Label>
      		<Form.Field>
      			<Form.Control>
  		        <Form.Textarea rows={10} spellCheck={false} onChange={this.setSignatureInput} value={this.state.signatureInput ? this.state.signatureInput : ''} />
      			</Form.Control>
      		</Form.Field>
        </Section>
        <Section>
      		<Form.Field>
      			<Form.Label>Key Format</Form.Label>
      			<Form.Control>
              <Form.Select onChange={this.setSigningKeyType} value={this.state.signingKeyType ? this.state.signingKeyType : ''}>
                <option value="x509">X.509</option>
                <option value="jwk">JWK</option>
                <option value="shared">Shared</option>
      				</Form.Select>
      			</Form.Control>
      		</Form.Field>
      		<Form.Label>Key material</Form.Label>
          {this.state.signingKeyType == 'x509' && (
            <>
              <Button onClick={this.loadRsaPssPrivate}>RSA Private</Button>
              <Button onClick={this.loadRsaPssPublic}>RSA Public</Button>
              <Button onClick={this.loadEccPrivate}>ECC Private</Button>
          		<Form.Field>
          			<Form.Control>
      		        <Form.Textarea rows={10} spellCheck={false} onChange={this.setSigningKeyX509} value={this.state.signingKeyX509} />
          			</Form.Control>
          		</Form.Field>
            </>
          )}
          {this.state.signingKeyType == 'jwk' && (
            <>
              <Button onClick={this.loadRsaPssPrivateJwk}>RSA Private</Button>
              <Button onClick={this.loadRsaPssPublicJwk}>RSA Public</Button>
              <Button onClick={this.loadEccPrivateJwk}>ECC Private</Button>
          		<Form.Field>
          			<Form.Control>
      		        <Form.Textarea rows={10} spellCheck={false} onChange={this.setSigningKeyJwk} value={this.state.signingKeyJwk} />
          			</Form.Control>
          		</Form.Field>
            </>
          )}
          {this.state.signingKeyType == 'shared' && (
            <>
          		<Form.Field>
          			<Form.Control>
      		        <Form.Textarea rows={10} spellCheck={false} onChange={this.setSigningKeyShared} value={this.state.signingKeyShared} />
          			</Form.Control>
          		</Form.Field>
            </>
          )}
        </Section>
        <Section>
          <Form.Field>
            <Form.Label>Label</Form.Label>
            <Form.Control>
      				<Form.Input onChange={this.setLabel} value={this.state.label} />
            </Form.Control>
          </Form.Field>
        </Section>
        <Section>
      		<Form.Field>
      			<Form.Label>Signature Algorithm</Form.Label>
      			<Form.Control>
              <Form.Select onChange={this.setAlg} disabled={this.state.algParam !== ''} value={this.state.algParam ? this.state.algParam : this.state.alg}>
                <option value="rsa-pss-sha512">RSA PSS</option>
                <option value="ecdsa-p256-sha256">EC</option>
                <option value="hmac-sha256">HMAC</option>
                <option value="rsa-v1_5-sha256">RSA 1.5</option>
                <option value="jose" disabled>Use JWA value from Key</option>
      				</Form.Select>
      			</Form.Control>
      		</Form.Field>
          <Button onClick={this.signInput}>Sign Signature Input</Button>
        </Section>
      </Box>
      <Box id="output">
        <Heading>Output</Heading>
        <Section>
      		<Form.Label>Signature Value (in Base64)</Form.Label>
      		<Form.Field>
      			<Form.Control>
  		        <Form.Textarea rows={10} spellCheck={false} onChange={this.setSignatureOutput} value={this.state.signatureOutput} />
      			</Form.Control>
      		</Form.Field>
        </Section>
        <Section>
      		<Form.Label>HTTP Message Signature Headers</Form.Label>
      		<Form.Field>
      			<Form.Control>
  		        <Form.Textarea rows={10} spellCheck={false} onChange={this.setSignatureHeaders} value={this.state.signatureHeaders} />
      			</Form.Control>
      		</Form.Field>
        </Section>
      </Box>
      </>
    );
  }
  
}

const CoveredContent = ({...props}) =>
(
      <>
        <Form.Label>Covered content</Form.Label>
    		<Form.Field kind='group'>
  {props.availableContent.map((value, index) => (
    			<Form.Control key={index}>
            <label>
              <input type="checkbox" checked={props.coveredContent.includes(value)} onChange={props.setCoveredContent(value)} />
              <code>{value}{props.coveredContent.includes(value)}</code>
            </label>
    			</Form.Control>
  ))}
    		</Form.Field>
      </>
);


const IndexPage = () => <Layout>
  <HttpSigForm />
</Layout>;

export default IndexPage;

