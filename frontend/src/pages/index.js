import React, {memo} from 'react';
import Moment from 'react-moment';
import Layout from '../components/layout';
import libraryList from '../components/libraries';

import { decodeItem, decodeList, decodeDict, encodeItem, encodeList, encodeDict} from 'structured-field-values';

import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faClock, faPlusSquare, faTrash, faPenFancy, faCheckSquare, faFileSignature, faFileContract, faBook, faCircleXmark, faCircleCheck, faScrewdriverWrench, faCodeBranch, faKeyboard } from '@fortawesome/free-solid-svg-icons';
import { faJava, faJs, faNodeJs, faGolang, faPhp, faPython, faRust, faSquareGithub } from '@fortawesome/free-brands-svg-icons';



import { Button, ButtonGroup, Tabs, Container, Section, Level, Form, Columns, Content, Heading, Box, Icon, Tag, TagGroup, Hero, Tile, Card } from 'react-bulma-components';

//const api = 'https://grb8qjtvye.execute-api.us-east-1.amazonaws.com/dev' // bspk test
//const api = 'https://o52ky0nc31.execute-api.ca-central-1.amazonaws.com/dev' // secureKey install
//const api = 'https://rntmg89xu9.execute-api.us-east-1.amazonaws.com/dev' // avast install
//const api = 'http://localhost:3000/dev'
const api = ''; // use api on same host

class Selector extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      mode: 'sign', // can be 'sign' or 'verify'
      stage: 'input' // can be: input, params, material, output
    }
  }
  
  setMode = (mode) => (e) => {
    e.preventDefault();
    this.setState({
      mode: mode,
      stage: 'input'
    });
  }

  setStage = (stage) => {
    this.setState({
      stage: stage
    });
  }
  
  
  
  render = () => {
    return (
      <>
      <Tabs
        fullwidth
        type='boxed'
        size='large'
      >
        <Tabs.Tab
          active={this.state.mode === 'sign'}
          onClick={this.setMode('sign')}>
          <Icon>
            <FontAwesomeIcon icon={faFileSignature} />
          </Icon>
          Sign</Tabs.Tab>
        <Tabs.Tab
          active={this.state.mode === 'verify'}
          onClick={this.setMode('verify')}>
          <Icon>
            <FontAwesomeIcon icon={faFileContract} />
          </Icon>
          Verify</Tabs.Tab>
        <Tabs.Tab
          active={this.state.mode === 'libraries'}
          onClick={this.setMode('libraries')}>
          <Icon>
            <FontAwesomeIcon icon={faBook} />
          </Icon>
          Libraries</Tabs.Tab>
      </Tabs>
      {this.state.mode === 'sign' && <HttpSigForm mode={this.state.mode} stage={this.state.stage} setStage={this.setStage} />}
      {this.state.mode === 'verify' && <HttpSigForm mode={this.state.mode} stage={this.state.stage} setStage={this.setStage} />}
      {this.state.mode === 'libraries' && <Libraries />}
      </>
    );
  }
}

const LanguageIcon = ({...props}) => {
  if (props.language === 'Java') {
    return (
      <Icon>
        <FontAwesomeIcon icon={faJava} />
      </Icon>
    );
  } else if (props.language === 'Go') {
    return (
      <Icon>
        <FontAwesomeIcon icon={faGolang} />
      </Icon>
    );
  } else if (props.language === 'JavaScript') {
    return (
      <Icon>
        <FontAwesomeIcon icon={faJs} />
      </Icon>
    );
  } else if (props.language === 'NodeJS') {
    return (
      <Icon>
        <FontAwesomeIcon icon={faNodeJs} />
      </Icon>
    );
  } else if (props.language === 'PHP') {
    return (
      <Icon>
        <FontAwesomeIcon icon={faPhp} />
      </Icon>
    );
  } else if (props.language === 'Python') {
    return (
      <Icon>
        <FontAwesomeIcon icon={faPython} />
      </Icon>
    );
  } else if (props.language === 'Rust') {
    return (
      <Icon>
        <FontAwesomeIcon icon={faRust} />
      </Icon>
    );
  } else {
    return (
      <Icon>
        <FontAwesomeIcon icon={faKeyboard} />
      </Icon>
    );
  }
};

const YesNo = ({...props}) => {
  if (props.val) {
    return (
      <li className="has-text-success">
        <Icon>
          <FontAwesomeIcon icon={faCircleCheck} />
        </Icon>
      {props.label}
      </li>
    );
  } else {
    return (
      <li className="has-text-info">
        <Icon>
          <FontAwesomeIcon icon={faCircleXmark} />
        </Icon>
      {props.label}
      </li>
    );
  }
};

const MaintainerLink = ({...props}) => {
  if (props.maintainerLink) {
    return (
      <a href={props.maintainerLink}>{props.maintainer}</a>
    );
  } else {
    return props.maintainer;
  }
}

const VisitRepo = ({...props}) => {
  if (props.repo.startsWith('https://github.com/')) {
    var disp = props.repo.replace('https://github.com/', '');
    return (
      <li>
        <Icon>
          <FontAwesomeIcon icon={faCodeBranch} />
        </Icon>
        <a href={props.repo}><Icon><FontAwesomeIcon icon={faSquareGithub}/></Icon>{disp}</a>
      </li>
    );
  } else {
    return (
      <li>
        <Icon>
          <FontAwesomeIcon icon={faCodeBranch} />
        </Icon>
        <a href={props.repo}>{props.repo}</a>
      </li>
    );
  }
}

const Libraries = ({...props}) => {
  const cards = libraryList.map(l => {
    return (
    <Tile kind="parent" size={4}>
    <Tile renderAs={Card} kind="child">
    <Card.Content>
      <ul>
      <li className="has-background-primary-light">
        <b><LanguageIcon language={l.language} /> {l.language}</b>
      </li>
      <YesNo val={l.sign} label="Sign" />
      <YesNo val={l.verify} label="Verify" />
      <YesNo val={l.request} label="Request" />
      <YesNo val={l.response} label="Response" />
      <li>
        <Icon>
          <FontAwesomeIcon icon={faScrewdriverWrench} />
        </Icon>
        <b>Maintainer:</b> <MaintainerLink maintainer={l.maintainer} maintainerLink={l.maintainerLink} />
      </li>
      <VisitRepo repo={l.repo} />
      </ul>
    </Card.Content>
    </Tile>
    </Tile>
    );
  });
  
  return (
    <Tile kind="ancestor" className="libraries">
    {cards}
    </Tile>
  );
  
};


class HttpSigForm extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      httpMsg: '',
      showRelatedMsg: false,
      relatedMsg: '',
      parsedComponents: [],
      parsedRelatedComponents: [],
      availableComponents: [],
      coveredComponents: [],
      algParam: '',
      alg: '',
      keyid: undefined,
      created: undefined,
      expires: undefined,
      nonce: undefined,
      tag: undefined,
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
      signatureParams: undefined,
      verifySignature: undefined,
      signatureVerified: undefined,
      error: undefined
    };
  }

  setHttpMsg = (e) => {
    this.setState({
      httpMsg: e.target.value
    });
  }

  setShowRelatedMsg = (e) => {
    var value = !this.state.showRelatedMsg;
    this.setState({
      showRelatedMsg: value
    });
  }

  setRelatedMsg = (e) => {
    this.setState({
      relatedMsg: e.target.value
    });
  }
  
  clearError = (e) => {
    this.setState({
      error: undefined
    });
  }

  loadExampleRequest = (e) => {
    this.setState({
      httpMsg: `POST /foo?param=value&pet=dog HTTP/1.1
Host: example.com
Date: Tue, 20 Apr 2021 02:07:55 GMT
Content-Type: application/json
Content-Digest: sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
Example-Dict: a=(1 2), b=3, c=4;aa=bb, d=(5 6);valid
Content-Length: 18

{"hello": "world"}`,
      relatedMsg: ''
    });
  }

  loadExampleResponse = (e) => {
    this.setState({
      httpMsg: `HTTP/1.1 200 OK
Date: Tue, 20 Apr 2021 02:07:56 GMT
Content-Type: application/json
Content-Digest: sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
Content-Length: 18

{"hello": "world"}`,
      relatedMsg: `POST /foo?param=value&pet=dog HTTP/1.1
Host: example.com
Date: Tue, 20 Apr 2021 02:07:55 GMT
Content-Type: application/json
Content-Digest: sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
Example-Dict: a=(1 2), b=3, c=4;aa=bb, d=(5 6);valid
Content-Length: 18

{"hello": "world"}`
    });
  }

  loadExampleSignedRequest = (e) => {
    this.setState({
      httpMsg: `NOTE: '\\' line wrapping per RFC 8792

POST /foo?param=value&pet=dog HTTP/1.1
Host: example.com
Date: Tue, 20 Apr 2021 02:07:55 GMT
Content-Type: application/json
Content-Digest: sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+T\\
  aPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:
Content-Length: 18
Signature-Input: sig=("@method" "@authority" "@path" "@query" \\
  "content-digest" "content-length" "content-type")\\
  ;alg="rsa-pss-sha512";created=1618884473\\
  ;keyid="RSA (X.509 preloaded)"
Signature: sig=:k2kD1VAw9TOA72zoDzt3ZAOdjhOg9edgBYqsvyQb5mBnwzY/fKz\\
  5W30tZud9YA4o8NfCYh8VnW5m4fxFsWCTOOQbrsWXmmGSKtblfi3o5DxlHJcUkrAH\\
  /d13tmy7r2Jtipjrhv6Ca67VU9z1Q2S8Zd87sNxFnyhIxX+CiKJ+i+P6XfJfeTbCV\\
  UIo8cTTqLD9go9xdZ8sSUkU9kDy5WxghbbPV/y9rmmigO0y3qxI8/UGZ/OWhsN13O\\
  zvE0SBj8tCYQ8qlh20zjNmJm0GN62RJXK0dX1h83Gh0IIXGPPmWQNCavO4hAbY3eW\\
  7nhGdEjlh364x8dd323UKuMfuwqYEyg==:

{"hello": "world"}`,
      relatedMsg: ''
    });
  }

  loadExampleSignedResponse = (e) => {
    this.setState({
      httpMsg: `NOTE: '\\' line wrapping per RFC 8792
      
HTTP/1.1 200 OK
Date: Tue, 20 Apr 2021 02:07:56 GMT
Content-Type: application/json
Content-Digest: sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+T\\
  aPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:
Content-Length: 18
Signature-Input: sig=("@status" "content-digest" "content-length" \\
  "content-type");alg="rsa-pss-sha512";created=1618884473\\
  ;keyid="RSA (X.509 preloaded)"
Signature: sig=:SfHwLLMHetROs/nmZoKFbxwJhlgVt5pwWc0Ag7yuDfTxB1RaX8x\\
  4Fscdb5ZZJ5j9K/r7Q58jOxKpmBGv3bHeeFa2LRbjntzvlnbntAi4t6ZzYAoBMQdt\\
  oOvORqRdGE5iR3crLacJn+CPu7iupDiu4e4dBRbN2fYHZWm/1r15kgU2gTQym2Qcp\\
  0FZspzNmxmo3iOLQJaeKx5QmRYE6oFM5OYw1kOdaTlLl26M9wNonBCrMrDrG0/qfm\\
  hxfG/C8zeexbL+FVjUqx/4NqdIu0spcBSat2Fo08N6tT/SWhmLN4B2Lu3eyVLUp/G\\
  zekHFdvZiLULkfLh7e9b5dKqevsgtJw==:

{"hello": "world"}`,
      relatedMsg: ''
    });
  }

  parseHttpMsg = (e) => {
    e.preventDefault();
    
    var body = {
      msg: this.state.httpMsg
    };
    
    if (this.state.showRelatedMsg) {
      body['req'] = this.state.relatedMsg;
    }
    
    fetch(api + '/parse', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(body)
    }).then(response => {
      if (response.ok) {
        return response.json();
      } else {
        throw new Error(response.json()['error']);
      }
    }).then(data => {
      var components = data['components'];
      var reqComponents = data['reqComponents']

      var possible = components['fields'].concat(components['derived']);

      var availableComponents = {};

      possible.forEach(c => {

        if (!(c['id'] in availableComponents)) {
          availableComponents[c['id']] = [];
        }
        availableComponents[c['id']].push(c);
      });
      
      if (reqComponents) {
        possible = reqComponents['fields'].concat(reqComponents['derived']);
        
        possible.forEach(c => {
          if (!(c['id'] in availableComponents)) {
            availableComponents[c['id']] = [];
          }
          availableComponents[c['id']].push(c);
        });
      }

      this.setState({
        availableComponents: availableComponents,
        coveredComponents: [],
        inputSignatures: components['inputSignatures'],
        parsedComponents: components,
        parsedRelatedComponents: reqComponents,
        existingSignature: undefined,
      }, () => {
        if (this.props.mode === 'verify' && this.state.inputSignatures) {
          this.setExistingSignature(Object.keys(this.state.inputSignatures)[0]);
        }
        this.props.setStage('params');
        document.getElementById('stages').scrollIntoView({behavior: 'smooth'});
      });
    })
    .catch(e => {
      this.setState({
        error: e.message
      });
    });
  }

  setCoveredComponents = (value) => (e) => {
    //e.preventDefault();
    var covered = this.state.coveredComponents;
    if (covered.some((c) => c['cid'] === value['cid'])) {
      // remove the value
      covered = covered.filter((c) => c['cid'] !== value['cid']);
    } else {
      // add the value
      covered.push(value);
    }
    this.setState({
      coveredComponents: [...covered]
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
  
  setNonce = (e) => {
    this.setState({
      nonce: e.target.value
    });
  }
  
  setTag = (e) => {
    this.setState({
      tag: e.target.value
    });
  }

  generateSignatureInput = (e) => {
    e.preventDefault();

    if (this.props.mode === 'verify' && this.state.existingSignature) {
      var sig = this.state.inputSignatures[this.state.existingSignature];
      var params = sig['params'];
    } else {
      var params = {
        alg: this.state.algParam ? this.state.algParam : undefined,
        keyid: this.state.keyid,
        created: this.state.created,
        expires: this.state.expires,
        nonce: this.state.nonce,
        tag: this.state.tag
      };
    }
    
    var body = {
      components: this.state.parsedComponents,
      reqComponents: this.state.parsedRelatedComponents,
      coveredComponents: this.state.coveredComponents,
      params: params
    };

    fetch(api + '/base', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(body)
    }).then(response => {
      if (response.ok) {
        return response.json()
      } else {
        throw new Error(response.json()['error']);
      }
    }).then(data => {
      this.setState({
        signatureInput: data['signatureInput'],
        signatureParams: data['signatureParams'],
      }, () => {
        this.props.setStage('material');
        document.getElementById('stages').scrollIntoView({behavior: 'smooth'});
      });
    })
    .catch(e => {
      this.setState({
        error: e.message
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
    this.setExistingSignature(sel);
  }
  
  setExistingSignature = (sel) => {
    if (sel && sel != this.state.existingSignature) {
      var sig = this.state.inputSignatures[sel];
      var sigCovered = sig['coveredComponents'];
      // collect covered components
      var coveredComponents = [];
      var avail = this.state.availableComponents;
      sigCovered.forEach(c => {
        console.log(avail);
        console.log(c);
        var comp = avail[c['id']].find(x => x['cid'] === c['cid']);
        coveredComponents.push(comp);
      });
      var alg = sig['params']['alg'];
      var created = sig['params']['created'];
      var expires = sig['params']['expires'];
      var keyid = sig['params']['keyid'];

      this.setState({
        coveredComponents: coveredComponents,
        algParam: alg,
        created: created,
        expires: expires,
        keyid: keyid,
        existingSignature: sel,
        verifySignature: sel
      });
    } else {
      this.setState({
        coveredComponents: [],
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
      signingKeyType: 'x509'
    });
  }

  loadEccPrivate = (e) => {
    this.setState({
      signingKeyX509: `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIFKbhfNZfpDsW43+0+JjUr9K+bTeuxopu653+hBaXGA7oAoGCCqGSM49
AwEHoUQDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lfw0EkjqF7xB4FivAxzic30tMM
4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==
-----END EC PRIVATE KEY-----
      `,
      alg: 'ecdsa-p256-sha256',
      signingKeyType: 'x509'
    });
  }

  loadEccPublic = (e) => {
    this.setState({
      signingKeyX509: `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lf
w0EkjqF7xB4FivAxzic30tMM4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==
-----END PUBLIC KEY-----
      `,
      alg: 'ecdsa-p256-sha256',
      signingKeyType: 'x509'
    });
  }

  loadSharedJwk = (e) => {
    this.setState({
      signingKeyJwk: `{
    "kty": "oct",
    "k": "vmVXzCQe2ASdfg8tTz23rDnVVHfLQGIH0PukOiiepQS15COB8y6Bc6urybq_VryC-6ThcSBBjIL0kvTJwwe5-0cEt0bu-Zk7tZAfpCEgIzRZtig98PYMZNd_6aITWbjq7vLFgeIhr0t_wQGSFvPSGZPVuMuf8IGLx5RuI4Tw5zJE2LN7Byi0FWNsVZrbqnHZBF7Gg3G_gOnt_RaDtbz4DmjRYn2OIAW322JGgQwLww_czDHCe51kZ84qQI_WCRfyCHr9JEr7riLP1StSYfV-oaU_Qlbm-96q1yYKfwDh-pTAFZhZgc9Gz_gXOxkCMCLcuFGMGPeZninUVV1V8-MwQw"
}
      `,
      alg: 'hmac-sha256',
      signingKeyType: 'jwk'
    });
  }

  loadRsaPublicJwk = (e) => {
    this.setState({
      signingKeyJwk: `{
    "kty": "RSA",
    "e": "AQAB",
    "n": "n3l04HtB4zJLSXajGfRZSGafRRNGgiEpIoZC7NW22RQ-9kALeS_BjkDFAHWvAsMaewVaFySosQis4GqH8p-wFmOg33trWqS50CIwvwShXFhTIkkd1WUMaVsq_dbe6SmJfbtwM0k5hNOl9xl6HCYCMC2BVnvThuDHIQnfnPL_Cw-EDmOrAqBNqbrt-T5l5NHONoBBtfh-2T1q7fWo2rCizq6RfoRsxxESzbzVZVFHABvARkkfbbLHpgo3CEcHhwZ_sgXUY3ydowfrYnpEBKy8mBxkwZG1ZmUOhakpIrUJJdsF_Isw3c1hBo8IttUqiUzYqYp-Lz-OSP4AcHVUYSfiFw"
}
      `,
      alg: 'rsa-pss-sha512',
      signingKeyType: 'jwk'
    });
  }

  loadRsaPrivateJwk = (e) => {
    this.setState({
      signingKeyJwk: `{
    "p": "z0iuJwBV3q5nWo5FslhTL9-AusvTJLd1HemcPXhkyc0pNnpW7m6lNuDkDyXbn85IF-9oYASdK1mbX8hc0sDoUd16PICMTSxJ9E-en8T-yuCPYJFacPLAqNqmOsUiJn0fIH5kwHKDh5P3dirO6m9FZ8K-XMaufKhZYoWgBzNELKk",
    "kty": "RSA",
    "q": "xPRM5wRgSZk_vCjJlulGV5RawMCJWmV0WpJpsUHIrUAgdc0Ef_RYZluuqvXxd-y1oLBJqHWm_cMWLOw0AqLhCpRg55RWMhV7xZ_vLfD__pM4X5YXCo1097JkWrWWaO-UfR8guVg7sKx3emJedm0z9TWvEhwtKrLS_cn9knqAEL8",
    "d": "ZmF5MWywHgX5443wpAcFEsAfXB9F0uErIWkEqjuCCdc_nKP9Oa35GzRlxSfIVYOgCn6jGdyFGDKzmdeKs67lQ1puu0rm3uiGCiMJHHkChuCFbqt2Jbubvj-zWAeMUDBEfp3JKIPIE4g1Mm_-vvd_zCJKuJUCdcL01DccggxWxGgMIGqC71hU66RFO843GmpUsz1Jowjto6BZM-Bto9XST3RQ25rLxr_faHSZ1BayqjLfQooZR-sqiI6NuvRrN8hWSymcyrmS62mtiVRZl6WBRT-59ODfivHELirQLLagBshP70EiCW-7qYaNPKDljriu3kQDwE0awm8j2DHnQKel4Q",
    "e": "AQAB",
    "qi": "oKDQI_HD_WJ5aUjaJNnjBvNkVtl_6mAGRDdYveRTDG7e2ujq8VE2iG_rpWqCOMRZUSK0fAfGGoWgQIOg_cmgWJZFotWTe3zdtRP-1b-YyZt6X-gwrqGjfOM10Y2Z2xjq61pp2_Sm9P6k-GBJX8M3YW6OsZI6B43PCMbZ4n5NQJ0",
    "dp": "qXMp4vo0OGjsVqvtsADiaEVWz91mCyLqW_yoW9v60Lml0kIqpJnQ987awMNbCgWxC9gLxEqhTVngWWnK8AMBKENc9O7FQyVMg6s-6i85dxIiQ3gvrhvUgXTU5UBYTYyFkKOiq2wxt_ivGGugYSd7Xnpl8iP9aiyZfZ_tFVXEipk",
    "dq": "T4DqdirPD4acMsEoNxHtgjbxt3NBPstLf7AwmAwdDMqhD8x1r40cDh2eUYa8NZPI8ZeX9Deh9DfHANVMXXAQdavVvkWj0c3YS7s22o25WLNnAzbcEDdv6vkJB5DbqXpkr2lcVVUnqzbDeBSzWwzT93z3MdFL7juHbkkWYgWvIpM",
    "n": "n3l04HtB4zJLSXajGfRZSGafRRNGgiEpIoZC7NW22RQ-9kALeS_BjkDFAHWvAsMaewVaFySosQis4GqH8p-wFmOg33trWqS50CIwvwShXFhTIkkd1WUMaVsq_dbe6SmJfbtwM0k5hNOl9xl6HCYCMC2BVnvThuDHIQnfnPL_Cw-EDmOrAqBNqbrt-T5l5NHONoBBtfh-2T1q7fWo2rCizq6RfoRsxxESzbzVZVFHABvARkkfbbLHpgo3CEcHhwZ_sgXUY3ydowfrYnpEBKy8mBxkwZG1ZmUOhakpIrUJJdsF_Isw3c1hBo8IttUqiUzYqYp-Lz-OSP4AcHVUYSfiFw",
    "alg": "RS256"
}
      `,
      alg: 'rsa-pss-sha512',
      signingKeyType: 'jwk'
    });
  }

  loadEccPrivateJwk = (e) => {
    this.setState({
      signingKeyJwk: `{
    "kty": "EC",
    "d": "wcHNx8kkBCcBnGY39K995TShcdOFdKtaRQLGrUELqBI",
    "crv": "P-256",
    "x": "m5dnqNXawIKF3qyCfs_raR1LtTKUtyf4t2uVa4Wmd6A",
    "y": "prF8Lo5JC2JTyj2GwtaI2LWWEaRa6v6XykjUMg-9C1U",
    "alg": "ES256"
}
      `,
      alg: 'ecdsa-p256-sha256',
      signingKeyType: 'jwk'
    });
  }

  loadEccPublicJwk = (e) => {
    this.setState({
      signingKeyJwk: `{
    "kty": "EC",
    "crv": "P-256",
    "x": "m5dnqNXawIKF3qyCfs_raR1LtTKUtyf4t2uVa4Wmd6A",
    "y": "prF8Lo5JC2JTyj2GwtaI2LWWEaRa6v6XykjUMg-9C1U"
}
      `,
      alg: 'ecdsa-p256-sha256',
      signingKeyType: 'jwk'
    });
  }
  
  loadEdPrivate = (e) => {
    this.setState({
      signingKeyX509: `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF
-----END PRIVATE KEY-----
      `,
      alg: 'ed25519',
      signingKeyType: 'x509'
    });
  }

  loadEdPublic = (e) => {
    this.setState({
      signingKeyX509: `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=
-----END PUBLIC KEY-----
      `,
      alg: 'ed25519',
      signingKeyType: 'x509'
    });
  }

  setSigningKeyType = (e) => {
    if (e.target.value === 'shared') {
      this.setState({
        signingKeyType: e.target.value,
        alg: 'hmac-sha256'
      });
    } else {
      this.setState({
        signingKeyType: e.target.value
      });
    }
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
      relatedMsg: this.state.relatedMsg,
      signatureParams: this.state.signatureParams
    };

    fetch(api + '/sign', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(body)
    }).then(response => {
      if (response.ok) {
        return response.json();
      } else {
        throw new Error(response.json()['error']);
      }
    }).then(data => {
      this.setState({
        signatureOutput: data['signatureOutput'],
        signatureHeaders: data['headers'],
      }, () => {
        this.props.setStage('output');
        document.getElementById('stages').scrollIntoView({behavior: 'smooth'});
      });
    })
    .catch(e => {
      this.setState({
        error: e.message
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

  selectVerifySignature = (e) => {
    this.setState({
      verifySignature: e.target.value
    });
  }

  verifySignature = (e) => {
    e.preventDefault();

    var body = {
      signatureInput: this.state.signatureInput,
      signingKeyType: this.state.signingKeyType,
      signingKeyX509: this.state.signingKeyX509,
      signingKeyJwk: this.state.signingKeyJwk,
      signingKeyShared: this.state.signingKeyShared,
      alg: this.state.algParam ? this.state.algParam : this.state.alg,
      label: this.state.label,
      httpMsg: this.state.httpMsg,
      relatedMsg: this.state.relatedMsg,
      signatureParams: this.state.signatureParams,
      signature: this.state.inputSignatures[this.state.verifySignature]['signature']
    };

    fetch(api + '/verify', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(body)
    }).then(response => {
      if (response.ok) {
        return response.json();
      } else {
        throw new Error(response.json()['error']);
      }
    }).then(data => {
      this.setState({
        signatureVerified: data['signatureVerified'],
      }, () => {
        this.props.setStage('output');
        document.getElementById('stages').scrollIntoView({behavior: 'smooth'});
      });
    })
    .catch(e => {
      this.setState({
        error: e.message
      });
    });
  }
  
  render = () => {
    return (
      <>
      <Heading id="stages">
      <Button 
        color={this.props.stage === 'input' ? 'primary' : 'info'}
        inverted={this.props.stage !== 'input'}
        onClick={(e) => {
          e.preventDefault();
          this.props.setStage('input')
        }}>Input</Button>
      &raquo;
      <Button 
        color={this.props.stage === 'params' ? 'primary' : 
          this.props.stage === 'input' ? 'danger' : 'info'}
        inverted={this.props.stage !== 'params'}
        onClick={(e) => {
          e.preventDefault();
          this.props.setStage('params')
        }}>Parameters</Button>
      &raquo;
      <Button 
        color={this.props.stage === 'material' ? 'primary'  : 
          (this.props.stage === 'input' || this.props.stage ==='params') ? 'danger' : 'info'}
        inverted={this.props.stage !== 'material'}
        onClick={(e) => {
          e.preventDefault();
          this.props.setStage('material')
        }}>Material</Button>
      &raquo;
      <Button 
        color={this.props.stage === 'output' ? 'primary' : 
          (this.props.stage === 'input' || this.props.stage ==='params' || this.props.stage ==='material') ? 'danger' : 'info'}
        inverted={this.props.stage !== 'output'}
        onClick={(e) => {
          e.preventDefault();
          this.props.setStage('output')
        }}>Output</Button>
      </Heading>
      
      {this.state.error && (
        <Box id="input" color="danger">
        <Hero color="danger">
          <Hero.Header>Error</Hero.Header>
          <Hero.Body>{this.state.error}</Hero.Body>
          <Hero.Footer><Button onClick={this.clearError}>Close</Button></Hero.Footer>
        </Hero>
        </Box>
      )}
      {this.props.stage === 'input' && (
        <Box id="input">
          <Heading>Input</Heading>
          <Section>
        		<Form.Label>HTTP Message</Form.Label>
            {this.props.mode === 'sign' && <Button onClick={this.loadExampleRequest}>Example Request</Button>}
            {this.props.mode === 'sign' && <Button onClick={this.loadExampleResponse}>Example Response</Button>}
            <Button onClick={this.loadExampleSignedRequest}>Example Signed Request</Button>
            <Button onClick={this.loadExampleSignedResponse}>Example Signed Response</Button>
        		<Form.Field>
        			<Form.Control>
    		        <Form.Textarea rows={10} spellCheck={false} onChange={this.setHttpMsg} value={this.state.httpMsg} />
        			</Form.Control>
        		</Form.Field>
        		<Form.Field>
              <label>
                <input type="checkbox" checked={this.state.showRelatedMsg} onChange={this.setShowRelatedMsg} /> Send Related-Request Message Context (for responses)
              </label>
            {this.state.showRelatedMsg && 
        			<Form.Control>
    		        <Form.Textarea rows={10} spellCheck={false} onChange={this.setRelatedMsg} value={this.state.relatedMsg} />
        			</Form.Control>
             }
        		</Form.Field>
          </Section>
          <Section>
            <Button onClick={this.parseHttpMsg}>Parse</Button>
          </Section>
        </Box>
      )}
      {this.props.stage === 'params' && (
        <Box id="params">
          <Heading>Signature Parameters</Heading>
          <Section>
            {this.props.mode === 'verify' && this.state.inputSignatures && (
              <Form.Field>
                <Form.Label>Use parameters from existing signature</Form.Label>
                <Form.Control>
                  <Form.Select value={this.state.existingSignature} onChange={this.selectExistingSignature}>
                    <option value="">None</option>
                      {Object.entries(this.state.inputSignatures).map(([k, v], i) => (
                        <option value={k}>{k}</option>
                      ))}
                  </Form.Select>
                </Form.Control>
              </Form.Field>
            )}
            <CoveredComponents coveredComponents={this.state.coveredComponents} availableComponents={this.state.availableComponents} setCoveredComponents={this.setCoveredComponents} />
            <Form.Field>
              <Form.Label>Explicit Signature Algorithm</Form.Label>
              <Form.Control>
        				<Form.Select onChange={this.setAlgParam} value={this.state.algParam}>
                  <option value="">Not Specified</option>
                  <option value="rsa-pss-sha512">RSA PSS</option>
                  <option value="ecdsa-p256-sha256">ECDSA</option>
                  <option value="hmac-sha256">HMAC</option>
                  <option value="rsa-v1_5-sha256">RSA 1.5</option>
                  <option value="ed25519">Ed25519</option>
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
            <Form.Field>
              <Form.Label>Nonce</Form.Label>
              <Form.Control>
        				<Form.Input onChange={this.setNonce} value={this.state.nonce ? this.state.nonce : ''} />
              </Form.Control>
            </Form.Field>
            <Form.Field>
              <Form.Label>Tag</Form.Label>
              <Form.Control>
        				<Form.Input onChange={this.setTag} value={this.state.tag ? this.state.tag : ''} />
              </Form.Control>
            </Form.Field>
          </Section>
          <Section>
            <Button onClick={this.generateSignatureInput}>Generate Signature Base</Button>
          </Section>
        </Box>
      )}
      {this.props.stage === 'material' && (
        <Box id="material">
          <Heading>Signature Material</Heading>
          <Section>
        		<Form.Label>Signature Base</Form.Label>
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
                  <option value="x509">PEM (Certificate)</option>
                  <option value="jwk">JWK</option>
                  <option value="shared">Shared</option>
        				</Form.Select>
        			</Form.Control>
        		</Form.Field>
        		<Form.Label>Key material</Form.Label>
            {this.state.signingKeyType == 'x509' && (
              <>
                {this.props.mode === 'sign' && <Button onClick={this.loadRsaPssPrivate}>RSA Private</Button>}
                {this.props.mode === 'verify' && <Button onClick={this.loadRsaPssPublic}>RSA Public</Button>}
                {this.props.mode === 'sign' && <Button onClick={this.loadEccPrivate}>ECC Private</Button>}
                {this.props.mode === 'verify' && <Button onClick={this.loadEccPublic}>ECC Public</Button>}
                {this.props.mode === 'sign' && <Button onClick={this.loadEdPrivate}>Ed25519 Private</Button>}
                {this.props.mode === 'verify' && <Button onClick={this.loadEdPublic}>Ed25519 Public</Button>}
            		<Form.Field>
            			<Form.Control>
        		        <Form.Textarea rows={10} spellCheck={false} onChange={this.setSigningKeyX509} value={this.state.signingKeyX509} />
            			</Form.Control>
            		</Form.Field>
              </>
            )}
            {this.state.signingKeyType == 'jwk' && (
              <>
                {this.props.mode === 'sign' && <Button onClick={this.loadRsaPrivateJwk}>RSA Private</Button>}
                {this.props.mode === 'verify' && <Button onClick={this.loadRsaPublicJwk}>RSA Public</Button>}
                {this.props.mode === 'sign' && <Button onClick={this.loadEccPrivateJwk}>ECC Private</Button>}
                <Button onClick={this.loadSharedJwk}>Shared</Button>
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
          {this.props.mode === 'sign' && (
          <Section>
            <Form.Field>
              <Form.Label>Label</Form.Label>
              <Form.Control>
        				<Form.Input onChange={this.setLabel} value={this.state.label} />
              </Form.Control>
            </Form.Field>
          </Section>
          )}
          <Section>
        		<Form.Field>
        			<Form.Label>Signature Algorithm</Form.Label>
        			<Form.Control>
                <Form.Select onChange={this.setAlg} disabled={this.state.algParam !== ''} value={this.state.algParam ? this.state.algParam : this.state.alg}>
                  <option value="rsa-pss-sha512" disabled={this.state.signingKeyType == 'shared'}>RSA PSS</option>
                  <option value="ecdsa-p256-sha256" disabled={this.state.signingKeyType == 'shared'}>ECDSA</option>
                  <option value="hmac-sha256">HMAC</option>
                  <option value="rsa-v1_5-sha256" disabled={this.state.signingKeyType == 'shared'}>RSA 1.5</option>
                  <option value="ed25519" disabled={this.state.signingKeyType == 'shared'}>Ed25519</option>
                  <option value="jose" disabled={this.state.signingKeyType !== 'jwk'}>Use JWA value from Key</option>
        				</Form.Select>
        			</Form.Control>
        		</Form.Field>
          </Section>
          {this.props.mode === 'sign' && (
          <Section>
            <Button onClick={this.signInput}>Sign Signature Base</Button>
          </Section>
          )}
          {this.props.mode === 'verify' && this.state.inputSignatures && (
          <Section>
              <Form.Field>
                <Form.Control>
                  <Form.Select value={this.state.verifySignature} onChange={this.selectVerifySignature}>
                    <option value="">--</option>
                    {Object.entries(this.state.inputSignatures).map(([k, v], i) => (
                      <option value={k}>{k}</option>
                    ))}
                  </Form.Select>
                  <Button onClick={this.verifySignature}>Verify Signature</Button>
                </Form.Control>
              </Form.Field>
          </Section>
          )}
        </Box>
      )}
      {this.props.stage === 'output' && (
        <Box id="output">
          <Heading>Output</Heading>
          {this.props.mode === 'verify' && (
          <Section>
            <Form.Label>Signature Status</Form.Label>
            <Form.Field>
              <Form.Control>
            {this.state.signatureVerified && (
              <Tag size="large" className="is-fullwidth" color="success">Signature Verified Successfully</Tag>
            )}
              </Form.Control>
            </Form.Field>
            {!this.state.signatureVerified && (
              <Tag size="large" className="is-fullwidth" color="danger">Signature Verification Failed</Tag>
            )}
          </Section>
          )}
          {this.props.mode === 'sign' && (
          <>
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
          </>
          )}
        </Box>
      )}
      
      </>
    );
  }

}

const CoveredComponents = ({...props}) =>
(
      <>
        <Form.Label>Covered Components</Form.Label>
  { Object.keys(props.availableComponents).map((key) => (
    		<Form.Field kind='group' multiline>
    { props.availableComponents[key].map((c, index) => (
    			<Form.Control key={index}>
            <label>
              <input type="checkbox" checked={props.coveredComponents.some((ec) => ec['cid'] === c['cid'])} onChange={props.setCoveredComponents(c)} />
              <code>{c['id']}</code>
      { c['sf'] && (<Tag color="success">structured</Tag>) }
      { c['req'] && (<Tag color="info">request</Tag>) }
      { c['key'] && (<Tag color="dark">key="{c['key']}"</Tag>) }
      { c['name'] && (<Tag color="danger">name="{c['name']}"</Tag>) }
            </label>
    			</Form.Control>
      ))}
        </Form.Field>
  ))}
      </>
);

const IndexPage = () => <Layout>
  <Selector />
</Layout>;

export default IndexPage;

