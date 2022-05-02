import React, {memo} from 'react';
import Moment from 'react-moment';
import Layout from '../components/layout';

import { decodeItem, decodeList, decodeDict, encodeItem, encodeList, encodeDict} from 'structured-field-values';

import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faClock, faPlusSquare, faTrash, faPenFancy, faCheckSquare } from '@fortawesome/fontawesome-free-solid';



import { Button, ButtonGroup, Tabs, Container, Section, Level, Form, Columns, Content, Heading, Box, Icon, Tag } from 'react-bulma-components';

//const api = 'https://grb8qjtvye.execute-api.us-east-1.amazonaws.com/dev' // bspk test
//const api = 'https://o52ky0nc31.execute-api.ca-central-1.amazonaws.com/dev' // secureKey install
const api = 'https://rntmg89xu9.execute-api.us-east-1.amazonaws.com/dev' // avast install
//const api = 'http://localhost:3000/dev'

class HttpSigForm extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      mode: 'sign', // can be 'sign' or 'verify'
      httpMsg: '',
      availableComponents: [],
      coveredComponents: [],
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
      signatureParams: undefined,
      verifySignature: undefined,
      signatureVerified: undefined,
      stage: 'input' // can be: input, params, material, output
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
Content-Digest: sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
Example-Dict: a=(1 2), b=3, c=4;aa=bb, d=(5 6);valid
Content-Length: 18

{"hello": "world"}`
    });
  }

  loadExampleResponse = (e) => {
    this.setState({
      httpMsg: `HTTP/1.1 200 OK
Date: Tue, 20 Apr 2021 02:07:56 GMT
Content-Type: application/json
Content-Digest: sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
Content-Length: 18

{"hello": "world"}`
    });
  }

  loadExampleSignedRequest = (e) => {
    this.setState({
      httpMsg: `POST /foo?param=value&pet=dog HTTP/1.1
Host: example.com
Date: Tue, 20 Apr 2021 02:07:55 GMT
Content-Type: application/json
Content-Digest: sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
Content-Length: 18
Signature-Input: sig=("@method" "@authority" "@path" "@query" "content-type" "content-digest" "content-length");created=1622749937;keyid="RSA (X.509 preloaded)";alg="rsa-pss-sha512"
Signature: sig=:BUt1JQp5SEvVDJmUqINLredbW0ktaGp423eRutpTfHiXgU8bhePTSebGqMoYm/Def8rJpdtbYRzNHUX8OzsAL0w6MKqk0Hvc6GuCzw+WLAIl/ZnOtR+AjOejYgbG+mZx5mb+N+M0DOh6tQpRxuAa/FA4uRAXr+r2dE7w8JeiY+fW38DiiurSVLW3zNgoTeCFnR/HI+8LWFUnm5nezkNAdpLduFW1Kdb1J7HOo2RvT/YsHGaNIHszyTfcVCnumtFCBHajvD9ktDvHwLM3vRJ/PwyUjeItD7trfYxGDPqNMUy7lcZT4HlJFOeEQlze2wL3+4fKVEYXV0IkvezVuFEtjA==:

{"hello": "world"}`
    });
  }

  loadExampleSignedResponse = (e) => {
    this.setState({
      httpMsg: `HTTP/1.1 200 OK
Date: Tue, 20 Apr 2021 02:07:56 GMT
Content-Type: application/json
Content-Digest: sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:
Content-Length: 18
Signature-Input: sig=("content-digest" "content-type" "content-length" "@status");created=1622749937;keyid="RSA (X.509 preloaded)";alg="rsa-pss-sha512"
Signature: sig=:cjya2ClOLXO3VMT9EhIggRvh1kKsYuMxonvQOSslX4+l1I9+l+1MJzLehpM/ysdxTEC+5X/8Gtcw8wMu1sRbpQcJjwHZ3vkt5OFJG9jgppGwrYEDb2+uCAooprRc59Ch7NcwBq7P8tBgvVVuk4phE7hAXQeCbGqOtynv5SoAusOiBKylhatJKUmaz0vAEUaUs2DIhlzeoOBlZkA45zxyuu1bQKD623E6/Ec3EBRwkWd8vlV8iQLiYv++ROlAzhAo3gTSNyxPD0hcvuoE+MVN6eAvpILp+TTcMzrNu1iPiQAPqE9o60Cqj6orKoa+sj+ZDWY1hauDJ5bD0d6ic1eCXA==:

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
      var possible = data['fields'].concat(data['derived']);

      var availableComponents = {};

      possible.forEach(c => {
        if (!(c['id'] in availableComponents)) {
          availableComponents[c['id']] = [];
        }
        availableComponents[c['id']].push(c);
      });

      console.log(availableComponents);

      this.setState({
        availableComponents: availableComponents,
        coveredComponents: [],
        inputSignatures: data['inputSignatures'],
        existingSignature: undefined,
        stage: 'params'
      }, () => {
        if (this.state.mode === 'verify' && this.state.inputSignatures) {
          this.setExistingSignature(Object.keys(this.state.inputSignatures)[0]);
        }
        document.getElementById('stages').scrollIntoView({behavior: 'smooth'});
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

  generateSignatureInput = (e) => {
    e.preventDefault();

    var body = {
      msg: this.state.httpMsg,
      coveredComponents: this.state.coveredComponents,
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
        signatureParams: data['signatureParams'],
        stage: 'material'
      }, () => {
        document.getElementById('stages').scrollIntoView({behavior: 'smooth'});
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
      var coveredComponents = sig['coveredComponents'];
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
        signatureHeaders: data['headers'],
        stage: 'output'
      }, () => {
        document.getElementById('stages').scrollIntoView({behavior: 'smooth'});
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
      signatureParams: this.state.signatureParams,
      signature: this.state.inputSignatures[this.state.verifySignature]['signature']
    };

    fetch(api + '/verify', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(body)
    }).then(response => {
      return response.json()
    }).then(data => {
      this.setState({
        signatureVerified: data['signatureVerified'],
        stage: 'output'
      }, () => {
        document.getElementById('stages').scrollIntoView({behavior: 'smooth'});
      });
    });
  }
  
  setStage = (stage) => (e) => {
    e.preventDefault();
    this.setState({
      stage: stage
    });
  }
  
  setMode = (mode) => (e) => {
    e.preventDefault();
    this.setState({
      mode: mode,
      stage: 'input'
    });
  }

  render = () => {
    return (
      <>
      <Heading id="stages">
      <Columns>
      <Columns.Column size="half">
      <Button
        color={this.state.mode === 'sign' ? 'info' : 'grey'}
        fullwidth
        onClick={this.setMode('sign')}>
        Sign</Button>
      </Columns.Column>
      <Columns.Column size="half">
      <Button
        color={this.state.mode === 'verify' ? 'info' : 'grey'}
        fullwidth
        onClick={this.setMode('verify')}>
        Verify</Button>
      </Columns.Column>
      </Columns>
      <Button 
        color={this.state.stage === 'input' ? 'primary' : 'info'}
        inverted={this.state.stage !== 'input'}
        onClick={this.setStage('input')}>Input</Button>
      &raquo;
      <Button 
        color={this.state.stage === 'params' ? 'primary' : 
          this.state.stage === 'input' ? 'danger' : 'info'}
        inverted={this.state.stage !== 'params'}
        onClick={this.setStage('params')}>Parameters</Button>
      &raquo;
      <Button 
        color={this.state.stage === 'material' ? 'primary'  : 
          (this.state.stage === 'input' || this.state.stage ==='params') ? 'danger' : 'info'}
        inverted={this.state.stage !== 'material'}
        onClick={this.setStage('material')}>Material</Button>
      &raquo;
      <Button 
        color={this.state.stage === 'output' ? 'primary' : 
          (this.state.stage === 'input' || this.state.stage ==='params' || this.state.stage ==='material') ? 'danger' : 'info'}
        inverted={this.state.stage !== 'output'}
        onClick={this.setStage('output')}>Output</Button>
      </Heading>
      {this.state.stage === 'input' && (
        <Box id="input">
          <Heading>Input</Heading>
          <Section>
        		<Form.Label>HTTP Message</Form.Label>
            {this.state.mode === 'sign' && <Button onClick={this.loadExampleRequest}>Example Request</Button>}
            {this.state.mode === 'sign' && <Button onClick={this.loadExampleResponse}>Example Response</Button>}
            <Button onClick={this.loadExampleSignedRequest}>Example Signed Request</Button>
            <Button onClick={this.loadExampleSignedResponse}>Example Signed Response</Button>
        		<Form.Field>
        			<Form.Control>
    		        <Form.Textarea rows={10} spellCheck={false} onChange={this.setHttpMsg} value={this.state.httpMsg} />
        			</Form.Control>
        		</Form.Field>
          </Section>
          <Section>
            <Button onClick={this.parseHttpMsg}>Parse</Button>
          </Section>
        </Box>
      )}
      {this.state.stage === 'params' && (
        <Box id="params">
          <Heading>Signature Parameters</Heading>
          <Section>
            {this.state.mode === 'verify' && this.state.inputSignatures && (
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
                  <option value="">Not Speficied</option>
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
          </Section>
          <Section>
            <Button onClick={this.generateSignatureInput}>Generate Signature Base</Button>
          </Section>
        </Box>
      )}
      {this.state.stage === 'material' && (
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
                {this.state.mode === 'sign' && <Button onClick={this.loadRsaPssPrivate}>RSA Private</Button>}
                {this.state.mode === 'verify' && <Button onClick={this.loadRsaPssPublic}>RSA Public</Button>}
                {this.state.mode === 'sign' && <Button onClick={this.loadEccPrivate}>ECC Private</Button>}
                {this.state.mode === 'verify' && <Button onClick={this.loadEccPublic}>ECC Public</Button>}
                {this.state.mode === 'sign' && <Button onClick={this.loadEdPrivate}>Ed25519 Private</Button>}
                {this.state.mode === 'verify' && <Button onClick={this.loadEdPublic}>Ed25519 Public</Button>}
            		<Form.Field>
            			<Form.Control>
        		        <Form.Textarea rows={10} spellCheck={false} onChange={this.setSigningKeyX509} value={this.state.signingKeyX509} />
            			</Form.Control>
            		</Form.Field>
              </>
            )}
            {this.state.signingKeyType == 'jwk' && (
              <>
                {this.state.mode === 'sign' && <Button onClick={this.loadRsaPrivateJwk}>RSA Private</Button>}
                {this.state.mode === 'verify' && <Button onClick={this.loadRsaPublicJwk}>RSA Public</Button>}
                {this.state.mode === 'sign' && <Button onClick={this.loadEccPrivateJwk}>ECC Private</Button>}
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
          {this.state.mode === 'sign' && (
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
          {this.state.mode === 'sign' && (
          <Section>
            <Button onClick={this.signInput}>Sign Signature Base</Button>
          </Section>
          )}
          {this.state.mode === 'verify' && this.state.inputSignatures && (
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
      {this.state.stage === 'output' && (
        <Box id="output">
          <Heading>Output</Heading>
          {this.state.mode === 'verify' && (
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
          {this.state.mode === 'sign' && (
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
              <code>{
                c['id'] +
                (c['sf'] ? " (structured)" :
                  (c['key'] ? ", key=" + c['key'] :
                    (c['name'] ? ", name=" + c['name'] : ''))) }</code>
            </label>
    			</Form.Control>
              ))}
        </Form.Field>
  ))}
      </>
);

const IndexPage = () => <Layout>
  <HttpSigForm />
</Layout>;

export default IndexPage;

