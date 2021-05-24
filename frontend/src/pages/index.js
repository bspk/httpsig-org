import React, {memo} from 'react';
import Moment from 'react-moment';
import Layout from '../components/layout';

import { Button, ButtonGroup, Tabs, Container, Section, Level, Form, Columns, Content, Heading, Box } from 'react-bulma-components';

const api = 'https://y2dgwjj82j.execute-api.us-east-1.amazonaws.com/dev'

class HttpSigForm extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      httpMsg: '',
      availableContent: [],
      coveredContent: [],
      requestTarget: '',
      signatureInput: '',
      algParam: '',
      alg: '',
      keyid: undefined,
      created: undefined,
      expires: undefined,
      signatureInput: undefined,
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
        requestTarget: data['request-target']
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
        signatureInput: data['signature-input'],
        signatureParams: data['signature-params']
      });
    });
  }
  
  setSignatureInput = (e) => {
    this.setState({
      signatureInput: e.target.value
    });
  }

  
  
  render = () => {
    return (
      <>
      <Box>
        <Heading>Input</Heading>
        <Section>
      		<Form.Label>HTTP Message</Form.Label>
      		<Form.Field>
      			<Form.Control>
  		        <Form.Textarea rows={10} spellCheck={false} onChange={this.setHttpMsg} value={this.state.httpMsg} />
      			</Form.Control>
      		</Form.Field>
            <Button onClick={this.parseHttpMsg}>Parse</Button>
            <Button onClick={this.loadExampleRequest}>Example Request</Button>
            <Button onClick={this.loadExampleResponse}>Example Response</Button>
        </Section>
      </Box>
      <Box>
        <Heading>Signature Parameters</Heading>
        <Section>
          <CoveredContent coveredContent={this.state.coveredContent} availableContent={this.state.availableContent} setCoveredContent={this.setCoveredContent} />
          <Form.Field>
            <Form.Label>Explicit Signature Algorithm</Form.Label>
            <Form.Control>
      				<Form.Select onChange={this.setAlgParam} value={this.state.algParam}>
                <option value="">Not Speficied</option>
                <option value="rsa-pss">RSA PSS</option>
                <option value="ec">EC</option>
                <option value="hmac">HMAC</option>
                <option value="rsa">RSA 1.5</option>
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
            </Form.Control>
            <Form.Control>
              <Button isStatic>
              {this.state.created && (
                <Moment>{this.state.created * 1000}</Moment>
              )}
              </Button>
            </Form.Control>
          </Form.Field>
          <Form.Label>Expiration Time</Form.Label>
          <Form.Field kind="addons">
            <Form.Control>
      				<Form.Input onChange={this.setExpires} value={this.state.expires ? String(this.state.expires) : ''} />
            </Form.Control>
            <Form.Control>
              <Button isStatic>
              {this.state.expires && (
                <Moment>{this.state.expires * 1000}</Moment>
              )}
              </Button>
            </Form.Control>
          </Form.Field>
          <Button onClick={this.generateSignatureInput}>Generate Signature Input</Button>
        </Section>
      </Box>
      <Box>
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
      		<Form.Label>Key material</Form.Label>
      		<Form.Field>
      			<Form.Control>
  		        <Form.Textarea rows={10} spellCheck={false} />
      			</Form.Control>
      		</Form.Field>
        </Section>
        <Section>
      		<Form.Field>
      			<Form.Label>Signature Algorithm</Form.Label>
      			<Form.Control>
              <Form.Select onChange={this.setAlg} disabled={this.state.algParam !== ''} value={this.state.algParam ? this.state.algParam : this.state.alg}>
                <option value="jose">Use JWA value from Key</option>
                <option value="rsa-pss">RSA PSS</option>
                <option value="ec">EC</option>
                <option value="hmac">HMAC</option>
                <option value="rsa">RSA 1.5</option>
      				</Form.Select>
      			</Form.Control>
      		</Form.Field>
        </Section>
      </Box>
      <Box>
        <Heading>Output</Heading>
        <Section>
      		<Form.Label>Signature Value</Form.Label>
      		<Form.Field>
      			<Form.Control>
  		        <Form.Textarea rows={10} spellCheck={false} />
      			</Form.Control>
      		</Form.Field>
        </Section>
        <Section>
      		<Form.Label>Signed HTTP Message</Form.Label>
      		<Form.Field>
      			<Form.Control>
  		        <Form.Textarea rows={10} spellCheck={false} />
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
    			<Form.Control>
  {props.availableContent.map((value, index) => (
            <label>
              <input type="checkbox" checked={props.coveredContent.includes(value)} onClick={props.setCoveredContent(value)} />
              <code>{value}{props.coveredContent.includes(value)}</code>
            </label>
  ))}
    			</Form.Control>
    		</Form.Field>
      </>
);


const IndexPage = () => <Layout>
  <HttpSigForm />
</Layout>;

export default IndexPage;

