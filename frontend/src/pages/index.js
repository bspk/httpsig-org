import React from 'react';

import Layout from '../components/layout';

import { Button, Tabs, Container, Section, Level, Form, Columns, Content } from 'react-bulma-components';

const api = 'https://y2dgwjj82j.execute-api.us-east-1.amazonaws.com/dev'

class HttpSigForm extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      httpMsg: '',
      coveredContent: ['@request-target', 'Header1', 'Header2'],
      requestTarget: ''
    };
  }
  
  setHttpMsg = (e) => {
    this.setState({
      httpMsg: e.target.value
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
      var coveredContent = data['headers'];
      if (data['request-target']) {
        coveredContent.push('@request-target');
      }
      this.setState({
        coveredContent: coveredContent,
        requestTarget: data['request-target']
      });
    });
  }
  
  render = () => {
    return (
      <>
      <Section>
    		<Form.Label>HTTP Message</Form.Label>
    		<Form.Field>
    			<Form.Control>
		        <Form.Textarea rows={10} spellCheck={false} onChange={this.setHttpMsg} value={this.state.httpMsg} />
            <Button onClick={this.parseHttpMsg}>Parse</Button>
    			</Form.Control>
    		</Form.Field>
      </Section>
      <CoveredContent coveredContent={this.state.coveredContent} />
      <Section>
    		<Form.Label>Signature Base String</Form.Label>
    		<Form.Field>
    			<Form.Control>
		        <Form.Textarea rows={10} spellCheck={false} />
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
    			<Form.Label>Signature algorithm</Form.Label>
    			<Form.Control>
    				<Form.Select>
              <option value="jose">Use JWA value from Key</option>
              <option value="rsa-pss">RSA PSS</option>
              <option value="ec">EC</option>
              <option value="hmac">HMAC</option>
              <option value="rsa">RSA 1.5</option>
    				</Form.Select>
    			</Form.Control>
    		</Form.Field>
      </Section>
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
      </>
    );
  }
  
}

const CoveredContent = ({...props}) =>
      <Section>
    		<Form.Label>Covered content</Form.Label>
    		<Form.Field kind='group'>
    			<Form.Control>
  {props.coveredContent.map((value, index) => (
		        <Form.Checkbox>
              <code>{value}</code>
            </Form.Checkbox>
  ))}
    			</Form.Control>
    		</Form.Field>
      </Section>
;


const IndexPage = () => <Layout>
  <HttpSigForm />
</Layout>;

export default IndexPage;

