import React from 'react'
import PropTypes from 'prop-types'
import './layout.sass'
import { Button, Tabs, Container, Section, Level, Form, Columns, Content, Hero, Heading, Footer } from 'react-bulma-components';
import { Helmet } from 'react-helmet'

const Layout = ({ children }) => (
  <>
      <Helmet title="HTTP Message Signatures Sandbox" />      
      <Container>
          <Hero>
            <Hero.Body>
            <Heading>HTTP Message Signatures</Heading>
              <p>
              This site allows you to try out <a href="https://www.rfc-editor.org/rfc/rfc9421.html">HTTP Message Signatures (RFC9421)</a> interactively. This page works in two modes: signing and verifying, both working in four steps. To sign, add an HTTP message to the form, choose which components should be signed, choose the signing key and algorithm, and view the signed results. To verify, add a signed HTTP message to the form, choose which signature to verify, supply the verification key material, and verify the results. You can also find a list of implementations of the specification in a variety of languages.
              </p>
            </Hero.Body>
          </Hero>
          {children}
          <Footer>This service is provided by <a href="https://bspk.io/">Bespoke Engineering</a> and <a href="https://www.authlete.com">Authlete</a>. The source is available <a href="https://github.com/bspk/httpsig-org/">on GitHub</a>.</Footer>
      </Container>
  </>
)

Layout.propTypes = {
  children: PropTypes.node.isRequired,
}

export default Layout
