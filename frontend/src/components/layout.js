import React from 'react'
import PropTypes from 'prop-types'
import './layout.sass'
import { Button, Tabs, Container, Section, Level, Form, Columns, Content, Hero, Heading } from 'react-bulma-components';
import { Helmet } from 'react-helmet'

const Layout = ({ children }) => (
  <>
      <Helmet title="HTTP Message Signatures Sandbox" />      
      <Container>
          <Hero>
            <Hero.Body>
            <Heading>HTTP Message Signatures</Heading>
              <p>
              This site allows you to try out HTTP Message Signatures interactively. This page works in two modes: signing and verifying. To sign, add an HTTP message to the form, choose which components should be signed, choose the signing key and algorithm, and view the signed results. To verify, add a signed HTTP message to the form, choose which signature to verify, supply the verification key material, and verify the results.
              </p>
            </Hero.Body>
          </Hero>
          {children}
      </Container>
  </>
)

Layout.propTypes = {
  children: PropTypes.node.isRequired,
}

export default Layout
