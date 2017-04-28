const fs = require('fs')
const should = require('should');
const signMessage = require('../lib/passport-saml/saml-post-signing')

const signingKey = fs.readFileSync(__dirname + '/static/key.pem')

describe('SAML POST Signing', function () {
  it('should sign a simple saml request', function () {
    var xml = '<SAMLRequest/>'
    var result = signMessage(xml, '/SAMLRequest', signingKey, {})
    result.should.not.be.null
  })

  it('should sign and digest with SHA256 when specified', function () {
    var xml = '<SAMLRequest/>'
    var options = {
      signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
      digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256'
    }
    var result = signMessage(xml, '/SAMLRequest', signingKey, options)
    result.should.match(/<SignatureMethod Algorithm="http:\/\/www.w3.org\/2001\/04\/xmldsig-more#rsa-sha256"/)
    result.should.match(/<Transform Algorithm="http:\/\/www.w3.org\/2001\/10\/xml-exc-c14n#"\/>/)
    result.should.match(/<DigestMethod Algorithm="http:\/\/www.w3.org\/2001\/04\/xmlenc#sha256"\/>/)
  })
})