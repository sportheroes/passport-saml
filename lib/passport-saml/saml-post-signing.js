var SignedXml = require('xml-crypto').SignedXml
var transforms = [
  "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
  "http://www.w3.org/2001/10/xml-exc-c14n#"
]
module.exports = function signPostMessage(samlMessage, xpath, signingKey, options) {
  if (!samlMessage) throw new Error('samlMessage is required')
  if (!xpath) throw new Error('xpath is required')
  if (!signingKey) throw new Error('signingKey is required')
  options = options || {}

  var sig = new SignedXml()
  if (options.signatureAlgorithm) {
    sig.signatureAlgorithm = options.signatureAlgorithm
  }

  sig.addReference(xpath, transforms, options.digestAlgorithm)
  sig.signingKey = signingKey
  sig.computeSignature(samlMessage)
  return sig.getSignedXml()
}