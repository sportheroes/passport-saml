var SignedXml = require('xml-crypto').SignedXml
module.exports = function signMessage(samlMessage, xpath, signingKey, options) {
  if (!samlMessage) throw new Error('samlMessage is required')
  if (!xpath) throw new Error('xpath is required')
  if (!signingKey) throw new Error('signingKey is required')
  options = options || {}

  var sig = new SignedXml()
  if (options.signatureAlgorithm) {
    sig.signatureAlgorithm = options.signatureAlgorithm
  }
  sig.addReference(xpath, null, options.digestAlgorithm)
  sig.signingKey = signingKey
  sig.computeSignature(samlMessage)
  return sig.getSignedXml()
}