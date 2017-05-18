var SignedXml = require('xml-crypto').SignedXml;
var algorithms = require('./algorithms');

var authnRequestXPath = '/*[local-name(.)="AuthnRequest" and namespace-uri(.)="urn:oasis:names:tc:SAML:2.0:protocol"]';
var defaultTransforms = [ 'http://www.w3.org/2000/09/xmldsig#enveloped-signature', 'http://www.w3.org/2001/10/xml-exc-c14n#' ];

function signSamlPost(samlMessage, xpath, options) {
  if (!samlMessage) throw new Error('samlMessage is required');
  if (!xpath) throw new Error('xpath is required');
  if (!options || !options.privateCert) throw new Error('options.privateCert is required');
  if (!options || !options.authnCertificate) throw new Error('options.authnCertificate is required');

  var transforms = options.xmlSignatureTransforms || defaultTransforms;
  var sig = new SignedXml();
  if (options.signatureAlgorithm) {
    sig.signatureAlgorithm = algorithms.getSigningAlgorithm(options.signatureAlgorithm);
  }
  sig.addReference(xpath, transforms, algorithms.getDigestAlgorithm(options.digestAlgorithm));
  sig.signingKey = options.privateCert;
  sig.authnCertificate = options.authnCertificate;

  const opts = {
    prefix: 'ds',
  };

  sig.computeSignature(samlMessage, opts);
  return sig.getSignedXml();
}

function signAuthnRequestPost(authnRequest, options) {
  return signSamlPost(authnRequest, authnRequestXPath, options);
}

exports.signSamlPost = signSamlPost;
exports.signAuthnRequestPost = signAuthnRequestPost;