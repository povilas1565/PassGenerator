'use strict';

import * as forge from 'node-forge';

const APPLE_CA_CERTIFICATE = forge.pki.certificateFromPem(
  process.env.APPLE_WWDR_CERT_PEM ||
    `-----BEGIN CERTIFICATE-----

-----END CERTIFICATE-----`,
);

/**
 * Signs a manifest and returns the signature.
 *
 * @param {import('node-forge').pki.Certificate} certificate - signing certificate
 * @param {import('node-forge').pki.PrivateKey} key - certificate password
 * @param {string} manifest - manifest to sign
 * @returns {Buffer} - signature for given manifest
 */
export function signManifest(
  certificate: forge.pki.Certificate,
  key: forge.pki.PrivateKey,
  manifest: string,
): Buffer {
  // create PKCS#7 signed data
  const p7 = forge.pkcs7.createSignedData();
  p7.content = manifest;
  p7.addCertificate(certificate);
  p7.addCertificate(APPLE_CA_CERTIFICATE);
  p7.addSigner({
    key: forge.pki.privateKeyToPem(key),
    certificate,
    digestAlgorithm: forge.pki.oids.sha1,
    authenticatedAttributes: [
      {
        type: forge.pki.oids.contentType,
        value: forge.pki.oids.data,
      },
      {
        type: forge.pki.oids.messageDigest,
        // value will be auto-populated at signing time
      },
      {
        type: forge.pki.oids.signingTime,
        // value will be auto-populated at signing time
        // value: new Date('2050-01-01T00:00:00Z')
      },
    ],
  });

  /**
   * Creating a detached signature because we don't need the signed content.
   */
  p7.sign({ detached: true });

  return Buffer.from(forge.asn1.toDer(p7.toAsn1()).getBytes(), 'binary');
}
