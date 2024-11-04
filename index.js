'use strict';

const { X509Certificate } = require('node:crypto');
const { getCertStatus } = require('easy-ocsp');
const fs = require('node:fs/promises');
const https = require('node:https');
const url = require('node:url');

const httpsDefaults = {
  agent: false,
  method: 'HEAD',
  rejectUnauthorized: false,
};

const subjectRegExp = /CN=(.*)$/u;

function checkCertificateDates (certificate) {
  const validTo = new Date(certificate.validTo);
  const daysRemaining = Math.floor((validTo.getTime() - Date.now()) / 86400000);
  return {
    daysRemaining,
    validFrom: new Date(certificate.validFrom).toISOString(),
    validTo: validTo.toISOString(),
  };
}

async function getFileCertificate (filename) {
  const data = await fs.readFile(filename);
  const certificate = new X509Certificate(data);
  return {
    certificate,
    ...checkCertificateDates(certificate),
  };
}

function getHTTPSCertificate ({ hostname, port = 443 }) {
  return new Promise((resolve, reject) => {
    try {
      const req = https.request({
        ...httpsDefaults,
        hostname,
        port,
      }, (res) => {
        const certificate = res.socket.getPeerX509Certificate();
        const cipher = res.socket.getCipher();
        res.socket.destroy();
        return resolve({
          authorizationError: res.socket.authorizationError,
          authorized: res.socket.authorized,
          certificate,
          cipher,
          hostname,
          ...checkCertificateDates(certificate),
        });
      });

      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        return reject(new Error(`Connection to ${ hostname } timed out`));
      });

      return req.end();
    } catch (error) {
      return reject(error);
    }
  });
}

async function validateCertificate (location) {
  let validation;

  try {
    let data;

    if (location.startsWith('https://')) {
      data = await getHTTPSCertificate(url.parse(location));
    } else if (location.startsWith('/')) {
      data = await getFileCertificate(location);
    } else {
      data = await getHTTPSCertificate({ hostname: location });
    }

    if (data) {
      validation = {
        valid: true,
        location,
        cname: null,
        daysRemaining: data.daysRemaining,
        validFrom: data.validFrom,
        validTo: data.validTo,
        certificate: data.certificate,
        cipher: data.cipher,
        ocsp: null,
        errors: [],
        warnings: [],
        status: 'ok',
      };

      if (typeof data.authorized !== 'undefined') {
        validation.valid = data.authorized;
        if (!data.authorized) {
          validation.errors.push(data.authorizationError);
        }
      }

      if (data.certificate.subject) {
        if (subjectRegExp.test(data.certificate.subject)) {
          const [ , cname ] = data.certificate.subject.match(subjectRegExp);
          validation.cname = cname;
        } else {
          validation.valid = false;
          validation.errors.push("Certificate doesn't contain a common name");
        }
      } else {
        validation.valid = false;
        validation.errors.push("Certificate doesn't contain a subject");
      }

      if (validation.valid && data.certificate?.infoAccess) {
        try {
          const ocspResult = await getCertStatus(data.certificate);
          validation.ocsp = ocspResult;

          if (ocspResult.state === 'revoked') {
            validation.valid = false;
            validation.errors.push('Certificate has been revoked');
          }
        } catch (error) {
          validation.warnings.push(`OCSP validation failure: ${ error.message }`);
        }
      }
    } else {
      validation.valid = false;
      validation.errors.push(`Unable to get the certificate at ${ validation.location }`);
    }

    if (validation.valid) {
      if (validation.daysRemaining <= 14) {
        validation.warnings.push('Certificate expires within two weeks');
      }

      if (validation.cipher) {
        if (validation.cipher.version !== 'TLSv1.3') {
          validation.warnings.push(`Outdated TLS, using version ${ validation.cipher.version } instead of TLSv1.3`);
        }
      }

      if (validation.warnings.length) {
        validation.status = 'warning';
      }
    } else {
      validation.status = 'invalid';
    }

    return validation;
  } catch (error) {
    if (typeof validation === 'object' && validation !== null) {
      validation.valid = false;
      validation.errors.push(error.message);
    } else {
      validation = {
        valid: false,
        location,
        errors: [ error.message ],
      };
    }

    return validation;
  }
}

module.exports = {
  getFileCertificate,
  getHTTPSCertificate,
  validate: validateCertificate,
  validateCertificate,
};
