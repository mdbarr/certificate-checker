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
        return reject(new Error('Timed Out'));
      });

      return req.end();
    } catch (error) {
      return reject(error);
    }
  });
}

async function validateCertificate (location) {
  let data;

  try {
    if (location.startsWith('https://')) {
      data = await getHTTPSCertificate(url.parse(location));
    } else if (location.startsWith('/')) {
      data = await getFileCertificate(location);
    } else {
      data = await getHTTPSCertificate({ hostname: location });
    }

    if (data) {
      const validation = {
        valid: true,
        location,
        cname: null,
        daysRemaining: data.daysRemaining,
        validFrom: data.validFrom,
        validTo: data.validTo,
        certificate: data.certificate,
        cipher: data.cipher,
        ocsp: null,
        reasons: [],
      };

      if (typeof data.authorized !== 'undefined') {
        validation.valid = data.authorized;
        if (!data.authorized) {
          validation.reasons.push(data.authorizationError);
        }
      }

      if (data.certificate.subject) {
        if (subjectRegExp.test(data.certificate.subject)) {
          const [ , cname ] = data.certificate.subject.match(subjectRegExp);
          validation.cname = cname;
        } else {
          validation.valid = false;
          validation.reasons.push('NO_CERT_CNAME');
        }
      } else {
        validation.valid = false;
        validation.reasons.push('NO_CERT_SUBJECT');
      }

      if (validation.valid && data.certificate?.infoAccess) {
        const ocspResult = await getCertStatus(data.certificate);
        validation.ocsp = ocspResult;

        if (ocspResult.state === 'revoked') {
          validation.valid = false;
          validation.reasons.push('CERT_REVOKED');
        }
      }

      return validation;
    }

    return {
      valid: false,
      location,
      reason: 'UNABLE_TO_GET_CERT',
    };
  } catch (error) {
    return {
      valid: false,
      location,
      reason: error.message,
    };
  }
}

module.exports = {
  getFileCertificate,
  getHTTPSCertificate,
  validate: validateCertificate,
  validateCertificate,
};
