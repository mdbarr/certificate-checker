'use strict';

const { X509Certificate } = require('node:crypto');
const { getCertStatus } = require('easy-ocsp');
const fs = require('node:fs/promises');
const https = require('node:https');
const url = require('node:url');

const defaultRules = {
  expiration: {
    enabled: true,
    level: 'warning',
    days: 14,
  },
  ocsp: {
    enabled: true,
    level: 'error',
    failure: 'info',
  },
  tls: {
    enabled: true,
    level: 'warning',
  },
};

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
    type: 'file',
    certificate,
    ...checkCertificateDates(certificate),
  };
}

function getHostCertificate ({ hostname, port = 443 }) {
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
          type: 'host',
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

function annotate (validation, level, message) {
  if (level === 'error') {
    validation.valid = false;
    validation.errors.push(message);
  } else if (level === 'warning') {
    validation.warnings.push(message);
  } else {
    validation.info.push(message);
  }
}

async function validateCertificate (location, options) {
  let validation;

  try {
    const rules = {
      ...defaultRules,
      ...options,
    };

    let data;

    if (location.startsWith('https://')) {
      data = await getHostCertificate(url.parse(location));
    } else if (location.startsWith('/')) {
      data = await getFileCertificate(location);
    } else {
      data = await getHostCertificate({ hostname: location });
    }

    if (data) {
      validation = {
        type: data.type,
        location,
        valid: true,
        status: 'ok',
        cname: null,
        issuer: null,
        daysRemaining: data.daysRemaining,
        validFrom: data.validFrom,
        validTo: data.validTo,
        certificate: data.certificate,
        cipher: data.cipher,
        ocsp: null,
        errors: [],
        warnings: [],
        info: [],
        serialNumber: data.certificate.serialNumber,
        checked: Date.now(),
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

      if (data.certificate.issuer) {
        if (subjectRegExp.test(data.certificate.issuer)) {
          const [ , issuer ] = data.certificate.issuer.match(subjectRegExp);
          validation.issuer = issuer;
        } else {
          validation.valid = false;
          validation.errors.push("Certificate doesn't contain an issuer");
        }
      }

      if (rules?.ocsp?.enabled && data.certificate?.infoAccess) {
        try {
          const ocspResult = await getCertStatus(data.certificate);
          validation.ocsp = ocspResult;

          if (ocspResult.status === 'revoked') {
            annotate(validation, rules?.ocsp?.level, 'Certificate has been revoked');
          }
        } catch (error) {
          annotate(validation, rules?.ocsp.failure, `OCSP validation failure: ${ error.message }`);
        }
      }
    } else {
      validation.valid = false;
      validation.errors.push(`Unable to get the certificate at ${ validation.location }`);
    }

    if (validation.valid) {
      if (rules?.expiration?.enabled && validation.daysRemaining <= rules?.expiration?.days) {
        annotate(validation, rules?.expiration.level, `Certificate expires within ${ rules?.expiration?.days } days`);
      }

      if (rules?.tls?.enabled && validation.cipher) {
        if (validation.cipher.version !== 'TLSv1.3') {
          annotate(validation, rules?.tls?.level, `Outdated TLS, using version ${ validation.cipher.version } instead of TLSv1.3`);
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
  getHostCertificate,
  validate: validateCertificate,
  validateCertificate,
};
