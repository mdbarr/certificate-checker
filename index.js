#!/usr/bin/env node
'use strict';

const async = require('async');
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

function checkCertificate (certificate) {
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
    ...checkCertificate(certificate),
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
          ...checkCertificate(certificate),
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

      if (data.certificate?.infoAccess) {
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
      reason: 'Unable to fetch certificate',
    };
  } catch (error) {
    return {
      valid: false,
      location,
      reason: error.message,
    };
  }
}

async function main () {
  const locations = [
    'https://expired.badssl.com/',
    'https://wrong.host.badssl.com/',
    'https://self-signed.badssl.com/',
    'https://untrusted-root.badssl.com/',
    'https://revoked.badssl.com/',
    'https://pinning-test.badssl.com/',
    'https://no-common-name.badssl.com/',
    'https://no-subject.badssl.com/',
    'https://incomplete-chain.badssl.com/',
    'https://tls-v1-0.badssl.com:1010/',
    'https://tls-v1-1.badssl.com:1011/',
    'https://tls-v1-2.badssl.com:1012/',
    'https://rc4.badssl.com/',
  ];

  const validation = await async.map(locations, validateCertificate);
  console.log(validation);
}

main().catch(error => console.log(error));
