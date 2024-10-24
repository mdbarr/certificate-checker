#!/usr/bin/env node
'use strict';

const async = require('async');
const { X509Certificate } = require('node:crypto');
const fs = require('node:fs/promises');
const https = require('node:https');
const url = require('node:url');

const defaults = {
  agent: false,
  method: 'HEAD',
  rejectUnauthorized: false,
};

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
        ...defaults,
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
  let certificate;

  try {
    if (location.startsWith('https://')) {
      certificate = await getHTTPSCertificate(url.parse(location));
    } else if (location.startsWith('/')) {
      certificate = await getFileCertificate(location);
    } else {
      certificate = await getHTTPSCertificate({ hostname: location });
    }

    if (certificate) {
      const validation = {
        valid: true,
        location,
        daysRemaining: certificate.daysRemaining,
        validFrom: certificate.validFrom,
        validTo: certificate.validTo,
      };

      if (typeof certificate.authorized !== 'undefined') {
        validation.valid = certificate.authorized;
        if (!certificate.authorized) {
          validation.reason = certificate.authorizationError;
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
  ];

  const validation = await async.map(locations, validateCertificate);
  console.log(validation);
}

main().catch(error => console.log(error));
