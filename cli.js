#!/usr/bin/env node
'use strict';

const async = require('async');
const { validate } = require('./index');
const process = require('node:process');
const { styleText } = require('node:util');
const parser = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');

const { version } = require('./package.json');

function formatter (results, options) {
  for (const result of results) {
    if (!result.valid && options.exitCode) {
      process.exitCode = 1;
    }
  }

  if (options.json) {
    console.log(JSON.stringify(results, null, 2));
  } else {
    for (const result of results) {
      const icon = result.valid ? styleText('green', ' \u2714 ') : styleText('red', ' \u2716 ');
      const valid = result.valid ? styleText('green', 'ok') : styleText('red', 'invalid');

      const reasons = result.reasons.length ? styleText('red', ` ${ result.reasons.join(', ') }`) : '';

      let details = '';
      if (result.valid && options.verbose) {
        details = styleText('grey', `  ${ result.cname } valid until ${ result.validTo.replace(/T.*$/u, '') } (${ result.daysRemaining } days)`);
      }

      console.log(`${ icon }${ result.location } ${ valid }${ reasons || details }`);
    }
  }
}

async function main () {
  await parser(hideBin(process.argv)).
    command('check <locations...>', 'Check the certificates at the given location(s).',
      (yargs) => yargs.positional('locations', { describe: 'URLs or local filesystem paths' }),
      async (argv) => {
        const results = await async.map(argv.locations, validate);
        return formatter(results, argv);
      }).
    option('exit-code', {
      type: 'boolean',
      default: true,
      description: 'Exit with a non-zero code when certificate validation fails',
    }).
    option('json', {
      alias: 'j',
      type: 'boolean',
      description: 'Output results in JSON format',
    }).
    option('verbose', {
      alias: 'v',
      type: 'boolean',
      description: 'Verbose output',
    }).
    strictCommands().
    demandCommand(1).
    help().
    scriptName('certificate-checker').
    version(version).
    parse();
}

main().catch(error => console.log(error));
