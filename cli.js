#!/usr/bin/env node
'use strict';

const async = require('async');
const { validate } = require('./index');
const process = require('node:process');
const { styleText } = require('node:util');
const parser = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');

const { version } = require('./package.json');

function formatter (results) {
  for (const result of results) {
    const icon = result.valid ? styleText('green', ' \u2714 ') : styleText('red', ' \u2716 ');
    const valid = result.valid ? styleText('green', 'ok') : styleText('red', 'invalid');
    const reasons = result.reasons.length ? styleText('red', ` ${ result.reasons.join(', ') }`) : '';
    console.log(`${ icon }${ result.location } ${ valid }${ reasons }`);
    if (!result.valid) {
      process.exitCode = 1;
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
