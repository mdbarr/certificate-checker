#!/usr/bin/env node
'use strict';

const async = require('async');
const { validate } = require('./index');
const { hideBin } = require('yargs/helpers');
const { version } = require('./package.json');

async function main () {
  await require('yargs/yargs')(hideBin(process.argv)).
    command('check <locations...>', 'Check the certificates at the given location(s).',
      (yargs) => yargs.positional('locations', { describe: 'URLs or local filesystem paths' }),
      async (argv) => {
        const results = await async.map(argv.locations, validate);
        console.log(results);
      }).
    strictCommands().
    demandCommand(1).
    help().
    scriptName('certificate-checker').
    version(version).
    parse();
}

main().catch(error => console.log(error));
