let _ = require("lodash");
let types = require("./types");

// gen_nodeset.js is a generalized nodeset parser / generator.

let argv = require("yargs")
    .usage("Usage: $0 --bsd [path] --module [name] --outputdir [path]")
    .demandOption(['bsd', 'module'])
    .describe('bsd', "The OPC UA Bsd file to parse")
    .describe('module', "Path to the module folder.")
    .argv;


let config = {
    bsd_file: argv.bsd,
    rs_module: argv.module
};

if (config.bsd_file.includes('.xml')) {
    types.from_nodeset(config);
} else {
    types.from_xml(config);
}

