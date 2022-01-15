let _ = require("lodash");
let types = require("./types");
let fs = require("fs");

// gen_datatypes.js generates a rust module with the structs and enum from a .bsd file.

let argv = require("yargs")
    .usage("Usage: $0 --bsd [path] --module [name]")
    .demandOption(['bsd', 'module'])
    .describe('bsd', "The OPC UA Bsd file to parse")
    .describe('module', "Path to the module folder.")
    .argv;

let bsd_file = argv.bsd;
let rs_module = argv.module;

if (!fs.existsSync(rs_module)) {
    fs.mkdirSync(rs_module, {recursive: true});
}

types.from_xml(bsd_file, rs_module);
