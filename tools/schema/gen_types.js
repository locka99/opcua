let settings = require("./settings");
let types_xml = `${settings.schema_dir}/Opc.Ua.Types.bsd`;
let types = require("./types");

types.from_xml(types_xml, settings.rs_types_dir);
