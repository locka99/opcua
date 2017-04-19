var fs = require("fs");

exports.schema_dir = `${__dirname}/../../schemas/1.0.3`;
exports.rs_dir = `${__dirname}/../../core/src`;
exports.rs_address_space_dir = `${__dirname}/../../server/src/address_space`;

exports.write_to_file = function (file_path, contents) {
  var buffer = new Buffer(contents);
  var fd = fs.openSync(file_path, 'w');
  fs.writeSync(fd, buffer, 0, buffer.length, null);
  fs.closeSync(fd);
};