var fs = require("fs");

exports.write_to_file = function (file_path, contents) {
    var buffer = new Buffer(contents);
    var fd = fs.openSync(file_path, 'w');
    fs.writeSync(fd, buffer, 0, buffer.length, null);
    fs.closeSync(fd);
};