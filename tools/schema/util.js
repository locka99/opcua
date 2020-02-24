var fs = require("fs");

exports.write_to_file = function (file_path, contents) {
    var buffer = new Buffer(contents);
    var fd = fs.openSync(file_path, 'w');
    fs.writeSync(fd, buffer, 0, buffer.length, null);
    fs.closeSync(fd);
};

// Parses a string node id into an object with
exports.parse_node_id = function (node_id) {
    let re = /(?:ns=([0-9]+);)?(i|b|s|g)=([a-zA-Z0-9\-]+)/;
    let m = node_id.toString().match(re);
    if (m) {
        return {
            ns: m[1] ? m[1] : 0,
            type: m[2],
            value: m[3],
        };
    } else {
        return null;
    }
}