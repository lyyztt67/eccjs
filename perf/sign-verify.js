//run many signs and verifies
var ecc = require('../');
var prettyHrtime = require('pretty-hrtime');
var crypto = require('crypto');
function sha256(m) {
  return crypto.createHash('sha256').update(m).digest();
}

//key size
['k192', 'k256', 'c384'].forEach(function(c) {
  //buffer size
  [1, 2, 3, 4, 5].forEach(function(factor) {

    var buffersize = Math.pow(10, factor);
    var plain = new Buffer(buffersize);
    plain.fill("a");

    var curve = ecc.curves[c];

    var keyst = process.hrtime();
    var keys = ecc.generate(curve);
    keyst = process.hrtime(keyst);

    var hasht = process.hrtime();
    var hash = sha256(plain);
    hasht = process.hrtime(hasht);

    var sigt = process.hrtime();
    var sig = ecc.sign(curve, keys, hash);
    sigt = process.hrtime(sigt);

    var vert = process.hrtime();
    var result = ecc.verify(curve, keys, sig, hash);
    vert = process.hrtime(vert);

    console.log('curve: %s, buffer: 1e%sbytes, generate-keys: %s, sha256: %s, sign: %s, verify: %s',
                 c, factor, prettyHrtime(keyst), prettyHrtime(hasht), prettyHrtime(sigt), prettyHrtime(vert));

  });
});