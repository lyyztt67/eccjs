var tape = require('tape')

var ecc = require('../')
var sjcl = require('../vendor/sjcl')
var crypto = require('crypto')
function hash (m) {
  return crypto.createHash('sha256').update(m).digest()
}

tape('generate & sign valid keys', function (t) {
  var curve = ecc.curves.k256
  var keys = ecc.generate(curve)
//  console.log('Keys', keys)
  
  console.log('public key', keys.public.length, keys.public)
  console.log('private key', keys.private.length, keys.private)

  var message = hash('hello!')
  var sig = ecc.sign(curve, keys, message)
  console.log('Sig', sig)
  var valid = ecc.verify(curve, keys, sig, message)
  console.log('Valid?', valid)
  t.equal(valid, true, '(correct hash, sig, key, curve ==> valid)')

  //change a bit, should make the sig invalid
  var wrong = new Buffer(message)
  wrong[5] = 6
  var valid = ecc.verify(curve, keys, sig, wrong)
  t.equal(valid, false, '(wrong message, signature is invalid)')

  var wrongSig = new Buffer(sig)
  wrongSig[5] = 6

  var valid = ecc.verify(curve, keys, wrongSig, message)
  t.equal(valid, false, '(wrong message)')

  var valid = ecc.verify(ecc.curves.c256, keys, sig, message)
  t.equal(valid, false, '(wrong curve)')

  var b64 = sig.toString('base64')
  console.log(b64, b64.length, sig.length)

  //recreate a key from a private key
  var _keys = ecc.restore(curve, keys.private)

  t.deepEqual(_keys, keys, 'recreate keys from a private key')

  t.end()
})
