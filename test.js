var test = require('tape');
var d = require('./index.js');
var nacl = require('tweetnacl');

var hello = new Uint8Array([104, 101, 108, 108, 111])

test("Conversion functions", function (t) {
  t.plan(5);

  t.deepEqual(d.hex_to_u8("deadbeefc0de"), new Uint8Array([222, 173, 190, 239, 192, 222]), "Check hex_to_u8");
  t.deepEqual(d.hex_to_u8("0xdeadbeefc0de"), new Uint8Array([222, 173, 190, 239, 192, 222]), "Check hex_to_u8 with 0x");

  t.equal(d.u8_to_hex(new Uint8Array([222, 173, 190, 239, 192, 222])), "deadbeefc0de", "Check u8_to_hex");

  t.deepEqual(d.utf8_to_u8("Hello! 中英字典"), new Uint8Array([72,101,108,108,111,33,32,228,184,173,232,139,177,229,173,151,229,133,184]), "Check utf8_to_u8");
  t.equal(d.u8_to_utf8(new Uint8Array([72,101,108,108,111,33,32,228,184,173,232,139,177,229,173,151,229,133,184])), "Hello! 中英字典", "Check u8_to_utf8");
});

test("Structure defaults and clamping", function(t) {
  t.plan(9);

  t.deepEqual(d.make_struct(null), {"v": new Uint8Array(), "seq": 1}, "Check null value");
  t.deepEqual(d.make_struct({}), {"v": new Uint8Array(), "seq": 1}, "Check empty object");
  t.throws(function() { d.make_struct({"v": 12}) }, /must be a string or/, "Check type cast");
  t.deepEqual(d.make_struct({"v": "hello", "seq": 15}), {"v": hello, "seq": 15}, "Check high seq");
  t.deepEqual(d.make_struct({"v": "hello", "seq": "bad"}), {"v": hello, "seq": 1}, "Check string seq");
  t.deepEqual(d.make_struct({"v": "hello", "seq": -1000}), {"v": hello, "seq": 1}, "Check negative seq");
  t.deepEqual(d.make_struct({"v": [1,2,3]}), {"v": new Uint8Array([1,2,3]), "seq": 1}, "Check bytearray value");
  t.deepEqual(d.make_struct({"v": "hello", "salt": "beep"}), {"v": hello, "salt": "beep", "seq": 1}, "Check salt");
  t.deepEqual(d.make_struct({"v": "hello", "salt": "1234567890123456789012345678901234567890123456789012345678901234567890"}),
    {"v": hello, "salt": "1234567890123456789012345678901234567890123456789012345678901234", "seq": 1}, "Check salt clamp");
});

test("Sig material generation", function (t) {
  t.plan(6);

  t.equal(d.u8_to_utf8(d.make_sig_check({
    "salt": "foobar",
    "seq": 5,
    "v": d.utf8_to_u8("Hello! 中英字典"),
  })), "4:salt6:foobar3:seqi5e1:v19:Hello! 中英字典", "Check make_sig_check");

  t.equal(d.u8_to_utf8(d.make_sig_check({
    "salt": "中英字典",
    "seq": 5,
    "v": d.utf8_to_u8("One two three foobar."),
  })), "4:salt12:中英字典3:seqi5e1:v21:One two three foobar.", "Check make_sig_check");

  t.equal(d.u8_to_utf8(d.make_sig_check({
    "seq": 7,
    "v": d.utf8_to_u8("One two three goober."),
  })), "3:seqi7e1:v21:One two three goober.", "Check make_sig_check");

  t.equal(d.u8_to_utf8(d.make_sig_check({
    "v": "Auto encode test.",
  })), "3:seqi1e1:v17:Auto encode test.", "Check make_sig_check");

  // bep 0044 test vector 1
  t.equal(d.u8_to_utf8(d.make_sig_check({
    "v": d.utf8_to_u8("Hello World!"),
  })), "3:seqi1e1:v12:Hello World!", "Check make_sig_check (bep0044 check)");

  t.equal(d.u8_to_utf8(d.make_sig_check({
    "salt": "foobar",
    "v": d.utf8_to_u8("Hello World!"),
  })), "4:salt6:foobar3:seqi1e1:v12:Hello World!", "Check make_sig_check (bep0044 check)");
});

test("Test signatures", function(t) {
  t.plan(11);

  var bep44_vec1 = {
    "v": "Hello World!",
    "seq": 1,
    "k": d.hex_to_u8("77ff84905a91936367c01360803104f92432fcd904a43511876df5cdf3e7e548"),
    "sig": d.hex_to_u8("305ac8aeb6c9c151fa120f120ea2cfb923564e11552d06a5d856091e5e853cff1260d3f39e4999684aa92eb73ffd136e6f4f3ecbfda0ce53a1608ecd7ae21f01"),
  }

  t.deepEquals(d.freshest(null, bep44_vec1, nacl.sign.detached.verify), bep44_vec1, "BEP0044 test vector 1");

  // test vector key and signature material
  var v2k = d.hex_to_u8("77ff84905a91936367c01360803104f92432fcd904a43511876df5cdf3e7e548");
  var v2s = d.hex_to_u8("6834284b6b24c3204eb2fea824d82f88883a3d95e8b4a21b8c0ded553d17d17ddf9a8a7104b1258f30bed3787e6cb896fca78c58f8e03b5f18f14951a87d9a08");
  var v2sk = d.hex_to_u8("e06d3183d14159228433ed599221b80bd0a5ce8352e4bdf0262f76786ef1c74db7e7a9fea2c0eb269d61e3b38e450a22e754941ac78479d6c54e1faf6037881d");

  var bep44_vec2 = {
    "v": "Hello World!",
    "salt": "foobar",
    "seq": 1,
    "k": v2k,
    "sig": v2s,
  }

  t.deepEquals(d.freshest(null, bep44_vec2, nacl.sign.detached.verify), bep44_vec2, "BEP0044 test vector 2");

  bep44_vec2_mutated = {
    "v": "Hello World!!!",
    "salt": "foobar",
    "seq": 1,
    "k": v2k,
    "sig": v2s,
  }
  // test bad sig by mutating val
  t.deepEquals(d.freshest(null, bep44_vec2_mutated, nacl.sign.detached.verify), {"v": new Uint8Array(), "seq": 1}, "BEP0044 test vector 2 mutated value");

  bep44_vec2_mutated_salt = {
    "v": "Hello World!",
    "salt": "foobarr",
    "seq": 1,
    "k": v2k,
    "sig": v2s,
  }
  // test bad sig by mutating salt
  t.deepEquals(d.freshest(null, bep44_vec2_mutated_salt, nacl.sign.detached.verify), {"v": new Uint8Array(), "seq": 1}, "BEP0044 test vector 2 mutated salt");

  bep44_vec2_mutated_pk = {
    "v": "Hello World!",
    "salt": "foobar",
    "seq": 1,
    "k": d.hex_to_u8("87ff84905a91936367c01360803104f92432fcd904a43511876df5cdf3e7e548"),
    "sig": v2s,
  }
  // test bad sig by mutating pk
  t.deepEquals(d.freshest(null, bep44_vec2_mutated_salt, nacl.sign.detached.verify), {"v": new Uint8Array(), "seq": 1}, "BEP0044 test vector 2 mutated pk");

  // test lower sequence
  t.deepEquals(d.freshest({"v": "hello", "seq": 2}, bep44_vec2, nacl.sign.detached.verify), {"v": hello, "seq": 2}, "BEP0044 test vector 2 versus higher seq");

  // CAS and signing tests

  var kp = nacl.sign.keyPair.fromSeed(d.hex_to_u8("b771f53c3b8bd7a3cb9bf4ecbf9bab6e33fb9fa48f2357938925bd80db462a51"));
  // test cas match
  var cas_test_a = {
    "v": d.utf8_to_u8("a"),
    "seq": 1,
    "k": kp.publicKey,
  };

  var cas_test_b = {
    "v": d.utf8_to_u8("b"),
    "seq": 2,
    "cas": 1,
    "k": kp.publicKey,
  };

  // test basic signing
  var sig = nacl.sign.detached(d.make_sig_check(cas_test_a), kp.secretKey);
  t.ok(nacl.sign.detached.verify(d.make_sig_check(cas_test_a), sig, kp.publicKey), "Verify basic struct signature");

  var sig = nacl.sign.detached(d.make_sig_check(cas_test_b), kp.secretKey);
  t.ok(nacl.sign.detached.verify(d.make_sig_check(cas_test_b), sig, kp.publicKey), "Verify basic struct signature");

  cas_test_a.sig = nacl.sign.detached(d.make_sig_check(cas_test_a), kp.secretKey);
  cas_test_b.sig = nacl.sign.detached(d.make_sig_check(cas_test_b), kp.secretKey);

  // CAS success
  t.deepEquals(d.freshest(cas_test_a, cas_test_b, nacl.sign.detached.verify), cas_test_b, "Test compare-and-swap success");

  cas_test_b["cas"] = 2;
  // CAS fail 1
  t.deepEquals(d.freshest(cas_test_a, cas_test_b, nacl.sign.detached.verify), cas_test_a, "Test compare-and-swap fail 1");

  cas_test_b["cas"] = -12;
  // CAS fail 2
  t.deepEquals(d.freshest(cas_test_a, cas_test_b, nacl.sign.detached.verify), cas_test_a, "Test compare-and-swap fail 2");
});
