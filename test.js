var test = require('tape');
var d = require('./index.js');
var nacl = require('tweetnacl');

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

  var hello = new Uint8Array([104, 101, 108, 108, 111])

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
