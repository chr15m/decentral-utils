function u8_to_hex(x) {
  // https://stackoverflow.com/a/39225475/2131094
  return x.reduce(function(memo, i) {
    return memo + ('00' + i.toString(16)).slice(-2);
  }, '');
}

function hex_to_u8(h) {
  if (h.indexOf("0x") == 0) {
    var h = h.replace("0x", "");
  }
  var u = new Uint8Array(h.length / 2);
  for (var i=0; i<h.length/2; i++) {
    u[i] = parseInt("" + h[i*2] + h[i*2+1], 16);
  }
  return u;
}

if (typeof(TextEncoder) == "object") {
  var utf8encoder = new TextEncoder("utf8");
  var utf8decoder = new TextDecoder("utf8");

  function utf8_to_u8(s) {
    return utf8encoder.encode(s);
  }

  function u8_to_utf8(a) {
    return utf8decoder.decode(a);
  }
} else {
  function utf8_to_u8(s) {
    return Uint8Array.from(Buffer(s, "utf8"));
  }

  function u8_to_utf8(a) {
    return Buffer.from(a).toString("utf8");
  }
}

// assemble the struct fragment required to be signed
// e.g. 4:salt6:foobar3:seqi4e1:v12:Hello world!
function make_sig_check(struct) {
  var seq = isNaN(struct.seq) ? 1 : Math.max(Math.floor(struct.seq), 1);
  var header = "4:salt" + utf8_to_u8(struct.salt).length + ":" + struct.salt + "3:seq" + "i" + seq + "e" + "1:v" + struct.v.length;
  var check = new Uint8Array(header.length + struct.v.length);
  check.set(utf8_to_u8(header));
  check.set(struct.v, header.length)
  return check;
}

// bip0044 semantics
//        "k": <ed25519 public key (32 bytes string)>,
//        "salt": <optional salt to be appended to "k" when hashing (string)>
//        "cas": <optional expected seq-nr (int)>,
//        "seq": <monotonically increasing sequence number (integer)>,
//        "sig": <ed25519 signature (64 bytes string)>,
//        "v": <any bencoded type, whose encoded size < 1000>
//
// The signature is a 64 byte ed25519 signature of the bencoded sequence number concatenated with the v key. e.g. something like this:
// 3:seqi4e1:v12:Hello world!
//
// When a salt is included in what is signed, the key salt with the value of the key is prepended in its bencoded form.
// For example, if salt is "foobar", the buffer to be signed is:
// 4:salt6:foobar3:seqi4e1:v12:Hello world!
//
// verify should be a callback function of the form:
// verify(message, signature, publicKey)
// all arguments should be Uint8Arrays of bytes
// [note that supercop has different parameter ordering]
//
function freshest(struct, struct_new, verify) {
  // check sequence number is an int
  if (isNaN(struct_new.seq)) return struct;
  if (Math.round(struct_new.seq) != struct_new.seq) return struct;
  // check sequence number is non-zero
  if (struct_new.seq <= 0) return struct;
  // check sequence number is higher
  if (struct_new.seq < struct.seq) return struct;
  // check cas is previous seq
  if (struct_new["cas"] != undefined && struct_new.cas != struct.seq) return struct;
  // check length is shorter than required
  if (struct_new.v.length > 1000) return struct;
  // check structure is correctly signed
  if (!verify(make_sig_check(struct_new), struct_new.sig, struct_new.k)) return struct;
  // all tests have passed, return the new structure
  return struct_new;
}

module.exports = {
  u8_to_hex: u8_to_hex,
  hex_to_u8: hex_to_u8,
  u8_to_utf8: u8_to_utf8,
  utf8_to_u8: utf8_to_u8,
  make_sig_check: make_sig_check,
  freshest: freshest,
}
