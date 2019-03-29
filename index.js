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

// assemble a valid BEP0044 struct with correctly clamped values and defaults
function make_struct(struct) {
  var struct_new = {};
  var struct = struct || {};
  var val = struct.v || "";
  if (val instanceof Uint8Array) {
    struct_new.v = val;
  } else if (typeof(val) == "string"){
    struct_new.v = utf8_to_u8(val.toString());
  } else if (val.length) {
    struct_new.v = Uint8Array.from(val);
  } else {
    throw("struct.v must be a string or byte-array in make_struct()");
  }
  struct_new.seq = isNaN(struct.seq) ? 1 : Math.max(Math.floor(struct.seq), 1);
  if (struct.salt) struct_new.salt = struct.salt.substr(0, 64);
  if (struct.cas && !isNaN(struct.cas)) struct_new.cas = struct.cas;
  if (struct.k) struct_new.k = struct.k;
  if (struct.sig) struct_new.sig = struct.sig;
  return struct_new;
}

// assemble the struct fragment required to be signed
// e.g. 4:salt6:foobar3:seqi4e1:v12:Hello world!
function make_sig_check(struct) {
  var struct = make_struct(struct);
  var header = (struct.salt ? ("4:salt" + utf8_to_u8(struct.salt).length + ":" + struct.salt) : "") + "3:seq" + "i" + struct.seq + "e" + "1:v" + struct.v.length + ":";
  var header_length = utf8_to_u8(header).length;
  var check = new Uint8Array(header_length + struct.v.length);
  check.set(utf8_to_u8(header));
  check.set(struct.v, header_length)
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
  var struct = make_struct(struct);
  var struct_new = make_struct(struct_new);
  // check sequence number is an int
  if (isNaN(struct_new.seq)) return struct;
  if (Math.round(struct_new.seq) != struct_new.seq) return struct;
  // check sequence number is non-zero
  if (struct_new.seq <= 0) return struct;
  // check sequence number is higher
  if (struct_new.seq < (struct ? struct.seq : 1)) return struct;
  // check cas is previous seq
  if (struct_new["cas"] != undefined && struct_new.cas != (struct ? struct.seq : 1)) return struct;
  // check length is shorter than required
  if (struct_new.v.length > 1000) return struct;
  // check salt length is shorter than 64
  if (struct_new.salt > 64) return struct;
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
  make_struct: make_struct,
  freshest: freshest,
}
