var U = require('./engine.js'); var fails = 0, n = 0;
function eq(a, b, m) { n++; if (JSON.stringify(a) !== JSON.stringify(b)) { fails++; console.log('FAIL', m, JSON.stringify(a), JSON.stringify(b)); } }
// Oracle: Node's own UTF-8 encoder and string iterator
var pool = ['a', 'Z', ' ', '\n', '\u00e9', 'e\u0301', '\u00df', '\u20ac', '\u4f60', '\u05d0', '\u0630', '\ud83d\ude00', '\u{1F468}\u200D\u{1F469}\u200D\u{1F467}', '\u{10FFFF}', '\u200b', '\u202e', '\u00a0', '\u0430', '\ufeff', '\u{1F1EE}\u{1F1F1}', '\ud800', '\udc00', '\u0000', '\u{E000}'], seed = 11, i, k;
function rnd(m) { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed % m; }
for (i = 0; i < 400; i++) {
  var s = ''; for (k = rnd(14); k > 0; k--) s += pool[rnd(pool.length)];
  var a = U.analyze(s), iter = Array.from(s);
  eq(a.codePoints, iter.length, 'cp count ' + i); eq(a.utf16Units, s.length, 'utf16 ' + i);
  // lone surrogates encode as U+FFFD (3 bytes) exactly like TextEncoder
  eq(a.utf8Bytes, new TextEncoder().encode(s).length, 'utf8 length ' + i);
  var flat = []; a.items.forEach(function (it) { flat = flat.concat(it.bytes); });
  eq(flat, Array.from(new TextEncoder().encode(s)), 'utf8 bytes ' + i);
  eq(a.items.map(function (it) { return it.ch; }).join(''), s, 'roundtrip ' + i);
  eq(a.graphemes, Array.from(new Intl.Segmenter('en', { granularity: 'grapheme' }).segment(s)).length, 'graphemes ' + i);
  eq(a.nfc.text, s.normalize('NFC'), 'nfc ' + i);
  var c = U.clean(s); eq(U.analyze(c).counts.bidi, undefined, 'clean has no bidi ' + i); eq(U.analyze(c).counts.control, undefined, 'clean has no control ' + i); eq(U.clean(c), c, 'clean idempotent ' + i);
}
// worked cases
eq(U.analyze('caf\u00e9').utf8Bytes, 5, 'cafe 5 bytes'); eq(U.analyze('\u20ac').items[0].bytes, [0xE2, 0x82, 0xAC], 'euro E2 82 AC'); eq(U.analyze('\u{1F600}').items[0].bytes, [0xF0, 0x9F, 0x98, 0x80], 'grinning face F0 9F 98 80');
eq(U.analyze('\u{1F600}').utf16Units, 2, 'astral = 2 units'); eq(U.analyze('e\u0301').graphemes, 1, 'e + combining = 1 grapheme'); eq(U.analyze('e\u0301').nfc.same, false, 'decomposed e is not NFC'); eq(U.analyze('e\u0301').nfcLength, 1, 'NFC length 1');
eq(U.analyze('\u{1F468}\u200D\u{1F469}\u200D\u{1F467}').graphemes, 1, 'family emoji = 1 grapheme'); eq(U.analyze('\u{1F468}\u200D\u{1F469}\u200D\u{1F467}').codePoints, 5, 'family emoji = 5 code points');
// the nine codepoints named in the Rust advisory for CVE-2021-42574
[0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069].forEach(function (cp) { var r = U.analyze('x' + String.fromCodePoint(cp) + 'y'); eq(r.counts.bidi, 1, 'bidi ' + cp.toString(16)); eq(r.verdict, 'suspicious', 'bidi suspicious ' + cp.toString(16)); });
eq(Object.keys(U.BIDI).length, 9, 'nine bidi codepoints');
// the advisory's example line
var ex = 'if access_level != "user\u202E \u2066// Check if admin\u2069 \u2066"'; eq(U.analyze(ex).counts.bidi, 4, 'advisory example has 4 bidi controls'); eq(U.clean(ex), 'if access_level != "user // Check if admin "', 'advisory example cleaned');
// invisibles, spaces
eq(U.analyze('a\u200Bb').counts.invisible, 1, 'zwsp'); eq(U.analyze('a\u200Bb').verdict, 'suspicious', 'zwsp suspicious'); eq(U.clean('a\u200Bb'), 'ab', 'zwsp removed'); eq(U.clean('\ufeffabc'), 'abc', 'bom removed');
eq(U.analyze('\u{1F468}\u200D\u{1F469}').verdict, 'check', 'emoji joiner is only worth a look'); eq(U.analyze('a\u200Cb').verdict, 'check', 'zwnj is worth a look'); eq(U.analyze('a\u200C\u200Bb').verdict, 'suspicious', 'zwsp next to zwnj still suspicious');
eq(U.clean('a\u200Db'), 'a\u200Db', 'zwj kept by default'); eq(U.clean('a\u200Db', { all: true }), 'ab', 'zwj removed with all');
eq(U.analyze('a\u00a0b').counts.space, 1, 'nbsp'); eq(U.analyze('a\u00a0b').verdict, 'check', 'nbsp is check'); eq(U.clean('a\u00a0b\u3000c'), 'a b c', 'spaces normalized');
eq(U.analyze('plain ascii text.').verdict, 'clean', 'clean text'); eq(U.analyze('').verdict, 'empty', 'empty'); eq(U.analyze('a\u0000b').counts.control, 1, 'NUL is control'); eq(U.analyze('a\tb\n').counts.control, undefined, 'tab and newline are fine');
eq(U.analyze('\ud800').counts['lone-surrogate'], 1, 'lone surrogate'); eq(U.analyze('\ud800').items[0].bytes, [0xEF, 0xBF, 0xBD], 'lone surrogate encodes as FFFD'); eq(U.analyze('\ue000').counts.private, 1, 'private use');
// lookalikes
var m = U.analyze('p\u0430ypal'); eq(m.mixed.length, 1, 'mixed script word'); eq(m.mixed[0].odd, ['U+0430'], 'cyrillic a'); eq(m.verdict, 'suspicious', 'homoglyph suspicious'); eq(U.analyze('\u043f\u0440\u0438\u0432\u0435\u0442 hello').mixed.length, 0, 'separate words in two scripts are fine');
eq(U.analyze('caf\u00e9').mixed.length, 0, 'accented latin is one script'); eq(U.analyze('\u65e5\u672c\u8a9e\u3072\u3089\u304c\u306a').mixed.length, 1, 'han + hiragana word listed'); eq(U.analyze('\u65e5\u672c\u8a9e\u3072\u3089\u304c\u306a').verdict, 'clean', 'Japanese mix is not flagged risky');
eq(U.inspect('A')[0].category, 'Lu', 'category Lu'); eq(U.inspect('\u0430')[0].script, 'Cyrillic', 'script'); eq(U.inspect('a')[0].hex, 'U+0061', 'hex'); eq(U.inspect('\u{1F600}')[0].hex, 'U+1F600', 'hex astral');
console.log(n + ' checks, ' + fails + ' failures'); process.exit(fails ? 1 : 0);
