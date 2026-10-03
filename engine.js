(function (root) {
  // Hidden-character scanner. Bidi list: the nine codepoints the Rust advisory for CVE-2021-42574 says to search for.
  var BIDI = { 0x202A: 'LEFT-TO-RIGHT EMBEDDING', 0x202B: 'RIGHT-TO-LEFT EMBEDDING', 0x202C: 'POP DIRECTIONAL FORMATTING', 0x202D: 'LEFT-TO-RIGHT OVERRIDE', 0x202E: 'RIGHT-TO-LEFT OVERRIDE', 0x2066: 'LEFT-TO-RIGHT ISOLATE', 0x2067: 'RIGHT-TO-LEFT ISOLATE', 0x2068: 'FIRST STRONG ISOLATE', 0x2069: 'POP DIRECTIONAL ISOLATE' };
  var BIDI_MARK = { 0x200E: 'LEFT-TO-RIGHT MARK', 0x200F: 'RIGHT-TO-LEFT MARK', 0x061C: 'ARABIC LETTER MARK' };
  var INVIS = { 0x00AD: 'SOFT HYPHEN', 0x200B: 'ZERO WIDTH SPACE', 0x200C: 'ZERO WIDTH NON-JOINER', 0x200D: 'ZERO WIDTH JOINER', 0x2060: 'WORD JOINER', 0xFEFF: 'ZERO WIDTH NO-BREAK SPACE (BOM)', 0x180E: 'MONGOLIAN VOWEL SEPARATOR', 0x2061: 'FUNCTION APPLICATION', 0x2062: 'INVISIBLE TIMES', 0x2063: 'INVISIBLE SEPARATOR', 0x2064: 'INVISIBLE PLUS', 0x3164: 'HANGUL FILLER' };
  var SPACES = { 0x00A0: 'NO-BREAK SPACE', 0x1680: 'OGHAM SPACE MARK', 0x2000: 'EN QUAD', 0x2001: 'EM QUAD', 0x2002: 'EN SPACE', 0x2003: 'EM SPACE', 0x2004: 'THREE-PER-EM SPACE', 0x2005: 'FOUR-PER-EM SPACE', 0x2006: 'SIX-PER-EM SPACE', 0x2007: 'FIGURE SPACE', 0x2008: 'PUNCTUATION SPACE', 0x2009: 'THIN SPACE', 0x200A: 'HAIR SPACE', 0x202F: 'NARROW NO-BREAK SPACE', 0x205F: 'MEDIUM MATHEMATICAL SPACE', 0x3000: 'IDEOGRAPHIC SPACE' };
  // letters that look like Latin ones (small hand-picked list, not the full UTS #39 table)
  var LOOK = { 0x0430: 'a', 0x0435: 'e', 0x043E: 'o', 0x0440: 'p', 0x0441: 'c', 0x0445: 'x', 0x0443: 'y', 0x0456: 'i', 0x0455: 's', 0x0458: 'j', 0x0410: 'A', 0x0415: 'E', 0x041E: 'O', 0x0420: 'P', 0x0421: 'C', 0x0425: 'X', 0x0412: 'B', 0x041C: 'M', 0x041D: 'H', 0x0422: 'T', 0x039F: 'O', 0x03BF: 'o', 0x03BD: 'v', 0x0391: 'A', 0x0392: 'B', 0x0395: 'E', 0x0399: 'I', 0x039A: 'K', 0x039C: 'M', 0x039D: 'N', 0x03A1: 'P', 0x03A4: 'T', 0x03A7: 'X' };
  var SCRIPTS = ['Latin', 'Cyrillic', 'Greek', 'Arabic', 'Hebrew', 'Han', 'Hiragana', 'Katakana', 'Hangul', 'Devanagari', 'Thai'];
  var scriptRe = SCRIPTS.map(function (s) { return [s, new RegExp('^\\p{Script=' + s + '}$', 'u')]; });
  function hex(n) { var h = n.toString(16).toUpperCase(); while (h.length < 4) h = '0' + h; return 'U+' + h; }
  function utf8(cp) {
    if (cp < 0x80) return [cp];
    if (cp < 0x800) return [0xC0 | (cp >> 6), 0x80 | (cp & 63)];
    if (cp < 0x10000) return [0xE0 | (cp >> 12), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63)];
    return [0xF0 | (cp >> 18), 0x80 | ((cp >> 12) & 63), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63)];
  }
  function script(ch) { for (var i = 0; i < scriptRe.length; i++) if (scriptRe[i][1].test(ch)) return scriptRe[i][0]; return null; }
  function category(ch) {
    var cats = ['Lu', 'Ll', 'Lt', 'Lm', 'Lo', 'Mn', 'Mc', 'Me', 'Nd', 'Nl', 'No', 'Pc', 'Pd', 'Ps', 'Pe', 'Pi', 'Pf', 'Po', 'Sm', 'Sc', 'Sk', 'So', 'Zs', 'Zl', 'Zp', 'Cc', 'Cf', 'Cs', 'Co', 'Cn'];
    for (var i = 0; i < cats.length; i++) if (new RegExp('^\\p{' + cats[i] + '}$', 'u').test(ch)) return cats[i];
    return '??';
  }
  // flag kinds: bidi, invisible, space, control, private, unassigned, lone-surrogate, lookalike
  function charFlags(cp, ch) {
    var f = [];
    if (BIDI[cp]) f.push({ kind: 'bidi', name: BIDI[cp] });
    else if (BIDI_MARK[cp]) f.push({ kind: 'bidi-mark', name: BIDI_MARK[cp] });
    if (INVIS[cp]) f.push({ kind: 'invisible', name: INVIS[cp] });
    if (SPACES[cp]) f.push({ kind: 'space', name: SPACES[cp] });
    if (cp >= 0xD800 && cp <= 0xDFFF) f.push({ kind: 'lone-surrogate', name: 'UNPAIRED SURROGATE' });
    else {
      if ((cp < 32 || (cp >= 0x7F && cp < 0xA0)) && cp !== 9 && cp !== 10 && cp !== 13) f.push({ kind: 'control', name: 'CONTROL CHARACTER' });
      if (/^\p{Co}$/u.test(ch)) f.push({ kind: 'private', name: 'PRIVATE USE' });
      if (/^\p{Cn}$/u.test(ch)) f.push({ kind: 'unassigned', name: 'UNASSIGNED' });
    }
    return f;
  }
  function inspect(text) {
    var out = [], i = 0, idx = 0;
    while (i < text.length) {
      var cp = text.codePointAt(i), ch = String.fromCodePoint(cp), u = ch.length;
      var b = utf8(cp >= 0xD800 && cp <= 0xDFFF ? 0xFFFD : cp);
      out.push({ index: idx++, ch: ch, cp: cp, hex: hex(cp), units: u, bytes: b, category: cp >= 0xD800 && cp <= 0xDFFF ? 'Cs' : category(ch), script: script(ch), flags: charFlags(cp, ch), look: LOOK[cp] || null });
      i += u;
    }
    return out;
  }
  function words(items) {
    var res = [], cur = [];
    items.forEach(function (it) { if (/^[\p{L}\p{N}\p{M}_]$/u.test(it.ch)) cur.push(it); else { if (cur.length) res.push(cur); cur = []; } });
    if (cur.length) res.push(cur);
    return res;
  }
  function mixedWords(items) {
    var out = [];
    words(items).forEach(function (w) {
      var sc = {}; w.forEach(function (it) { if (it.script) sc[it.script] = 1; });
      var names = Object.keys(sc);
      if (names.length > 1 && sc.Latin) out.push({ word: w.map(function (x) { return x.ch; }).join(''), scripts: names, at: w[0].index, odd: w.filter(function (x) { return x.script && x.script !== 'Latin'; }).map(function (x) { return x.hex; }) });
      else if (names.length > 1) out.push({ word: w.map(function (x) { return x.ch; }).join(''), scripts: names, at: w[0].index, odd: [] });
    });
    return out;
  }
  function graphemes(text) {
    if (typeof Intl !== 'undefined' && Intl.Segmenter) return Array.from(new Intl.Segmenter('en', { granularity: 'grapheme' }).segment(text)).length;
    return null;
  }
  function analyze(text) {
    var items = inspect(text), bytes = 0, bad = {};
    items.forEach(function (it) { bytes += it.bytes.length; it.flags.forEach(function (f) { bad[f.kind] = (bad[f.kind] || 0) + 1; }); });
    var mixed = mixedWords(items);
    var nfc = text.normalize('NFC'), nfd = text.normalize('NFD');
    var risky = (bad.bidi || 0) + (bad.invisible || 0) + (bad.control || 0) + (bad['lone-surrogate'] || 0) + mixed.filter(function (m) { return m.odd.length; }).length;
    return { codePoints: items.length, utf16Units: text.length, utf8Bytes: bytes, graphemes: graphemes(text), items: items, counts: bad, mixed: mixed,
      nfc: { text: nfc, same: nfc === text }, nfdLength: Array.from(nfd).length, nfcLength: Array.from(nfc).length,
      verdict: !text.length ? 'empty' : risky ? 'suspicious' : (bad.space || bad['bidi-mark'] || bad.private || bad.unassigned || !(nfc === text)) ? 'check' : 'clean' };
  }
  // clean: drops bidi controls, control characters, lone surrogates and invisibles; keeps ZWJ/ZWNJ (emoji sequences, Persian) unless o.all; turns odd spaces into a plain space
  function clean(text, o) {
    o = o || {}; var s = '';
    inspect(text).forEach(function (it) {
      var kinds = it.flags.map(function (f) { return f.kind; });
      var drop = kinds.indexOf('bidi') >= 0 || kinds.indexOf('control') >= 0 || kinds.indexOf('lone-surrogate') >= 0 || (kinds.indexOf('invisible') >= 0 && (o.all || (it.cp !== 0x200D && it.cp !== 0x200C)));
      if (drop) return;
      if (kinds.indexOf('space') >= 0) { s += ' '; return; }
      s += it.ch;
    });
    return o.nfc === false ? s : s.normalize('NFC');
  }
  var api = { inspect: inspect, analyze: analyze, clean: clean, mixedWords: mixedWords, BIDI: BIDI, INVIS: INVIS, SPACES: SPACES, hex: hex };
  if (typeof module !== 'undefined' && module.exports) module.exports = api; else root.UtfLens = api;
})(typeof window !== 'undefined' ? window : this);
