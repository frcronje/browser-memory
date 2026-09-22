# browser-memory

Finds the URL(s) of currently-open pages by scanning a *running* browser
engine's process memory — no debugger attach, no pausing the process, no
browser-provided APIs (DevTools protocol, accessibility tree, etc.).

## Status

- **Chromium (Blink): working, self-calibrating.** `src/chrome_url_scan.cpp`.
  No hardcoded per-build constants — the tool derives the ABI fact it
  needs at runtime, so it isn't tied to one Chromium version. Tested
  against two distinct binaries from the same release (regular `chrome`
  and `headless_shell`, Chromium 141.0.7390.37) — both calibrate
  independently and find the right URLs.
- **WebKit: working, self-calibrating.** `src/webkit_url_scan.cpp`.
  Tested via WebKitGTK (`epiphany`'s `MiniBrowser`, WebKitGTK 2.50.4) —
  a real native package, not a snap stub. Targets the per-tab
  **WebProcess**, not the UI process (see below for why). Verified
  against two separate WebProcess instances with different URLs
  (including one with a query string).
- **Firefox (Gecko): not attempted.** Ubuntu 24.04 ships `firefox` only
  as a snap wrapper, and this sandbox has no snapd; Mozilla's own
  download servers aren't reachable through this environment's network
  policy either (only npm/PyPI/crates/Go-proxy/Anthropic domains are
  allowed). Revisit if a real Firefox binary becomes available.

### On version coverage

This sandbox also can't reach Google's Chrome-for-Testing CDN or any
other source of a *different* Chrome/Chromium version, so "tested
across versions" here means: the self-calibration step in both tools
was designed specifically so they don't need to be tested against every
version to work — each re-derives the build-specific facts it depends
on from the live process on every run, instead of assuming a value
baked in at compile time.

## How it works (common to both tools)

1. **Find candidate strings.** Scan the target's **writable, private,
   anonymous** regions (heap/stack/allocator arenas) for `scheme://...`
   patterns and extract full URL-shaped strings. A live URL object, its
   string buffer, and the pointers to it all live in this memory, so
   scanning it alone is enough — and it skips executable code and
   file-backed read-only data, which is also where the compiled-in
   "static string" false positives live (see below). If calibration
   fails on that set (an unusual build/allocator), the tool falls back
   to scanning all readable memory.
2. **Rank by raw occurrence count.** An actively-referenced URL (open
   tab, in-flight request, autocomplete entry, etc.) tends to appear
   more often than an incidental one-off string, so this cheaply
   shortlists the top candidates for calibration.
3. **Calibrate against a handful of top candidates**, deriving the
   engine's ABI facts from the live process rather than assuming them
   (details differ per engine — see below).
4. **Validate every shortlisted candidate** directly at the calibrated
   offset(s) — fast, no more brute force. Each candidate is checked
   against *its own* component layout, so URLs with a port, query
   string, or fragment validate just as well as bare `scheme://host/path`
   ones. This is what makes a result deterministic rather than a guess:
   a plain string sitting in history, cache, or an IPC buffer won't have
   the right structure sitting next to a pointer to it — only a live URL
   object does.
5. **Report** strings that validate, ranked by how many independent
   objects reference them.

If calibration can't find a consistent layout, the tool says so
explicitly and exits, rather than silently reporting nothing.

### Chromium: `GURL` / `url::Parsed`

Chrome represents every URL as a `GURL` object: a `std::string spec_`
(the full URL text) plus a `url::Parsed parsed_` struct recording the
byte offset and length of each component (scheme, username, password,
host, port, path, query, ref) within `spec_`.

For a handful of top candidates, find an 8-byte pointer to the
string's buffer elsewhere in memory, then brute-force search nearby
offsets for a `url::Parsed`-shaped block: eight `(begin, len)` int32
pairs that, applied back to the string, slice out its own
scheme/host/path/etc. exactly. The offset (pointer → struct) that
independent occurrences agree on is a real ABI fact about *this
specific running build*.

This finds **any currently-open page**, not necessarily the focused
tab — confirmed with multiple tabs open simultaneously, and confirmed
to track navigation and tab-close events (a closed tab's reference
count drops sharply, while an open tab's stays high).

```
$ ./chrome_url_scan <browser-process-pid>
read 441.7 MB across 660 regions (skipped 206.1 MB)
pass1: 2241 distinct URL-like strings
calibrated: url::Parsed sits at pointer_field_addr + 32 on this build
valid  raw     url
59     76      https://example.org/calib-test-page
11     14      chrome-error://chromewebdata/
...
```

Runtime on this container: **under ~2 seconds** (see Performance).

### WebKit: `WTF::URL` / `StringImpl`

WebKit's process model differs: the UI process (`epiphany`,
`MiniBrowser`) mostly just caches the committed URL as a plain display
string (no component-offset metadata was found near it). The *parsed*
URL lives in the per-tab **WebProcess**, where WebCore actually parses
it — so `webkit_url_scan` targets a WebProcess pid, found via:

```sh
ps -eo pid,cmd | grep WebKitWebProcess
```

A `WTF::URL`'s internal string doesn't point directly at the character
data — it points at a `StringImpl` object that starts a small, constant
number of bytes *before* the characters. Empirically, on the tested
build: a pointer to `(string_addr - 20)` found elsewhere in memory has,
at `pointer_field_addr + 12`, seven consecutive `unsigned` fields:
`userStart, userEnd, passwordEnd, hostEnd, pathAfterLastSlash, pathEnd,
queryEnd` — each an absolute byte offset into the URL string. Both the
`-20` and `+12` constants are **calibrated at runtime** (a 2D
brute-force search over a plausible range, requiring an exact 7-field
match), not hardcoded, the same way Chromium's single offset is.

```
$ ./webkit_url_scan <WebProcess-pid>
read 1000.6 MB across 966 regions (skipped 72792.7 MB)
pass1: 241 distinct URL-like strings
calibrated: string_addr-20 is pointed to, boundary fields at pointer_field_addr+12
valid  raw     url
1      19      https://example.net/webkit-probe-url
```

Runtime on this container: **under ~6 seconds** (WebProcess memory is
larger — ~1 GB — and the calibration search space is 2D instead of 1D).
See Performance for how much of that memory is actually scanned now.

Only one WTF::URL was found per WebProcess in testing (vs. several for
Chromium's GURL), which is architecturally expected: a WebProcess in
this WebKitGTK setup holds one page, not Chromium's whole multi-tab
NavigationController.

**Known gap:** userinfo/port handling in the field-offset parser is
best-effort and was only validated against URLs *without* an explicit
port. If you need that, add a test case with `https://host:1234/...`
and verify `hostEnd` still lands where expected.

## Performance

Two changes cut the work per scan substantially:

- **Scan only writable/private/anonymous memory.** Live URL objects,
  their string buffers, and the pointers to them are all in this memory.
  Everything else — executable pages, file-backed read-only data — can be
  skipped. This is where most of the address space usually is, and it's
  also the source of the compiled-in static-string false positives, so
  the scan gets both faster *and* cleaner. A fallback to all-readable
  memory kicks in only if the narrow set fails to calibrate.
- **One pointer scan instead of two.** Calibration and validation used to
  make separate linear passes over memory. They now share a single pass:
  the pass collects every pointer to a shortlisted string, calibration
  derives the offset from those hits, and validation checks the same hits
  at that offset — no second scan.

A scan is fundamentally bounded by how much writable memory has to be
walked to find a pointer to the URL string, so it's O(memory), not
O(1) — there's no index to jump to without symbols or a debugger. These
changes shrink that constant hard rather than change the class.

Measured against a synthetic target here (a process with real
libstdc++/WTF-shaped URL objects plus ~400–600 MB of decoy memory,
since no real browser is installed in this sandbox): **~3–4 s → ~0.35 s**
for both tools, and the Chromium tool now also reports URLs with ports,
queries, and fragments that the previous fixed-score check dropped.

## Usage

```sh
g++ -O2 -o chrome_url_scan src/chrome_url_scan.cpp
g++ -O2 -o webkit_url_scan src/webkit_url_scan.cpp

# Chromium: the browser process (the one *without* --type=renderer/gpu-process/...)
ps -eo pid,cmd | grep '[c]hrome' | grep -v -- '--type='
sudo ./chrome_url_scan <pid>

# WebKit: a WebProcess (one per open tab/site)
ps -eo pid,cmd | grep WebKitWebProcess
sudo ./webkit_url_scan <pid>
```

Must run as root (or the same user as the target, with ptrace/proc
permissions) since both tools read `/proc/<pid>/mem` directly.

## Why not just search for the raw string?

Raw occurrence count alone is not reliable: static strings compiled
into the binary (e.g. `http://www.unicode.org/copyright.html`, a fixed
list of `domainreliability` beacon endpoints, W3C namespace URIs baked
into WebKit's SVG/XML support) can outrank the real open page. The
structural checks above are what give high confidence that a match is
a real, live URL object, not incidental text.
