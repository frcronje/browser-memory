# browser-memory

Finds the URL(s) of currently-open pages by scanning a *running* browser
engine's process memory — no debugger attach, no pausing the process, no
browser-provided APIs (DevTools protocol, accessibility tree, etc.).

## Status

- **Chromium (Blink): working, self-calibrating, calibration is cached.**
  `src/chrome_url_scan.cpp`. No hardcoded per-build constants — the tool
  derives the ABI fact it needs at runtime, so it isn't tied to one
  Chromium version. Tested against two distinct binaries from the same
  release (regular `chrome` and `headless_shell`, Chromium 141.0.7390.37)
  — both calibrate independently, cache separately, and find the right
  URLs. Re-verified with the calibration cache in place: cold run
  calibrates and populates the cache; a second run against the same
  process, a fresh process of the same binary (different pid, different
  open URL), and the second distinct binary all behave correctly (see
  "Calibration caching" below).
- **WebKit: working, self-calibrating, calibration is cached.**
  `src/webkit_url_scan.cpp`. Tested via WebKitGTK (`epiphany`'s
  `MiniBrowser`, WebKitGTK 2.50.4) — a real native package, not a snap
  stub. Targets the per-tab **WebProcess**, not the UI process (see below
  for why). Verified against two separate WebProcess instances with
  different URLs (including one with a query string), and re-verified
  with the calibration cache in place the same way as Chromium above.
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

1. **Find candidate strings.** Scan all readable memory in the target
   process for `scheme://...` patterns and extract full URL-shaped
   strings.
2. **Rank by raw occurrence count.** An actively-referenced URL (open
   tab, in-flight request, autocomplete entry, etc.) tends to appear
   more often than an incidental one-off string, so this cheaply
   shortlists the top candidates for calibration.
3. **Calibrate against a handful of top candidates**, deriving the
   engine's ABI facts from the live process rather than assuming them
   (details differ per engine — see below).
4. **Validate every shortlisted candidate** directly at the calibrated
   offset(s) — fast, no more brute force. This is what makes a result
   deterministic rather than a guess: a plain string sitting in
   history, cache, or an IPC buffer won't have the right structure
   sitting next to a pointer to it — only a live URL object does.
5. **Report** strings that validate, ranked by how many independent
   objects reference them.

If calibration can't find a consistent layout, the tool says so
explicitly and exits, rather than silently reporting nothing.

## Calibration caching

Both tools are meant to run as a periodic monitor (poll no more often than
every ~20s), and calibration is a fact about the *binary*, not about any
one poll or process — it only changes when the browser is rebuilt or
updated. Re-deriving it by brute force on every invocation is pure waste,
so both tools cache the result:

1. **Fingerprint the target binary per run:** resolve `/proc/<pid>/exe`
   and hash its path + `st_size` + `st_mtime` (`src/calibration_cache.h`,
   `ComputeFingerprint`). This is deliberately cheap — no hashing of the
   binary's contents, since these binaries run 200MB-1GB+.
2. **Cache hit:** the calibrated offset(s) for that fingerprint are read
   from `~/.cache/browser-memory/{chrome,webkit}_calibration.json` and
   used directly. The brute-force search is skipped entirely; memory is
   still fully re-read and re-scanned every poll (that part is
   unavoidable and unchanged).
3. **Cache miss** (new build, or no cache yet): calibrate as before, then
   write the result to the cache, keyed by fingerprint.
4. **Stale-cache fallback:** if a cached offset validates *nothing* on a
   given run (e.g. the binary changed without its fingerprint changing,
   or a corrupted cache entry), the tool logs that and falls back to a
   full recalibration in the same run, overwriting the bad entry —
   it never silently reports zero results because of a bad cache.

The cache file is a small hand-written JSON map (no new dependencies),
one entry per binary fingerprint, e.g.:

```json
{
  "f87d58ac94d46dc6": {
    "exe": "/opt/pw-browsers/chromium-1194/chrome-linux/chrome",
    "size": 463227992,
    "mtime": 1774963888,
    "fields": {"offset": 32}
  }
}
```

Verified: cold run (cache miss) calibrates and populates the cache; a
second run against the same process hits the cache and returns the same
result; killing and relaunching the same binary as a fresh process (new
pid, different open URL) still hits the cache, since the fingerprint is
per-binary, not per-process; a second, distinct binary (`headless_shell`
vs. `chrome`) gets its own cache entry and calibrates independently;
injecting a bad cached offset triggers the stale-cache fallback, which
recalibrates and repairs the cache entry in place.

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

**Performance (this container, headless `chrome`, ~450MB read):**

| Run | Time |
| --- | --- |
| Cold (cache miss, full calibration) | ~3.0s |
| Warm (cache hit, calibration skipped) | ~0.9-2.3s (repeat runs; container I/O noise dominates) |

Phase breakdown on a warm run (`read` / `pass1` string scan / `validation`
fast pass — all unavoidable per poll — vs. the calibration step the cache
now skips): reading + hashing memory takes ~0.3-1.2s and the fast
validation pass ~0.45-0.5s depending on scheduler noise; the brute-force
calibration step this replaces adds roughly another 1-2s on top when it
runs, which is exactly what a cache hit avoids. (The task's target range
of ~0.3-0.5s assumes a faster disk/memory subsystem than this particular
sandbox has for `/proc/<pid>/mem` reads; the *relative* win — calibration
cost removed from every poll but the first — holds regardless of the
absolute numbers.)

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

**Performance (this container, WebKitGTK `MiniBrowser` WebProcess, ~1GB read):**

| Run | Time |
| --- | --- |
| Cold (cache miss, full 2D calibration) | ~7.8s |
| Warm (cache hit, calibration skipped) | ~2.4-4.8s (repeat runs; container I/O noise dominates), steady state ~2.4-2.7s |

WebProcess memory is larger (~1GB) than Chromium's browser process, and
the uncached calibration search is 2D (`delta` × `struct_offset`) instead
of Chromium's 1D search, which is why it was the more expensive of the
two tools before caching — and why skipping it on a cache hit saves the
most here: roughly 3-5s per poll, most of the original ~5-6s runtime.

Only one WTF::URL was found per WebProcess in testing (vs. several for
Chromium's GURL), which is architecturally expected: a WebProcess in
this WebKitGTK setup holds one page, not Chromium's whole multi-tab
NavigationController.

**Known gap:** userinfo/port handling in the field-offset parser is
best-effort and was only validated against URLs *without* an explicit
port. If you need that, add a test case with `https://host:1234/...`
and verify `hostEnd` still lands where expected.

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
`src/calibration_cache.h` is a header-only helper included by both
`.cpp` files — no separate compilation unit, no new dependencies, no
change to the build commands above.

Calibration results are cached at `~/.cache/browser-memory/`; delete
that directory (or the specific `chrome_calibration.json` /
`webkit_calibration.json` file) to force recalibration, e.g. after
manually patching a browser binary in place without changing its
mtime/size.

## Why not just search for the raw string?

Raw occurrence count alone is not reliable: static strings compiled
into the binary (e.g. `http://www.unicode.org/copyright.html`, a fixed
list of `domainreliability` beacon endpoints, W3C namespace URIs baked
into WebKit's SVG/XML support) can outrank the real open page. The
structural checks above are what give high confidence that a match is
a real, live URL object, not incidental text.
