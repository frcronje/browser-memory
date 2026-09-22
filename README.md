# browser-memory

Finds the URL(s) of currently-open pages by scanning a *running* browser
engine's process memory — no debugger attach, no pausing the process, no
browser-provided APIs (DevTools protocol, accessibility tree, etc.).

## Status

- **Chromium (Blink): working, self-calibrating.** `src/chrome_url_scan.cpp`.
  No hardcoded per-build constants — the tool derives the ABI fact it
  needs at runtime, so it isn't tied to one Chromium version.
- **WebKit: working, self-calibrating.** `src/webkit_url_scan.cpp`.
  Targets the per-tab **WebProcess**, not the UI process (see below for why).
  Supports both modern inline and legacy indirect `StringImpl` layouts.
- **Firefox (Gecko): working, self-calibrating.** `src/firefox_url_scan.cpp`.
  Targets a Firefox **content process**, where the live document URI resides.
  It derives the `nsStandardURL` table offset, field count, and stride from
  the running process, including legacy, release, and early-beta layouts.

### On version coverage

The scanners have been exercised at both ends of the oldest-to-current range
available on this modern x86_64 Debian 12 host, always with a URL containing
an explicit port, path, query, and fragment:

| Engine | Oldest tested here | Current tested here |
| --- | --- | --- |
| Chromium | 15.0.875.0, official Linux snapshot r100002 (2011) | Chrome 153.0.8010.52 |
| WebKitGTK | 2.6.2, oldest archived Debian `libwebkit2gtk-4.0-37` package (2014) | 2.50.6 |
| Firefox | 4.0.1, first official Linux x86_64 Firefox release (2011) | 153.3.0esr |

The old builds run natively on the current kernel and glibc, with their
missing legacy shared libraries loaded side-by-side. These are the oldest
available 64-bit artifacts of the relevant form that could be launched here,
not a claim about every build ever produced. Chromium 141 and WebKitGTK 2.50.4
were also tested during the original implementation.

## How it works (common to all three tools)

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
4. **Validate every retained candidate** directly at the calibrated
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

A modern `WTF::URL`'s internal string points at an inline `StringImpl` header
that starts a small, constant number of bytes before the characters. On the
tested current build, a pointer to `(string_addr - 20)` found elsewhere has,
at `pointer_field_addr + 12`, seven consecutive `unsigned` fields:
`userStart, userEnd, passwordEnd, hostEnd, pathAfterLastSlash, pathEnd,
queryEnd` — each an absolute byte offset into the URL string. Both the
`-20` and `+12` constants are **calibrated at runtime** (a 2D
brute-force search over a plausible range, requiring an exact 7-field
match), not hardcoded, the same way Chromium's single offset is.

Older WebKit uses an indirect string representation instead: `StringImpl`
contains a separate pointer to its character buffer, and `URL` has ten
boundary fields including explicit scheme, port, and fragment ends. The
scanner detects that two-hop pointer chain, calibrates the boundary offset,
and validates all ten fields. WebKitGTK 2.6.2 calibrates this legacy path at
`string_pointer_field_addr + 12`; WebKitGTK 2.50.6 calibrates the modern path
at `pointer_field_addr + 12`.

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

### Firefox: `nsStandardURL` / `URLSegment`

Firefox keeps the authoritative URI for a live document in the content
process hosting that document. `nsStandardURL` stores a normalized UTF-8
`nsCString`, followed by twelve parsed component ranges (scheme, authority,
username, password, host, path, filepath, directory, basename, extension,
query, and fragment). Each range is a byte position and length in the same
string. Firefox 4 uses thirteen ranges because it has an additional legacy
path-parameter component before query and fragment.

For top URL candidates, `firefox_url_scan` finds pointers to their buffers
and searches nearby for either complete table. It calibrates the table's
offset, count, and stride: release builds use 8-byte ranges, while early-beta
builds use 16-byte parity-checked ranges. Requiring every range to reproduce
the candidate's own components distinguishes a live parsed URI from history,
IPC, or cache strings.

Firefox may distribute tabs and cross-origin frames among several content
processes. Scan each `-contentproc` PID to enumerate all open pages. As with
the other engines, valid URL objects can also belong to subresources,
history, or an iframe; the `valid` count is useful for ranking but does not
prove that a URL is the focused top-level tab.

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

The original optimization was measured against a synthetic target with
libstdc++/WTF-shaped URL objects plus ~400–600 MB of decoy memory:
**~3–4 s → ~0.35 s** for the Chromium and modern-WebKit paths. The Chromium
tool also reports URLs with ports,
queries, and fragments that the previous fixed-score check dropped.

## Usage

```sh
g++ -std=c++17 -O2 -o browser_engine_discovery src/browser_engine_discovery.cpp
g++ -O2 -o chrome_url_scan src/chrome_url_scan.cpp
g++ -O2 -o webkit_url_scan src/webkit_url_scan.cpp
g++ -std=c++17 -O2 -o firefox_url_scan src/firefox_url_scan.cpp

# Inspect every process visible through this /proc mount. Output is JSON.
sudo ./browser_engine_discovery

# Reconcile periodically, retaining first/last observation times and the
# artifact cache. The default interval is five seconds.
sudo ./browser_engine_discovery --watch

# Chromium: the browser process (the one *without* --type=renderer/gpu-process/...)
ps -eo pid,cmd | grep '[c]hrome' | grep -v -- '--type='
sudo ./chrome_url_scan <pid>

# WebKit: a WebProcess (one per open tab/site)
ps -eo pid,cmd | grep WebKitWebProcess
sudo ./webkit_url_scan <pid>

# Firefox: scan each content process (tabs/frames may be split across them)
ps -eo pid,cmd | grep '[f]irefox.*-contentproc'
sudo ./firefox_url_scan <content-process-pid>
```

Must run as root (or the same user as the target, with ptrace/proc
permissions) since all three tools read `/proc/<pid>/mem` directly.

## Linux engine discovery

`src/browser_engine_discovery.cpp` is a separate process-discovery layer; it
does not change or invoke the URL scanners. It reads `/proc` directly and:

- enumerates every visible PID without filtering on process or application
  name, recording PID, start time, parent, executable, and command line;
- inspects the main executable and every file-backed executable mapping,
  including modules loaded later with `dlopen`;
- opens `map_files` handles where possible, falling back to paths under the
  target's root only when device and inode still exactly match `/proc/PID/maps`;
- caches recognition by device, inode, size, modification time, and status
  change time, while revisiting process metadata and mappings on every watch pass;
- recognizes Blink/Chromium, Gecko, and WebKit evidence independently, so one
  PID can report more than one family; and
- infers process roles separately and reports direct parent/engine-child
  relationships as association evidence, not as proof that the parent loaded
  engine code.

Output distinguishes `probable` findings (at least two independent
engine-specific binary features), `candidate` findings (such as an artifact
name lead), and `associated-only` processes. The built-in rules intentionally
do not emit `identified`: that status requires an external, validated artifact
digest registry, which this initial implementation does not ship. V8 alone,
JavaScriptCore alone, user-agent text, and generic engine names are not binary
proof.

Each JSON sweep includes inspection totals, unknown process and unrecognized
artifact counts, bytes read, access/race gaps, truncated-gap indication, and
whether an analysis budget was exhausted. Artifact analysis defaults to 128
MiB per unfamiliar file and 1 GiB per cold sweep; tune these with
`--artifact-budget-mib` and `--sweep-budget-mib`. An incomplete analysis is
reported as such and is never presented as proof that no engine exists.

Discovery is best-effort, not a universal engine oracle. Stripped or modified
builds, static binaries without known features, anonymous executable mappings,
permissions, mount/PID namespaces, and processes that live entirely between
polls can all create recognition or inspection gaps. A complete sweep only
describes processes visible in the current `/proc` scope; a container cannot
establish host-wide absence.

Run the discovery integration test with:

```sh
tests/discovery_test.sh
```

## Why not just search for the raw string?

Raw occurrence count alone is not reliable: static strings compiled
into the binary (e.g. `http://www.unicode.org/copyright.html`, a fixed
list of `domainreliability` beacon endpoints, W3C namespace URIs baked
into WebKit's SVG/XML support) can outrank the real open page. The
structural checks above are what give high confidence that a match is
a real, live URL object, not incidental text.
