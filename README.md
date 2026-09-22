# browser-memory

Finds the URL(s) of currently-open pages by scanning a *running* browser
engine's process memory — no debugger attach, no pausing the process, no
browser-provided APIs (DevTools protocol, accessibility tree, etc.).

## Status

- **Chromium (Blink): working, self-calibrating.** No hardcoded
  per-build constants — the tool derives the ABI fact it needs at
  runtime, so it isn't tied to one Chromium version. Tested against two
  distinct binaries from the same release (regular `chrome` and
  `headless_shell`, Chromium 141.0.7390.37) — both calibrate
  independently and find the right URLs.
- **Firefox (Gecko): not attempted.** Ubuntu 24.04 ships `firefox` only
  as a snap wrapper, and this sandbox has no snapd; Mozilla's own
  download servers aren't reachable through this environment's network
  policy either (only npm/PyPI/crates/Go-proxy/Anthropic domains are
  allowed). Revisit if a real Firefox binary becomes available.
- **WebKit: in progress.** Available here via WebKitGTK (`epiphany`,
  `MiniBrowser`) — a real native package, not a snap stub.

### On version coverage

This sandbox also can't reach Google's Chrome-for-Testing CDN or any
other source of a *different* Chrome/Chromium version, so "tested
across versions" here means: the self-calibration step was designed
specifically so the tool doesn't need to be tested against every
version to work — it re-derives the one build-specific fact it depends
on (see below) from the live process on every run, instead of assuming
a value baked in at compile time.

## How it works (Chromium)

Chrome represents every URL as a `GURL` object: a `std::string spec_`
(the full URL text) plus a `url::Parsed parsed_` struct recording the
byte offset and length of each component (scheme, username, password,
host, port, path, query, ref) within `spec_`.

1. **Find candidate strings.** Scan all readable memory in the browser
   process for `scheme://...` patterns and extract full URL-shaped
   strings.
2. **Rank by raw occurrence count.** An actively-referenced URL (open
   tab, in-flight request, autocomplete entry, etc.) tends to appear
   more often than an incidental one-off string, so this cheaply
   shortlists the top candidates for the next steps.
3. **Calibrate.** For a handful of the top candidates, find an 8-byte
   pointer to the string's buffer elsewhere in memory, then brute-force
   search nearby offsets for a `url::Parsed`-shaped block: eight
   `(begin, len)` int32 pairs that, applied back to the string, slice
   out its own scheme/host/path/etc. exactly. The offset (pointer →
   struct) that several independent occurrences agree on is a real ABI
   fact about *this specific running build* — derived, not assumed.
4. **Validate.** Every shortlisted candidate is then checked directly
   at the calibrated offset (fast — no more brute force). This is what
   makes a result deterministic rather than a guess: a plain string
   sitting in history, cache, or an IPC buffer will not have this
   structure sitting next to a pointer to it — only a live `GURL` does.
5. **Report.** Strings that validate are printed, ranked by how many
   independent `GURL` objects reference them (a currently-open page is
   typically referenced by several live objects at once — the
   `NavigationEntry`'s committed and virtual URLs, `WebContents`'s
   last-committed-URL cache, etc. — while stale/incidental strings
   validate zero or very few times).

This finds **any currently-open page**, not necessarily the focused tab
— confirmed with multiple tabs open simultaneously, and confirmed to
track navigation and tab-close events (a closed tab's reference count
drops sharply, while an open tab's stays high).

If calibration can't find a consistent offset (e.g. a build whose
`GURL`/`std::string` layout differs enough from what step 3 assumes),
the tool says so explicitly and exits, rather than silently reporting
nothing.

## Performance

A single run reads the whole browser process's mapped memory once
(~250–450 MB for a Chromium instance with a couple of tabs open) and
does two-and-a-bit linear passes over it (candidate extraction,
calibration against a handful of candidates, then the fast validation
pass) — no large hash index of every pointer in memory, no
per-candidate memory rescans in the normal (non-calibration) path.

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

On this container: **under ~2 seconds**, dominated by the calibration
pass; a future run against a build already known to calibrate the same
way could skip straight to the fast path if that's ever worth adding.

(The "skipped" bytes are unreadable/guard regions and Chrome's own
~200MB read-only binary text segment, which can't hold live navigation
state.)

## Usage

```sh
g++ -O2 -o chrome_url_scan src/chrome_url_scan.cpp

# Find the browser process (the one *without* --type=renderer/gpu-process/...)
ps -eo pid,cmd | grep '[c]hrome' | grep -v -- '--type='

sudo ./chrome_url_scan <pid>
```

Must run as root (or the same user as the target, with ptrace/proc
permissions) since it reads `/proc/<pid>/mem` directly.

## Why not just search for the raw string?

Raw occurrence count alone is not reliable: static strings compiled
into the binary (e.g. `http://www.unicode.org/copyright.html`, a fixed
list of `domainreliability` beacon endpoints) can outrank the real open
page. The structural `url::Parsed` check is what gives high confidence
that a match is a real, live `GURL`, not incidental text.
