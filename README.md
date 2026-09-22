# browser-memory

Finds the URL(s) of currently-open pages by scanning a *running* browser
engine's process memory — no debugger attach, no pausing the process, no
browser-provided APIs (DevTools protocol, accessibility tree, etc.).

## Status

- **Chromium: working.** Validated against Chromium 141.0.7390.37
  (x86-64 Linux, the version bundled with Playwright in this environment).
- Other engines (Firefox/Gecko, WebKit) not yet attempted — per the task,
  only move on to them once Chromium is solid.

## How it works

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
   shortlists the top candidates for the next, more expensive step.
3. **Validate structurally.** For each shortlisted string, search memory
   for an 8-byte pointer to that string's buffer. In this build, a real
   `GURL` object always has its `url::Parsed` struct starting exactly
   **32 bytes after** that pointer's own address. Decoding those 8
   `(begin, len)` int32 pairs and slicing the candidate string at those
   offsets must reproduce its own scheme/host/path/etc. exactly. This
   is what makes the result deterministic rather than a guess: a plain
   string sitting in history, cache, or an IPC buffer will not have this
   structure sitting next to a pointer to it — only a live `GURL` does.
4. **Report.** Strings that validate are printed, ranked by how many
   independent `GURL` objects reference them (a currently-open page is
   typically referenced by several live objects at once — the
   `NavigationEntry`'s committed and virtual URLs, `WebContents`'s last-
   committed-URL cache, etc. — while stale/incidental strings validate
   zero or very few times).

This finds **any currently-open page**, not necessarily the focused tab
— confirmed with multiple tabs open simultaneously, and confirmed to
track navigation and tab-close events (a closed tab's reference count
drops sharply, while an open tab's stays high).

## Performance

A single run reads the whole browser process's mapped memory once
(~400–600 MB in a Chromium instance with a couple of tabs open) and does
two linear passes over it — no per-candidate memory rescans, no large
hash index of every pointer in memory. On this container: **under 1
second, ~budget-sized peak RSS matching the bytes actually read.**

```
$ ./chrome_url_scan <browser-process-pid>
read 421.1 MB across 654 regions (skipped 206.1 MB)
pass1: 2243 distinct URL-like strings
valid  raw     url
59     77      https://www.wikipedia.org/wiki/Memory_forensics
19     19      https://example.com/memtest-page1   <- tab was just closed
11     14      chrome-error://chromewebdata/
...
```

(The "skipped" bytes are unreadable/guard regions and the ~200MB
read-only Chrome binary text segment, which can't hold live navigation
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

## Important limitation: this offset is build-specific

`ptr + 32 == &parsed_` depends on the exact `std::string`/`GURL` object
layout for this Chromium build's toolchain (libc++, 24-byte
long-string representation, member order). It is **not** a stable ABI
guarantee across Chromium versions. If you point this at a different
build and get zero validated results, re-derive the offset:

1. Navigate to a page with a distinctive URL.
2. Find raw occurrences of the URL text in the process's memory.
3. Find where its buffer address is stored as an 8-byte pointer
   elsewhere in memory.
4. Look at the bytes right after that pointer for 8 `int32` pairs whose
   `(begin, len)` values, applied to the URL string, reproduce its
   scheme/host/path exactly. The offset from the pointer to the start
   of that 8-pair block is the new constant.

Update `kParsedStructOffset` in `src/chrome_url_scan.cpp` accordingly.

## Why not just search for the raw string?

Raw occurrence count alone is not reliable: static strings compiled
into the binary (e.g. `http://www.unicode.org/copyright.html`, a fixed
list of `domainreliability` beacon endpoints) can outrank the real open
page. The structural `url::Parsed` check is what gives high confidence
that a match is a real, live `GURL`, not incidental text.
