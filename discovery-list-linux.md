# Linux Browser-Engine Discovery Validation Matrix

This is the reference matrix for developing and validating Linux process
discovery. It targets applications with the ability to load and display an
arbitrary modern web page, including engines embedded in applications that are
not marketed as browsers.

The list is organized by materially different engine packaging and process
models, not application popularity. Testing many similarly packaged Electron
applications adds less confidence than testing one example of every distinct
runtime shape.

No finite matrix can establish universal coverage. Unknown, modified, stripped,
statically linked, deliberately concealed, inaccessible, or short-lived engines
can remain undetected. Passing this matrix means broad recognition coverage for
known Linux ecosystems, not proof that no other browser engine exists.

## Qualification

A target belongs in the primary matrix when it can load arbitrary remote URLs
and plausibly render current HTML, CSS, and JavaScript applications. A runtime
does not need to expose browser chrome or permit navigation through its normal
product UI: the embedded engine capability is what matters.

Targets with materially incomplete web-platform support remain expansion,
legacy, or negative controls rather than primary modern-page targets.

## P0: required current Linux runtimes

| Runtime | Applications or fixtures | Distinct coverage | Status |
| --- | --- | --- | --- |
| Chromium | Chromium or Google Chrome | Standard monolithic browser, zygote ancestry, renderer/GPU/network/utility roles | [ ] |
| Branded Chromium fork | Brave or Vivaldi | Renamed browser executable and product packaging | [ ] |
| Electron | Minimal renamed Electron app; VS Code; Signal Desktop | Product-named executable reused by controller and Chromium children | [ ] |
| CEF | `cefsimple`; `cefclient` | `libcef.so`, same-executable subprocesses, off-screen and windowed rendering | [ ] |
| Wrapped CEF | OBS Studio browser source; JetBrains/JCEF | Plug-in loading, Java/JNI host, nested framework packaging | [ ] |
| Qt WebEngine | Minimal `QWebEngineView`; qutebrowser or Falkon | Arbitrary native/Python host plus `QtWebEngineProcess` | [ ] |
| NW.js | Stock `nw`; renamed or package-appended application | Renamed Chromium+Node runtime | [ ] |
| Chromium Content API | `content_shell`; custom neutral-name Content host | Monolithic/static custom embedder without framework names | [ ] |
| Chromium headless | Chrome modern headless mode; `chrome-headless-shell` | No visible window and alternate executable packaging | [ ] |
| Firefox | Current Firefox release and ESR | `libxul.so`, Fission, multiple content and support process types | [ ] |
| Branded Gecko derivative | LibreWolf or Tor Browser | Renamed Firefox runtime and privacy-hardened packaging | [ ] |
| Gecko non-browser | Thunderbird rendering web content | Gecko hosted by an application not marketed as a browser | [ ] |
| WebKitGTK 6.0 | Epiphany or upstream GTK 4 MiniBrowser | Current GTK 4 ABI and generic `WebKit*Process` helpers | [ ] |
| WebKitGTK 4.1 | Luakit or upstream GTK 3 MiniBrowser | Alternate current ABI with the same helper family | [ ] |
| Arbitrary WebKitGTK host | Neutral-name Tauri/Wry application | Rust host backed by a system engine | [ ] |
| Dynamically loaded WebKitGTK | Neutralinojs or purpose-built loader | Engine loaded after process start | [ ] |
| WPE WebKit 2.0 | Minimal neutral-name WPE launcher | Embedded Linux, arbitrary host, `WPE*Process` helpers | [ ] |
| Headless WPE | WPE launcher with `WPE_PLATFORM=headless` | Engine without desktop integration or a visible surface | [ ] |
| Legacy WPE deployment | Cog | Common deployed WPE 1.x/WPEBackend-fdo packaging | [ ] |
| Playwright browsers | Playwright Chromium, Firefox, and WebKit builds | Patched, cache-local, headed/headless browser distributions | [ ] |

## P1: important packaging and relationship blind spots

| Runtime or scenario | Applications or fixtures | Distinct coverage | Status |
| --- | --- | --- | --- |
| JavaFX WebView | Minimal Java application with an address bar | WebKit running in the JVM through JavaFX native libraries, without normal WebKit helpers | [ ] |
| JxBrowser | Minimal Java/Kotlin application | Commercial Chromium runtime isolated behind Java/JNI | [ ] |
| Wails | Neutral-name Go application | WebKitGTK behind a Go host | [ ] |
| Direct Wry embedder | Neutral-name Rust application | Low-level WebKitGTK wrapper without Tauri branding | [ ] |
| CEF separate helper | Arbitrarily renamed host and independently renamed subprocess | No `cef`, browser, or product token in executable names | [ ] |
| CEF plug-in loaded late | Neutral host loading CEF after startup | Late module loading and host-to-engine attribution | [ ] |
| Relocated Qt helper | Custom `QTWEBENGINEPROCESS_PATH` and renamed helper | Defeats a fixed `QtWebEngineProcess` name assumption | [ ] |
| Concurrent WebKitGTK hosts | Epiphany and Luakit simultaneously | Correct association of generic helpers with separate UI processes | [ ] |
| Deleted engine module | Loaded CEF/WebKit module unlinked after mapping | Inspection through the mapped object rather than replacement path | [ ] |
| Replaced engine module | Loaded module whose pathname is replaced on disk | Device/inode validation and replacement rejection | [ ] |
| Flatpak application | Flatpak Electron, Qt WebEngine, or WebKitGTK application | PID/mount namespaces, relocated files, and sandbox launchers | [ ] |
| Containerized browser | Browser in a visible PID namespace and one outside it | Honest visibility-scope and absence reporting | [ ] |
| Multiple engines in one PID | Purpose-built host loading two supported engine libraries | Independent per-artifact, per-family reporting | [ ] |
| Parent exits after launch | Engine child surviving its original host | Detection preserved without live original parent | [ ] |
| Non-parent host relationship | Chromium zygote or external WebKit process provider | Relationships not restricted to direct PPID | [ ] |

## P2: recognition-scope expansion

These runtimes require dedicated recognition rules. Shared ancestry or a reused
JavaScript engine is not enough to classify them as WebKit, Gecko, or Chromium.

| Runtime | Representative target | Capability and classification notes | Status |
| --- | --- | --- | --- |
| Ultralight | Ultralight Browser sample and neutral custom host | WebKit WebCore fork, statically linked JavaScriptCore, custom renderer; claims support for most modern sites | [ ] |
| Ekioh Flow | Linux/Raspberry Pi Flow preview or SDK sample | Independent proprietary engine using SpiderMonkey; Linux and embedded deployments | [ ] |
| Current Cobalt | Linux reference build or representative embedded product | Current generations are Chromium/Blink-derived but product packaging is highly variable | [ ] |
| Android System WebView | Application under Waydroid or another Android environment whose PIDs are in scope | Chromium WebView artifacts and Android service/process identity rather than native desktop conventions | [ ] |
| Goanna/UXP | Pale Moon and Basilisk | Maintained older-Mozilla fork; modern-site support below current Gecko and ABI/process behavior differs | [ ] |
| Servo | `servoshell` and a minimal WebView embedder | Independent engine with single- and multi-process modes; not yet a production-equivalent arbitrary-page browser | [ ] |
| Ladybird/LibWeb | Ladybird with `WebContent` children | Independent developing engine; packaging and capability are not yet stable enough for the primary promise | [ ] |

## Legacy and negative controls

These cases prevent broad strings, shared JavaScript engines, and historical
ancestry from producing false modern-engine classifications.

| Target | Expected result | Status |
| --- | --- | --- |
| Node.js/V8-only process | No Blink/Chromium detection | [ ] |
| JavaScriptCore-only process | No WebKit detection | [ ] |
| SpiderMonkey-only process | No Gecko or Flow detection | [ ] |
| Application containing browser names, user agents, or incidental engine strings | Candidate at most; not probable from generic text | [ ] |
| Qt WebKit | Legacy WebKit-family compatibility target, not current Qt WebEngine or supported modern WebKit | [ ] |
| WebKitGTK WebKit1 | Legacy in-process WebKit target without required helpers | [ ] |
| Historical Cobalt | Do not infer current Blink solely from Cobalt or V8 evidence | [ ] |
| Sciter | Independent desktop-UI engine with intentionally incomplete browser compatibility; outside arbitrary-modern-page promise | [ ] |
| NetSurf | Independent browser with incomplete modern HTML/CSS/JavaScript support | [ ] |
| Dillo | No JavaScript and limited modern web-platform support | [ ] |
| Awesomium, Berkelium, CEF1, and old node-webkit | Obsolete compatibility corpus only | [ ] |
| Qt WebEngine sample | Must classify as Blink/Chromium, never WebKit because it replaced Qt WebKit | [ ] |
| Electron or CEF binary containing historical WebKit/user-agent text | Must classify from Chromium evidence, not generic WebKit strings | [ ] |

## Required variants for each applicable runtime

Each runtime should be exercised in as many of these states as it supports:

- [ ] Engine loaded but no page open.
- [ ] One arbitrary modern page loaded.
- [ ] Multiple pages, tabs, or cross-origin frames.
- [ ] Headed operation.
- [ ] Headless or off-screen operation.
- [ ] Arbitrarily renamed host executable.
- [ ] Arbitrarily renamed engine module or helper executable.
- [ ] Engine loaded after the initial discovery sweep.
- [ ] Host executes a different binary without changing PID.
- [ ] Original parent exits or child is reparented.
- [ ] Multiple engine families loaded in one process.
- [ ] Multiple PIDs participating in one runtime instance.
- [ ] Engine binary or module deleted after loading.
- [ ] Path replaced with a different inode after loading.
- [ ] Access denied to metadata, `maps`, `map_files`, or the artifact.
- [ ] Process exits during inspection.
- [ ] PID reused between enumeration and inspection.
- [ ] Artifact exceeds per-file analysis budget.
- [ ] Sweep exceeds total analysis budget.
- [ ] Runtime isolated by Flatpak, container, PID namespace, or mount namespace.
- [ ] Instance starts and exits entirely between watch observations.

## Assertions for every test

1. The expected process is enumerated using PID plus start time.
2. Engine family is supported by concrete artifact evidence, not application
   name alone.
3. Detection status accurately distinguishes identified, probable, candidate,
   associated-only, and unresolved evidence.
4. Every locally loaded engine family is reported independently.
5. Controller, renderer/content, GPU, network, utility, and unknown roles are
   classified separately and qualified by evidence strength.
6. Supporting descendants are not automatically labeled as locally containing
   engine code.
7. Host/runtime relationships survive zygotes, reparenting, and unusual process
   arrangements where available evidence permits association.
8. The actual mapped artifact is inspected where possible; deleted or replaced
   paths never silently substitute a different file.
9. Inaccessible, disappeared, anonymous, truncated, and budget-exhausted
   inspections are reported as gaps rather than negative detections.
10. A no-match result remains distinct from complete inspection, recognition
    coverage, and universal absence.
11. Warm passes reuse artifact analysis while still revisiting every process's
    executable identity and mappings.
12. Watch output records first and last observations and acknowledges that
    polling can miss instances between sweeps.

## Performance measurements

Record these for every cold and warm matrix run:

- Processes enumerated and fully/partially inspected.
- Mapping entries parsed.
- Unique executable artifacts encountered.
- Artifact-cache hits and misses.
- Bytes read from artifacts.
- CPU time, wall time, and peak collector memory.
- Access-denied, disappeared, anonymous, replaced, and incomplete artifacts.
- Budget-exhausted analyses.
- Detection latency for process start, `exec`, and late module loading.

Numerical service-level objectives should be set only after measurements across
desktop, CI, server, embedded, and container workloads.

## Current known implementation gaps

The initial detector should not be considered complete against this matrix:

- Recognition currently covers only Blink/Chromium, Gecko, and upstream-style
  WebKit binary features.
- Ultralight, Flow, Cobalt variants, Goanna, Servo, Ladybird, and Android WebView
  need explicit recognition research and rules.
- JavaFX WebKit and proprietary wrappers may expose different binary features.
- Very large artifacts can place useful evidence outside the inspected prefix.
- Direct-parent relationships are insufficient for Chromium zygotes,
  reparenting, Flatpak launchers, and external WebKit process providers.
- WPE-specific roles and Gecko remote process types need richer classification.

## Authoritative references

### Chromium and embedders

- Chromium multi-process architecture:
  <https://chromium.googlesource.com/playground/chromium-org-site/+/refs/heads/main/developers/design-documents/multi-process-architecture/index.md>
- Chromium Linux zygote design:
  <https://chromium.googlesource.com/chromium/src/+/HEAD/docs/linux/zygote.md>
- Electron process model:
  <https://www.electronjs.org/docs/latest/tutorial/process-model>
- CEF general usage and process architecture:
  <https://chromiumembedded.github.io/cef/general_usage.html>
- Qt WebEngine architecture:
  <https://doc.qt.io/qt-6/qtwebengine-overview.html>
- Qt WebEngine deployment and helper override:
  <https://doc.qt.io/qt-6/qtwebengine-deploying.html>
- NW.js getting started:
  <https://docs.nwjs.io/For%20Users/Getting%20Started>
- Chromium Content Shell:
  <https://chromium.googlesource.com/chromium/src/+/HEAD/docs/testing/content_shell.md>
- OBS browser/CEF integration:
  <https://github.com/obsproject/obs-browser>
- JetBrains JCEF:
  <https://github.com/JetBrains/jcef>

### WebKit and Linux webviews

- Current WebKit ports:
  <https://docs.webkit.org/Ports/Introduction.html>
- WebKitGTK:
  <https://webkitgtk.org/>
- WPE WebKit architecture:
  <https://wpewebkit.org/about/architecture.html>
- WPE FAQ and minimal launcher:
  <https://wpewebkit.org/about/faq.html>
- Cog:
  <https://github.com/Igalia/cog>
- Tauri WebView versions:
  <https://v2.tauri.app/reference/webview-versions/>
- Tauri process model:
  <https://tauri.app/concept/process-model>
- Wry Linux WebKitGTK backend:
  <https://docs.rs/wry/latest/wry/>
- Wails Linux runtime dependencies:
  <https://wails.io/docs/guides/linux-distro-support>
- Neutralinojs Linux WebKit backend:
  <https://github.com/neutralinojs/neutralinojs>
- JavaFX WebView/JxBrowser architecture comparison:
  <https://teamdev.com/jxbrowser/blog/jxbrowser-or-javafx-webview/>
- Ultralight WebCore architecture:
  <https://github.com/ultralight-ux/WebCore>

### Gecko and independent engines

- Gecko process model and remote types:
  <https://firefox-source-docs.mozilla.org/dom/ipc/process_model.html>
- Gecko process hierarchy:
  <https://firefox-source-docs.mozilla.org/ipc/processes.html>
- Gecko platform overview:
  <https://firefox-source-docs.mozilla.org/overview/gecko.html>
- Playwright browser distributions:
  <https://playwright.dev/docs/browsers>
- Goanna/UXP:
  <https://www.palemoon.org/tech/goanna.shtml>
- Servo architecture:
  <https://book.servo.org/design-documentation/architecture.html>
- Ladybird:
  <https://ladybird.org/>
- Ekioh Flow:
  <https://www.ekioh.com/flow-browser/>
- Cobalt:
  <https://cobalt.dev/overview.html>
- Sciter compatibility scope:
  <https://docs.sciter.com/docs/intro>
- NetSurf implementation status:
  <https://www.netsurf-browser.org/documentation/progress>
- Dillo capabilities:
  <https://dillo-browser.github.io/user_help.html>
