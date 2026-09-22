#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)
pids=()
cleanup() {
  if [[ -n ${watch_pid:-} ]]; then kill "$watch_pid" 2>/dev/null || true; fi
  if ((${#pids[@]})); then kill "${pids[@]}" 2>/dev/null || true; fi
  rm -rf "$tmp"
}
trap cleanup EXIT

cat >"$tmp/fixture.cpp" <<'CPP'
#include <chrono>
#include <cstring>
#include <thread>

volatile const char blink_a[] = "Chrome_RendererMain";
volatile const char blink_b[] = "ContentMainRunner";
volatile const char gecko_a[] = "NS_InitXPCOM2";
volatile const char gecko_b[] = "nsStandardURL";
volatile const char webkit_a[] = "WebKitWebProcessMain";
volatile const char webkit_b[] = "WebProcessPool";

int main(int argc, char** argv) {
  // Keep the feature strings live and accept role-looking arguments without
  // requiring the fixture to understand them.
  if (argc == 99) return blink_a[0] + blink_b[0] + gecko_a[0] + gecko_b[0] +
                         webkit_a[0] + webkit_b[0];
  std::this_thread::sleep_for(std::chrono::seconds(30));
}
CPP

cat >"$tmp/negative.cpp" <<'CPP'
#include <chrono>
#include <thread>
volatile const char v8_only[] = "V8 JavaScript engine";
volatile const char jsc_only[] = "JavaScriptCore";
int main(int argc, char**) {
  if (argc == 99) return v8_only[0] + jsc_only[0];
  std::this_thread::sleep_for(std::chrono::seconds(30));
}
CPP

cat >"$tmp/module.cpp" <<'CPP'
extern "C" {
volatile const char feature_a[] = "Chrome_RendererMain";
volatile const char feature_b[] = "cef_execute_process";
}
CPP

cat >"$tmp/module_host.cpp" <<'CPP'
#include <chrono>
#include <cstdlib>
#include <dlfcn.h>
#include <thread>
int main(int argc, char** argv) {
  if (argc < 2 || argc > 3) return 2;
  if (argc == 3) std::this_thread::sleep_for(std::chrono::seconds(std::atoi(argv[2])));
  if (!dlopen(argv[1], RTLD_NOW | RTLD_LOCAL)) return 2;
  std::this_thread::sleep_for(std::chrono::seconds(30));
}
CPP

g++ -std=c++17 -O2 -Wall -Wextra -Wpedantic -Werror \
  -o "$tmp/discover" "$repo/src/browser_engine_discovery.cpp"
g++ -std=c++17 -O2 -o "$tmp/arbitrary-renamed-host" "$tmp/fixture.cpp"
g++ -std=c++17 -O2 -o "$tmp/unrelated-runtime" "$tmp/negative.cpp"
g++ -std=c++17 -O2 -shared -fPIC -o "$tmp/arbitrary-module.so" "$tmp/module.cpp"
g++ -std=c++17 -O2 -o "$tmp/plain-module-host" "$tmp/module_host.cpp" -ldl
cp "$tmp/unrelated-runtime" "$tmp/electron-helper"

"$tmp/arbitrary-renamed-host" --type=renderer & pids+=("$!")
engine_pid=$!
"$tmp/unrelated-runtime" & pids+=("$!")
negative_pid=$!
"$tmp/electron-helper" & pids+=("$!")
name_pid=$!
"$tmp/plain-module-host" "$tmp/arbitrary-module.so" & pids+=("$!")
module_pid=$!

"$tmp/discover" --artifact-budget-mib 16 --sweep-budget-mib 256 >"$tmp/result.json"

python3 - "$tmp/result.json" "$engine_pid" "$negative_pid" "$name_pid" "$module_pid" <<'PY'
import json
import sys

path, engine_pid, negative_pid, name_pid, module_pid = sys.argv[1:]
data = json.load(open(path))
by_pid = {item["pid"]: item for item in data["processes"]}

engine = by_pid[int(engine_pid)]
statuses = {
    family["family"]: family["status"]
    for artifact in engine["artifacts"]
    for family in artifact["engines"]
}
assert statuses == {
    "blink/chromium": "probable",
    "gecko": "probable",
    "webkit": "probable",
}, statuses
assert engine["role"] == {"value": "renderer/content", "status": "inferred"}

assert int(negative_pid) not in by_pid, "V8/JSC-only negative control was detected"
candidate = by_pid[int(name_pid)]
candidate_engines = [
    family
    for artifact in candidate["artifacts"]
    for family in artifact["engines"]
]
assert len(candidate_engines) == 1, candidate_engines
assert candidate_engines[0]["family"] == "blink/chromium"
assert candidate_engines[0]["status"] == "candidate"
assert candidate_engines[0]["evidence"][0]["kind"] == "name-lead"

embedded = by_pid[int(module_pid)]
embedded_artifacts = [
    artifact
    for artifact in embedded["artifacts"]
    if artifact["observed_path"].endswith("arbitrary-module.so")
]
assert len(embedded_artifacts) == 1, embedded["artifacts"]
assert embedded_artifacts[0]["engines"][0]["family"] == "blink/chromium"
assert embedded_artifacts[0]["engines"][0]["status"] == "probable"

coverage = data["coverage"]
assert coverage["processes_enumerated"] >= coverage["processes_inspected"]
assert "inspection_gaps" in data
assert data["visibility_scope"]["proc_root"] == "/proc"
print("discovery integration checks passed")
PY

"$tmp/plain-module-host" "$tmp/arbitrary-module.so" 4 & pids+=("$!")
late_module_pid=$!
"$tmp/discover" --watch --interval 1 --artifact-budget-mib 16 \
  --sweep-budget-mib 256 >"$tmp/watch.jsonl" &
watch_pid=$!
sleep 6
kill "$watch_pid"
wait "$watch_pid"
watch_pid=

python3 - "$tmp/watch.jsonl" "$engine_pid" "$late_module_pid" <<'PY'
import json
import sys

documents = [json.loads(line) for line in open(sys.argv[1])]
assert len(documents) >= 2
engine_pid = int(sys.argv[2])
late_module_pid = int(sys.argv[3])
observations = [
    process
    for document in documents
    for process in document["processes"]
    if process["pid"] == engine_pid
]
assert len(observations) >= 2
assert observations[-1]["first_observed_at"] <= observations[-1]["last_observed_at"]
assert documents[1]["coverage"]["cache_hits"] > 0
late_presence = [
    any(process["pid"] == late_module_pid for process in document["processes"])
    for document in documents
]
assert not late_presence[0], late_presence
assert any(late_presence[1:]), late_presence
print("watch reconciliation checks passed")
PY
