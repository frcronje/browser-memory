// Finds URLs of currently-open pages by scanning a live Firefox content
// process's memory for Gecko nsStandardURL objects, without attaching to or
// pausing it.
//
// nsStandardURL stores its normalized UTF-8 URL in an nsCString, followed by
// default/explicit ports and twelve or thirteen URLSegment fields (scheme, authority,
// username, password, host, path, filepath, directory, basename, extension,
// optional legacy parameter, query, ref). Each segment records a byte position
// and length in that same string. We find pointers to candidate strings, then
// calibrate the offset, segment count, and stride by looking for a complete
// component layout that reproduces the candidate. This supports both the
// 13-segment Firefox 4 layout, the current 12-segment layout, and the wider
// parity-checked fields used in early-beta builds without build-specific constants.
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <map>
#include <string>
#include <unordered_map>
#include <unistd.h>
#include <utility>
#include <vector>

namespace {

constexpr size_t kMaxRegionSize = 300 * 1024 * 1024;
constexpr size_t kMaxCandidateLen = 500;
constexpr size_t kMinCandidateLen = 8;
constexpr size_t kMaxAddrsPerCandidate = 200;
constexpr int kCandidatesToCalibrateFrom = 200;
constexpr int64_t kCalibrationWindow = 256;
constexpr int kMinCalibrationVotes = 2;
constexpr int kMaxSegments = 13;

enum Segment {
  kScheme, kAuthority, kUsername, kPassword, kHost, kPath,
  kFilepath, kDirectory, kBasename, kExtension, kParam, kQuery, kRef
};

struct Region {
  uint64_t start;
  std::vector<uint8_t> data;
};

struct Component {
  uint32_t pos;
  int32_t len;
};

struct Candidate {
  std::string text;
  std::vector<uint64_t> addrs;
  Component expected[kMaxSegments];
  int valid_refs = 0;
};

bool IsUrlByte(uint8_t c) {
  return c != 0 &&
         ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9') ||
          strchr(":/.-_~%?#[]@!$&'()*+,;=", c) != nullptr);
}

bool IsSchemeByte(uint8_t c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
         (c >= '0' && c <= '9') || c == '+' || c == '.' || c == '-';
}

std::vector<Region> ReadProcessMemory(int pid, bool writable_only) {
  std::vector<Region> regions;
  char maps_path[64];
  snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
  FILE* f = fopen(maps_path, "r");
  if (!f) {
    fprintf(stderr, "cannot open %s: %s\n", maps_path, strerror(errno));
    return regions;
  }
  char mem_path[64];
  snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
  int memfd = open(mem_path, O_RDONLY);
  if (memfd < 0) {
    fprintf(stderr, "cannot open %s: %s\n", mem_path, strerror(errno));
    fclose(f);
    return regions;
  }

  char line[512];
  size_t total = 0, skipped = 0;
  while (fgets(line, sizeof(line), f)) {
    uint64_t start, end;
    char perms[8] = {0};
    if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) != 3) continue;
    if (perms[0] != 'r') { skipped += end - start; continue; }
    if (writable_only && perms[1] != 'w') { skipped += end - start; continue; }
    const char* path = line;
    for (int fld = 0; fld < 5 && path; fld++) {
      path = strchr(path, ' ');
      if (path) path++;
    }
    while (path && *path == ' ') path++;
    if (writable_only && path &&
        (*path == '/' || (*path == '[' && strncmp(path, "[heap]", 6) != 0 &&
                         strncmp(path, "[stack]", 7) != 0 &&
                         strncmp(path, "[anon", 5) != 0))) {
      skipped += end - start;
      continue;
    }
    size_t size = end - start;
    if (size == 0 || size > kMaxRegionSize) { skipped += size; continue; }
    std::vector<uint8_t> buf(size);
    ssize_t n = pread(memfd, buf.data(), size, start);
    if (n <= 0) continue;
    buf.resize(n);
    total += n;
    regions.push_back({start, std::move(buf)});
  }
  fclose(f);
  close(memfd);
  fprintf(stderr, "read %.1f MB across %zu regions (skipped %.1f MB)\n",
          total / 1e6, regions.size(), skipped / 1e6);
  return regions;
}

const Region* FindRegion(const std::vector<Region>& regions, uint64_t addr) {
  auto it = std::upper_bound(regions.begin(), regions.end(), addr,
      [](uint64_t a, const Region& r) { return a < r.start; });
  if (it == regions.begin()) return nullptr;
  --it;
  if (addr >= it->start && addr < it->start + it->data.size()) return &*it;
  return nullptr;
}

bool ReadBytes(const std::vector<Region>& regions, uint64_t addr,
               size_t n, void* out) {
  const Region* r = FindRegion(regions, addr);
  if (!r) return false;
  size_t off = addr - r->start;
  if (off + n > r->data.size()) return false;
  memcpy(out, r->data.data() + off, n);
  return true;
}

void SetAbsent(Component& c) {
  c.pos = 0;
  c.len = -1;
}

void SetPresent(Component& c, size_t pos, size_t len) {
  c.pos = static_cast<uint32_t>(pos);
  c.len = static_cast<int32_t>(len);
}

// Reproduce nsStandardURL's component ranges for ordinary hierarchical URLs.
bool ParseComponents(const std::string& url, Component out[kMaxSegments]) {
  for (int i = 0; i < kMaxSegments; i++) SetAbsent(out[i]);

  size_t scheme_end = url.find("://");
  if (scheme_end == std::string::npos || scheme_end == 0) return false;
  size_t i = 0;
  while (i < scheme_end && IsSchemeByte(url[i])) i++;
  if (i != scheme_end) return false;
  SetPresent(out[kScheme], 0, scheme_end);

  size_t authority_start = scheme_end + 3;
  size_t query = url.find('?', authority_start);
  size_t ref = url.find('#', authority_start);
  size_t path_end = url.size();
  if (query != std::string::npos) path_end = std::min(path_end, query);
  if (ref != std::string::npos) path_end = std::min(path_end, ref);
  size_t path = url.find('/', authority_start);
  size_t authority_end = (path != std::string::npos && path < path_end)
      ? path : path_end;
  SetPresent(out[kAuthority], authority_start, authority_end - authority_start);

  size_t host_start = authority_start;
  size_t at = url.rfind('@', authority_end);
  if (at != std::string::npos && at >= authority_start && at < authority_end) {
    size_t colon = url.find(':', authority_start);
    if (colon != std::string::npos && colon < at) {
      SetPresent(out[kUsername], authority_start, colon - authority_start);
      SetPresent(out[kPassword], colon + 1, at - colon - 1);
    } else {
      SetPresent(out[kUsername], authority_start, at - authority_start);
    }
    host_start = at + 1;
  }
  size_t host_end = authority_end;
  if (host_start < authority_end && url[host_start] == '[') {
    size_t close = url.find(']', host_start + 1);
    if (close != std::string::npos && close < authority_end) host_end = close + 1;
  } else {
    size_t colon = url.rfind(':', authority_end);
    if (colon != std::string::npos && colon >= host_start && colon < authority_end)
      host_end = colon;
  }
  SetPresent(out[kHost], host_start, host_end - host_start);

  if (path != std::string::npos && path < path_end) {
    // Gecko's mPath is path-query-ref; mFilepath stops before '?' or '#'.
    SetPresent(out[kPath], path, url.size() - path);
    SetPresent(out[kFilepath], path, path_end - path);
    size_t last_slash = url.rfind('/', path_end - 1);
    SetPresent(out[kDirectory], path, last_slash - path + 1);
    size_t name = last_slash + 1;
    size_t dot = url.rfind('.', path_end - 1);
    if (dot != std::string::npos && dot >= name) {
      SetPresent(out[kBasename], name, dot - name);
      SetPresent(out[kExtension], dot + 1, path_end - dot - 1);
    } else {
      SetPresent(out[kBasename], name, path_end - name);
    }
  } else {
    // Gecko normalizes hierarchical HTTP(S) URLs to include a slash.
    return false;
  }
  if (query != std::string::npos && (ref == std::string::npos || query < ref)) {
    size_t end = ref == std::string::npos ? url.size() : ref;
    SetPresent(out[kQuery], query + 1, end - query - 1);
  }
  if (ref != std::string::npos)
    SetPresent(out[kRef], ref + 1, url.size() - ref - 1);
  return true;
}

struct PtrHit { uint64_t ptr_addr; int cand_idx; };

std::vector<PtrHit> CollectPointerHits(const std::vector<Region>& regions,
                                       const std::vector<Candidate>& cands) {
  std::unordered_map<uint64_t, int> targets;
  for (size_t i = 0; i < cands.size(); i++)
    for (uint64_t addr : cands[i].addrs) targets[addr] = static_cast<int>(i);
  std::vector<PtrHit> hits;
  for (const Region& r : regions) {
    size_t first = (8 - r.start % 8) % 8;
    for (size_t off = first; off + 8 <= r.data.size(); off += 8) {
      uint64_t value;
      memcpy(&value, r.data.data() + off, sizeof(value));
      auto it = targets.find(value);
      if (it != targets.end()) hits.push_back({r.start + off, it->second});
    }
  }
  return hits;
}

// Release fields are {uint32 pos, int32 len} with stride 8. Early-beta
// fields wrap each number with a parity bool and have stride 16; the values
// remain at offsets 0 and 8 within each segment. Firefox 4 had an additional
// parameter segment between extension and query; it was later removed.
int ScoreSegments(const std::vector<Region>& regions, uint64_t address,
                  int stride, int segment_count,
                  const Component expected[kMaxSegments]) {
  int score = 0;
  for (int i = 0; i < segment_count; i++) {
    Component got;
    if (!ReadBytes(regions, address + i * stride, sizeof(got.pos), &got.pos) ||
        !ReadBytes(regions, address + i * stride + stride / 2,
                   sizeof(got.len), &got.len)) return -1;
    int expected_index = i + (segment_count == 12 && i >= kParam ? 1 : 0);
    if (got.len == expected[expected_index].len &&
        (got.len == -1 || got.pos == expected[expected_index].pos)) score++;
  }
  return score;
}

struct Calibration { int64_t offset; int stride; int segment_count; bool ok; };

Calibration Calibrate(const std::vector<Region>& regions,
                      const std::vector<Candidate>& cands,
                      const std::vector<PtrHit>& hits) {
  std::map<std::pair<int64_t, int>, int> votes;
  for (const PtrHit& hit : hits) {
    if (hit.cand_idx >= kCandidatesToCalibrateFrom) continue;
    for (int segment_count : {12, 13}) {
      for (int stride : {8, 16}) {
        for (int64_t off = 8; off <= kCalibrationWindow; off += 4) {
          if (ScoreSegments(regions, hit.ptr_addr + off, stride, segment_count,
                            cands[hit.cand_idx].expected) == segment_count)
            votes[{off, stride * 100 + segment_count}]++;
        }
      }
    }
  }
  if (votes.empty()) return {0, 0, 0, false};
  auto best = std::max_element(votes.begin(), votes.end(),
      [](const auto& a, const auto& b) { return a.second < b.second; });
  if (best->second < kMinCalibrationVotes) return {0, 0, 0, false};
  int encoded_layout = best->first.second;
  return {best->first.first, encoded_layout / 100, encoded_layout % 100, true};
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s <Firefox content-process pid>\n", argv[0]);
    fprintf(stderr, "  (find candidates with: ps -eo pid,cmd | grep '[f]irefox.*-contentproc')\n");
    return 1;
  }
  int pid = atoi(argv[1]);

  auto run = [&](bool writable_only) -> bool {
    std::vector<Region> regions = ReadProcessMemory(pid, writable_only);
    if (regions.empty()) return false;
    std::sort(regions.begin(), regions.end(),
              [](const Region& a, const Region& b) { return a.start < b.start; });

    std::unordered_map<std::string, std::vector<uint64_t>> found;
    for (const Region& r : regions) {
      const uint8_t* d = r.data.data();
      for (size_t p = 0; p + 3 < r.data.size(); p++) {
        if (d[p] != ':' || d[p + 1] != '/' || d[p + 2] != '/') continue;
        size_t start = p;
        while (start > 0 && IsSchemeByte(d[start - 1])) start--;
        size_t scheme_len = p - start;
        if (scheme_len < 2 || scheme_len > 16 || !isalpha(d[start])) continue;
        size_t end = p + 3;
        size_t cap = std::min(r.data.size(), start + kMaxCandidateLen);
        while (end < cap && IsUrlByte(d[end])) end++;
        size_t len = end - start;
        if (len < kMinCandidateLen || len > kMaxCandidateLen) continue;
        std::string text(reinterpret_cast<const char*>(d + start), len);
        auto& addrs = found[text];
        if (addrs.size() < kMaxAddrsPerCandidate) addrs.push_back(r.start + start);
      }
    }
    fprintf(stderr, "pass1: %zu distinct URL-like strings\n", found.size());

    std::vector<Candidate> cands;
    for (auto& [text, addrs] : found) {
      Candidate c;
      c.text = text;
      c.addrs = std::move(addrs);
      if (ParseComponents(c.text, c.expected)) cands.push_back(std::move(c));
    }
    std::sort(cands.begin(), cands.end(), [](const Candidate& a, const Candidate& b) {
      return a.addrs.size() > b.addrs.size();
    });

    std::vector<PtrHit> hits = CollectPointerHits(regions, cands);
    Calibration cal = Calibrate(regions, cands, hits);
    if (!cal.ok) return false;
    fprintf(stderr, "calibrated: nsStandardURL segments at pointer_field_addr%+ld, "
                    "count %d, stride %d\n",
            cal.offset, cal.segment_count, cal.stride);

    for (const PtrHit& hit : hits) {
      if (ScoreSegments(regions, hit.ptr_addr + cal.offset, cal.stride,
                        cal.segment_count, cands[hit.cand_idx].expected) ==
          cal.segment_count)
        cands[hit.cand_idx].valid_refs++;
    }
    std::sort(cands.begin(), cands.end(), [](const Candidate& a, const Candidate& b) {
      return a.valid_refs > b.valid_refs;
    });
    printf("%-6s %-6s  %s\n", "valid", "raw", "url");
    for (const Candidate& c : cands)
      if (c.valid_refs > 0)
        printf("%-6d %-6zu  %s\n", c.valid_refs, c.addrs.size(), c.text.c_str());
    return true;
  };

  if (run(/*writable_only=*/true)) return 0;
  fprintf(stderr, "writable-only scan did not calibrate; retrying over all readable memory...\n");
  if (run(/*writable_only=*/false)) return 0;
  fprintf(stderr, "calibration failed: could not find a consistent nsStandardURL layout "
                  "near any of the top %d candidates. Check that this is a Firefox "
                  "content-process pid and that pages have finished loading.\n",
          kCandidatesToCalibrateFrom);
  return 1;
}
