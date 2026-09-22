// Finds URLs of currently-open pages by scanning a live WebKit WebProcess's
// memory for WTF::URL objects, without attaching/pausing it.
//
// WebKit's process model differs from Chromium's: the UI process (e.g.
// epiphany/MiniBrowser) mostly just caches the committed URL as a plain
// display string. The *parsed* URL -- with byte offsets for each
// component -- lives in the per-tab WebProcess, where WebCore actually
// parses it. So this tool targets a WebProcess pid, not the UI process.
//
// Technique (mirrors chrome_url_scan.cpp, adapted to what was actually
// found in memory -- see README):
//   1. Find candidate "scheme://..." strings anywhere in readable memory.
//   2. Rank them by raw occurrence count (cheap pre-filter).
//   3. Calibrate two unknowns at once, from a handful of top candidates:
//      a. `delta`: a WTF::URL's internal String doesn't point directly at
//         the character data -- it points at a StringImpl object that
//         starts some small, constant number of bytes *before* the chars.
//      b. `struct_offset`: once a pointer to (string_addr + delta) is
//         found elsewhere in memory, the URL's component-boundary fields
//         sit at a constant byte offset from that pointer's own address.
//      Empirically (see README), the boundary fields found are 7
//      unsigned ints -- userStart, userEnd, passwordEnd, hostEnd,
//      pathAfterLastSlash, pathEnd, queryEnd -- each an absolute byte
//      offset into the URL string. A brute-force search across a handful
//      of top candidates, requiring independent agreement, pins down
//      both unknowns for the running build without hardcoding them.
//   4. Validate all shortlisted candidates directly at the calibrated
//      (delta, struct_offset). Reproducing 7 independent, URL-specific
//      integers exactly is what makes a match meaningful rather than
//      coincidental.
//
// Known gap: userinfo/port handling is best-effort (validated only
// against ports-omitted URLs); see README.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <unordered_map>
#include <map>
#include <utility>
#include <algorithm>
#include <fcntl.h>
#include <unistd.h>

namespace {

constexpr size_t kMaxRegionSize = 300 * 1024 * 1024;
constexpr size_t kMaxCandidateLen = 500;
constexpr size_t kMinCandidateLen = 8;
constexpr size_t kMaxAddrsPerCandidate = 200;
constexpr int kTopKToValidate = 40;
constexpr int kCandidatesToCalibrateFrom = 10;
constexpr int64_t kDeltaMin = -64, kDeltaMax = 8;       // search range for string->header delta
constexpr int64_t kStructWindow = 256;                  // bytes searched either side of the pointer
constexpr int kMinCalibrationVotes = 1;  // a full 7/7 field match is already highly specific
constexpr int kNumFields = 7;  // userStart,userEnd,passwordEnd,hostEnd,pathAfterLastSlash,pathEnd,queryEnd
constexpr int kPerfectScore = kNumFields;

struct Region {
  uint64_t start;
  std::vector<uint8_t> data;
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
    for (int fld = 0; fld < 5 && path; fld++) { path = strchr(path, ' '); if (path) path++; }
    while (path && *path == ' ') path++;
    if (writable_only && path && (*path == '/' || (*path == '[' && strncmp(path, "[heap]", 6) != 0
                                   && strncmp(path, "[stack]", 7) != 0
                                   && strncmp(path, "[anon", 5) != 0))) {
      skipped += end - start; continue;
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

// expected[0..6] = userStart, userEnd, passwordEnd, hostEnd,
//                  pathAfterLastSlash, pathEnd, queryEnd (absolute byte
//                  offsets into the URL string)
bool ParseComponents(const std::string& url, int32_t expected[kNumFields]) {
  size_t scheme_end = url.find("://");
  if (scheme_end == std::string::npos || scheme_end == 0) return false;
  size_t i = 0;
  while (i < scheme_end && IsSchemeByte(url[i])) i++;
  if (i != scheme_end) return false;

  size_t authority_start = scheme_end + 3;
  size_t query_pos = url.find('?');
  size_t frag_pos = url.find('#');
  size_t path_limit = url.size();
  if (query_pos != std::string::npos) path_limit = std::min(path_limit, query_pos);
  if (frag_pos != std::string::npos) path_limit = std::min(path_limit, frag_pos);

  size_t slash = url.find('/', authority_start);
  size_t authority_end = (slash != std::string::npos && slash < path_limit) ? slash : path_limit;
  std::string authority = url.substr(authority_start, authority_end - authority_start);

  int32_t user_start = (int32_t)authority_start;
  int32_t user_end = (int32_t)authority_start;
  int32_t pass_end = (int32_t)authority_start;
  size_t at = authority.rfind('@');
  if (at != std::string::npos) {
    std::string userinfo = authority.substr(0, at);
    size_t colon2 = userinfo.find(':');
    if (colon2 != std::string::npos) {
      user_end = (int32_t)(authority_start + colon2);
      pass_end = (int32_t)(authority_start + at);
    } else {
      user_end = (int32_t)(authority_start + at);
      pass_end = user_end;
    }
  }
  int32_t host_end = (int32_t)authority_end;  // port handling not validated -- see README

  size_t last_slash_search_start = (at != std::string::npos)
      ? authority_start + at + 1 : authority_start;
  size_t last_slash = url.rfind('/', path_limit > 0 ? path_limit - 1 : 0);
  int32_t path_after_last_slash = (last_slash != std::string::npos && last_slash >= last_slash_search_start)
      ? (int32_t)(last_slash + 1) : host_end;
  int32_t path_end = (int32_t)path_limit;
  int32_t query_end = (frag_pos != std::string::npos) ? (int32_t)frag_pos : (int32_t)url.size();

  expected[0] = user_start;
  expected[1] = user_end;
  expected[2] = pass_end;
  expected[3] = host_end;
  expected[4] = path_after_last_slash;
  expected[5] = path_end;
  expected[6] = query_end;
  return true;
}

struct Candidate {
  std::string text;
  std::vector<uint64_t> addrs;
  int32_t expected[kNumFields];
  int valid_refs = 0;
};

const Region* FindRegion(const std::vector<Region>& regions_sorted, uint64_t addr) {
  auto it = std::upper_bound(regions_sorted.begin(), regions_sorted.end(), addr,
      [](uint64_t a, const Region& r) { return a < r.start; });
  if (it == regions_sorted.begin()) return nullptr;
  --it;
  if (addr >= it->start && addr < it->start + it->data.size()) return &*it;
  return nullptr;
}

bool ReadBytes(const std::vector<Region>& regions_sorted, uint64_t addr, size_t n, uint8_t* out) {
  const Region* r = FindRegion(regions_sorted, addr);
  if (!r) return false;
  size_t off = addr - r->start;
  if (off + n > r->data.size()) return false;
  memcpy(out, r->data.data() + off, n);
  return true;
}

int ScoreFields(const int32_t got[kNumFields], const int32_t expected[kNumFields]) {
  int score = 0;
  for (int k = 0; k < kNumFields; k++)
    if (got[k] == expected[k]) score++;
  return score;
}

std::pair<int64_t, int> FindBestStructOffset(const std::vector<Region>& regions, uint64_t ptr_addr,
                                              const int32_t expected[kNumFields]) {
  int64_t best_off = 0;
  int best_score = -1;
  for (int64_t off = -kStructWindow; off <= kStructWindow; off += 4) {
    int32_t got[kNumFields];
    if (!ReadBytes(regions, ptr_addr + off, sizeof(got), reinterpret_cast<uint8_t*>(got)))
      continue;
    int score = ScoreFields(got, expected);
    if (score > best_score) { best_score = score; best_off = off; }
  }
  return {best_off, best_score};
}

struct Calibration { int64_t delta; int64_t struct_offset; bool ok; };

// A pointer occurrence found during the single scan: it holds value
// (string_buffer_addr + delta) for some candidate and some delta in range.
struct PtrHit { uint64_t ptr_addr; int cand_idx; int64_t delta; };

// One linear pass over memory collecting, for every top candidate and every
// delta in the search range, any 8-byte value equal to (string_addr + delta).
// The original did this scan twice (once to calibrate, once to validate);
// here both steps reuse this single collected set.
std::vector<PtrHit> CollectPointerHits(const std::vector<Region>& regions,
                                       std::vector<Candidate>& cands) {
  struct Target { int cand_idx; int64_t delta; };
  std::unordered_map<uint64_t, Target> target_map;
  for (size_t i = 0; i < cands.size(); i++) {
    if (!ParseComponents(cands[i].text, cands[i].expected)) continue;
    for (uint64_t a : cands[i].addrs)
      for (int64_t delta = kDeltaMin; delta <= kDeltaMax; delta++)
        target_map[a + delta] = {(int)i, delta};
  }
  std::vector<PtrHit> hits;
  if (target_map.empty()) return hits;
  for (const Region& r : regions) {
    size_t n = r.data.size();
    if (n < 8) continue;
    size_t off0 = (8 - (r.start % 8)) % 8;
    for (size_t off = off0; off + 8 <= n; off += 8) {
      uint64_t val;
      memcpy(&val, r.data.data() + off, 8);
      auto it = target_map.find(val);
      if (it == target_map.end()) continue;
      hits.push_back({r.start + off, it->second.cand_idx, it->second.delta});
    }
  }
  return hits;
}

// Discover (delta, struct_offset) from the collected hits, no extra scan.
Calibration CalibrateFromHits(const std::vector<Region>& regions,
                              const std::vector<Candidate>& cands,
                              const std::vector<PtrHit>& hits) {
  std::map<std::pair<int64_t, int64_t>, int> votes;
  for (const PtrHit& h : hits) {
    if (h.cand_idx >= kCandidatesToCalibrateFrom) continue;
    auto [off, score] = FindBestStructOffset(regions, h.ptr_addr, cands[h.cand_idx].expected);
    if (score == kPerfectScore) votes[{h.delta, off}]++;
  }
  if (votes.empty()) return {0, 0, false};
  auto best = std::max_element(votes.begin(), votes.end(),
      [](const auto& a, const auto& b) { return a.second < b.second; });
  if (best->second < kMinCalibrationVotes) return {0, 0, false};
  return {best->first.first, best->first.second, true};
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s <WebProcess pid>\n", argv[0]);
    fprintf(stderr, "  (find it with: ps -eo pid,cmd | grep WebKitWebProcess)\n");
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
      size_t n = r.data.size();
      if (n < 4) continue;
      for (size_t p = 0; p + 3 < n; p++) {
        if (d[p] != ':' || d[p + 1] != '/' || d[p + 2] != '/') continue;
        size_t scheme_start = p;
        while (scheme_start > 0 && IsSchemeByte(d[scheme_start - 1])) scheme_start--;
        size_t scheme_len = p - scheme_start;
        if (scheme_len < 2 || scheme_len > 16 || !isalpha(d[scheme_start])) continue;
        size_t end = p + 3;
        size_t cap = std::min(n, end + kMaxCandidateLen);
        while (end < cap && IsUrlByte(d[end])) end++;
        size_t len = end - scheme_start;
        if (len < kMinCandidateLen || len > kMaxCandidateLen) continue;
        std::string text(reinterpret_cast<const char*>(d + scheme_start), len);
        auto& v = found[text];
        if (v.size() < kMaxAddrsPerCandidate) v.push_back(r.start + scheme_start);
      }
    }
    fprintf(stderr, "pass1: %zu distinct URL-like strings\n", found.size());

    std::vector<Candidate> cands;
    cands.reserve(found.size());
    for (auto& kv : found) {
      Candidate c; c.text = kv.first; c.addrs = std::move(kv.second);
      cands.push_back(std::move(c));
    }
    std::sort(cands.begin(), cands.end(), [](const Candidate& a, const Candidate& b) {
      return a.addrs.size() > b.addrs.size();
    });
    if ((int)cands.size() > kTopKToValidate) cands.resize(kTopKToValidate);

    std::vector<PtrHit> hits = CollectPointerHits(regions, cands);
    Calibration cal = CalibrateFromHits(regions, cands, hits);
    if (!cal.ok) return false;
    fprintf(stderr, "calibrated: string_addr%+ld is pointed to, boundary fields at pointer_field_addr%+ld\n",
            cal.delta, cal.struct_offset);

    for (const PtrHit& h : hits) {
      if (h.delta != cal.delta) continue;
      Candidate& c = cands[h.cand_idx];
      uint64_t struct_addr = (int64_t)h.ptr_addr + cal.struct_offset;
      int32_t got[kNumFields];
      if (!ReadBytes(regions, struct_addr, sizeof(got), reinterpret_cast<uint8_t*>(got)))
        continue;
      if (ScoreFields(got, c.expected) == kPerfectScore) c.valid_refs++;
    }

    std::sort(cands.begin(), cands.end(), [](const Candidate& a, const Candidate& b) {
      return a.valid_refs > b.valid_refs;
    });
    printf("%-6s %-6s  %s\n", "valid", "raw", "url");
    for (const Candidate& c : cands) {
      if (c.valid_refs == 0) continue;
      printf("%-6d %-6zu  %s\n", c.valid_refs, c.addrs.size(), c.text.c_str());
    }
    return true;
  };

  if (run(/*writable_only=*/true)) return 0;
  fprintf(stderr, "writable-only scan did not calibrate; retrying over all readable memory...\n");
  if (run(/*writable_only=*/false)) return 0;
  fprintf(stderr, "calibration failed: could not find a consistent WTF::URL layout "
                   "near any of the top %d candidates. This build's URL/StringImpl "
                   "layout may differ from what this tool assumes.\n",
                   kCandidatesToCalibrateFrom);
  return 1;
  return 0;
}
