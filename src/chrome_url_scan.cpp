// Finds URLs of currently-open pages by scanning a live Chromium browser
// process's memory for url::GURL objects, without attaching/pausing it.
//
// Technique:
//   1. Find candidate "scheme://..." strings anywhere in readable memory.
//   2. Rank them by raw occurrence count (cheap pre-filter).
//   3. Calibrate: for a handful of the top candidates, find an 8-byte
//      pointer to the string's buffer, then brute-force search nearby
//      offsets for a url::Parsed-shaped block (eight (begin,len) int32
//      pairs for scheme/username/password/host/port/path/query/ref)
//      whose values, applied to the string, reproduce its own components
//      exactly. The offset (pointer -> struct) that this finds repeatedly
//      is a real ABI fact about the running build, not a guess.
//   4. Validate all shortlisted candidates using that calibrated offset
//      directly (fast: no more brute force needed once calibrated).
//
// A plain string sitting in history/cache/an IPC buffer will not have
// this structure sitting next to a pointer to it -- only a live GURL
// does. Because the offset is derived at runtime instead of hardcoded,
// this works across Chromium builds/versions without recompiling, as
// long as the general GURL{spec_, is_valid_, parsed_} layout holds.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <unordered_map>
#include <algorithm>
#include <fcntl.h>
#include <unistd.h>

#include "calibration_cache.h"

namespace {

constexpr size_t kMaxRegionSize = 128 * 1024 * 1024;
constexpr size_t kMaxCandidateLen = 500;
constexpr size_t kMinCandidateLen = 8;
constexpr size_t kMaxAddrsPerCandidate = 200;
constexpr int kTopKToValidate = 40;
constexpr int kCandidatesToCalibrateFrom = 8;
constexpr int64_t kCalibrationWindow = 1024;  // bytes searched either side of the pointer
constexpr int kMinCalibrationVotes = 2;       // independent hits that must agree on the offset

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

std::vector<Region> ReadProcessMemory(int pid) {
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
    if (perms[0] != 'r') continue;
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

// expected[i*2]=begin, expected[i*2+1]=len for scheme,user,pass,host,port,path,query,ref
// len == -1 means "component absent" (Chromium's url::Component default).
bool ParseComponents(const std::string& url, int32_t expected[16]) {
  size_t scheme_end = url.find("://");
  if (scheme_end == std::string::npos || scheme_end == 0) return false;
  size_t i = 0;
  while (i < scheme_end && IsSchemeByte(url[i])) i++;
  if (i != scheme_end) return false;
  expected[0] = 0; expected[1] = (int32_t)scheme_end;

  size_t authority_start = scheme_end + 3;
  size_t path_start = url.find('/', authority_start);
  size_t query_pos = url.find('?');
  size_t frag_pos = url.find('#');
  size_t authority_end = url.size();
  if (path_start != std::string::npos) authority_end = std::min(authority_end, path_start);
  if (query_pos != std::string::npos) authority_end = std::min(authority_end, query_pos);
  if (frag_pos != std::string::npos) authority_end = std::min(authority_end, frag_pos);

  std::string authority = url.substr(authority_start, authority_end - authority_start);
  size_t host_off = authority_start;
  int32_t user_len = -1, pass_len = -1;
  size_t at = authority.rfind('@');
  if (at != std::string::npos) {
    std::string userinfo = authority.substr(0, at);
    size_t colon = userinfo.find(':');
    if (colon != std::string::npos) {
      user_len = (int32_t)colon;
      pass_len = (int32_t)(userinfo.size() - colon - 1);
    } else {
      user_len = (int32_t)userinfo.size();
    }
    host_off = authority_start + at + 1;
    authority = authority.substr(at + 1);
  }
  expected[2] = (int32_t)authority_start; expected[3] = user_len;
  expected[4] = (int32_t)authority_start; expected[5] = pass_len;

  int32_t port_len = -1;
  size_t host_len = authority.size();
  size_t colon = authority.rfind(':');
  // avoid treating IPv6 literal colons as a port separator
  if (colon != std::string::npos && authority.find(']') == std::string::npos) {
    bool all_digit = colon + 1 < authority.size();
    for (size_t k = colon + 1; k < authority.size() && all_digit; k++)
      if (!isdigit((unsigned char)authority[k])) all_digit = false;
    if (all_digit) {
      port_len = (int32_t)(authority.size() - colon - 1);
      host_len = colon;
    }
  }
  expected[6] = (int32_t)host_off; expected[7] = (int32_t)host_len;
  expected[8] = (int32_t)(host_off + host_len + 1); expected[9] = port_len;

  size_t path_end = url.size();
  if (query_pos != std::string::npos) path_end = std::min(path_end, query_pos);
  if (frag_pos != std::string::npos) path_end = std::min(path_end, frag_pos);
  if (path_start != std::string::npos && path_start < path_end) {
    expected[10] = (int32_t)path_start; expected[11] = (int32_t)(path_end - path_start);
  } else {
    expected[10] = (int32_t)authority_end; expected[11] = -1;
  }

  if (query_pos != std::string::npos) {
    size_t qend = (frag_pos != std::string::npos && frag_pos > query_pos) ? frag_pos : url.size();
    expected[12] = (int32_t)(query_pos + 1); expected[13] = (int32_t)(qend - query_pos - 1);
  } else {
    expected[12] = 0; expected[13] = -1;
  }
  if (frag_pos != std::string::npos) {
    expected[14] = (int32_t)(frag_pos + 1); expected[15] = (int32_t)(url.size() - frag_pos - 1);
  } else {
    expected[14] = 0; expected[15] = -1;
  }
  return true;
}

struct Candidate {
  std::string text;
  std::vector<uint64_t> addrs;
  int32_t expected[16];
  int valid_refs = 0;
};

// binary-search helper: find region containing addr, or nullptr
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

// score how well a 16xint32 block matches a candidate's expected components
int ScoreComponents(const int32_t comp[16], const int32_t expected[16]) {
  int score = 0;
  for (int k = 0; k < 8; k++) {
    int32_t eb = expected[2 * k], el = expected[2 * k + 1];
    int32_t b = comp[2 * k], l = comp[2 * k + 1];
    if (el == -1) { if (l == -1) score++; }
    else { if (b == eb && l == el) score += 2; }
  }
  return score;
}

constexpr int kPerfectScore = 11;  // 3 valid components*2 + 5 absent components*1

// Brute-force-search near a pointer occurrence for the Parsed-shaped block,
// used only during calibration (not on the fast validation path).
// Returns the best-scoring offset (pointer_addr -> struct_addr) and its score.
std::pair<int64_t, int> FindBestOffset(const std::vector<Region>& regions, uint64_t ptr_addr,
                                        const int32_t expected[16]) {
  int64_t best_off = 0;
  int best_score = -1;
  for (int64_t off = -kCalibrationWindow; off <= kCalibrationWindow; off += 4) {
    int32_t comp[16];
    if (!ReadBytes(regions, ptr_addr + off, sizeof(comp), reinterpret_cast<uint8_t*>(comp)))
      continue;
    int score = ScoreComponents(comp, expected);
    if (score > best_score) { best_score = score; best_off = off; }
  }
  return {best_off, best_score};
}

// Determine the (pointer_field_addr -> url::Parsed) byte offset for this
// running build by brute-force search around a handful of known-good
// occurrences, then requiring independent agreement before trusting it.
struct Calibration { int64_t offset; bool ok; };
Calibration CalibrateOffset(const std::vector<Region>& regions, std::vector<Candidate>& cands) {
  // build a target set from every occurrence address of the top candidates
  // (not just their first), since many raw occurrences of a string are
  // cache/history/IPC copies rather than a real, pointed-to GURL buffer --
  // a single combined linear scan is far cheaper than one scan per address.
  std::unordered_map<uint64_t, const Candidate*> target_to_cand;
  int tried = 0;
  for (Candidate& c : cands) {
    if (tried >= kCandidatesToCalibrateFrom) break;
    if (!ParseComponents(c.text, c.expected)) continue;
    tried++;
    for (uint64_t a : c.addrs) target_to_cand[a] = &c;
  }
  if (target_to_cand.empty()) return {0, false};

  std::vector<uint64_t> ptr_occurrences;  // (pointer_field_addr, candidate)
  std::vector<const Candidate*> ptr_cand;
  for (const Region& r : regions) {
    size_t n = r.data.size();
    if (n < 8) continue;
    size_t off0 = (8 - (r.start % 8)) % 8;
    for (size_t off = off0; off + 8 <= n; off += 8) {
      uint64_t val;
      memcpy(&val, r.data.data() + off, 8);
      auto it = target_to_cand.find(val);
      if (it == target_to_cand.end()) continue;
      ptr_occurrences.push_back(r.start + off);
      ptr_cand.push_back(it->second);
    }
  }

  std::unordered_map<int64_t, int> votes;
  for (size_t i = 0; i < ptr_occurrences.size(); i++) {
    auto [off, score] = FindBestOffset(regions, ptr_occurrences[i], ptr_cand[i]->expected);
    if (score == kPerfectScore) votes[off]++;
  }
  if (votes.empty()) return {0, false};
  auto best = std::max_element(votes.begin(), votes.end(),
      [](const auto& a, const auto& b) { return a.second < b.second; });
  if (best->second < kMinCalibrationVotes) return {0, false};
  return {best->first, true};
}

// Fast validation pass: given an already-known (cached or freshly
// calibrated) offset, check every shortlisted candidate directly -- no more
// brute force. Resets valid_refs on every candidate first and returns the
// total across all of them.
int RunValidation(const std::vector<Region>& regions, std::vector<Candidate>& cands,
                   int64_t offset) {
  std::unordered_map<uint64_t, int> target_addr_to_cand;
  for (size_t i = 0; i < cands.size(); i++) {
    cands[i].valid_refs = 0;
    if (!ParseComponents(cands[i].text, cands[i].expected)) continue;
    for (uint64_t a : cands[i].addrs) target_addr_to_cand[a] = (int)i;
  }

  int total = 0;
  for (const Region& r : regions) {
    size_t n = r.data.size();
    if (n < 8) continue;
    size_t off0 = (8 - (r.start % 8)) % 8;
    for (size_t off = off0; off + 8 <= n; off += 8) {
      uint64_t val;
      memcpy(&val, r.data.data() + off, 8);
      auto it = target_addr_to_cand.find(val);
      if (it == target_addr_to_cand.end()) continue;
      Candidate& c = cands[it->second];
      uint64_t parsed_addr = (int64_t)(r.start + off) + offset;
      int32_t comp[16];
      if (!ReadBytes(regions, parsed_addr, sizeof(comp), reinterpret_cast<uint8_t*>(comp)))
        continue;
      if (ScoreComponents(comp, c.expected) == kPerfectScore) {
        c.valid_refs++;
        total++;
      }
    }
  }
  return total;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    fprintf(stderr, "usage: %s <pid>\n", argv[0]);
    return 1;
  }
  int pid = atoi(argv[1]);

  std::vector<Region> regions = ReadProcessMemory(pid);
  if (regions.empty()) return 1;
  std::sort(regions.begin(), regions.end(),
            [](const Region& a, const Region& b) { return a.start < b.start; });

  // --- Pass 1: find candidate "scheme://..." strings ---
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

  // --- rank by raw occurrence count, keep top-K for validation ---
  std::vector<Candidate> cands;
  cands.reserve(found.size());
  for (auto& kv : found) {
    Candidate c;
    c.text = kv.first;
    c.addrs = std::move(kv.second);
    cands.push_back(std::move(c));
  }
  std::sort(cands.begin(), cands.end(), [](const Candidate& a, const Candidate& b) {
    return a.addrs.size() > b.addrs.size();
  });
  if ((int)cands.size() > kTopKToValidate) cands.resize(kTopKToValidate);

  // --- Calibration cache: reuse a previously-derived offset for this exact
  // binary instead of re-running the brute-force search on every poll ---
  calib_cache::ExeFingerprint fp = calib_cache::ComputeFingerprint(pid);
  std::unordered_map<std::string, calib_cache::CacheEntry> cache;
  if (fp.ok) cache = calib_cache::LoadCache("chrome");

  Calibration cal{0, false};
  bool cache_hit = false;
  if (fp.ok) {
    auto it = cache.find(fp.key);
    if (it != cache.end()) {
      auto fit = it->second.fields.find("offset");
      if (fit != it->second.fields.end()) {
        cal.offset = fit->second;
        cal.ok = true;
        cache_hit = true;
      }
    }
  }

  int total_valid = 0;
  if (cache_hit) {
    fprintf(stderr, "cache hit: reusing url::Parsed offset %+ld for this binary "
                     "(skipping calibration)\n", cal.offset);
    total_valid = RunValidation(regions, cands, cal.offset);
    if (total_valid == 0) {
      fprintf(stderr, "cached offset validated nothing on this run; recalibrating\n");
      cache_hit = false;
      cal = {0, false};
    }
  }

  if (!cache_hit) {
    // --- Calibrate: discover this build's (pointer -> url::Parsed) offset ---
    cal = CalibrateOffset(regions, cands);
    if (!cal.ok) {
      fprintf(stderr, "calibration failed: could not find a consistent GURL::parsed_ "
                       "offset near any of the top %d candidates. This build's GURL/"
                       "std::string layout may differ from what this tool assumes.\n",
                       kCandidatesToCalibrateFrom);
      return 1;
    }
    fprintf(stderr, "calibrated: url::Parsed sits at pointer_field_addr + %ld on this build\n",
            cal.offset);
    total_valid = RunValidation(regions, cands, cal.offset);

    if (fp.ok) {
      calib_cache::CacheEntry entry;
      entry.exe = fp.path;
      entry.size = fp.size;
      entry.mtime = fp.mtime;
      entry.fields["offset"] = cal.offset;
      cache[fp.key] = entry;
      calib_cache::SaveCache("chrome", cache);
    }
  }
  (void)total_valid;

  std::sort(cands.begin(), cands.end(), [](const Candidate& a, const Candidate& b) {
    return a.valid_refs > b.valid_refs;
  });

  printf("%-6s %-6s  %s\n", "valid", "raw", "url");
  for (const Candidate& c : cands) {
    if (c.valid_refs == 0) continue;
    printf("%-6d %-6zu  %s\n", c.valid_refs, c.addrs.size(), c.text.c_str());
  }
  return 0;
}
