// Finds URLs of currently-open pages by scanning a live Chromium browser
// process's memory for url::GURL objects, without attaching/pausing it.
//
// Technique (validated against Chromium 141.0.7390.37 on x86-64 Linux):
//   1. Find candidate "scheme://..." strings anywhere in readable memory.
//   2. Rank them by raw occurrence count (cheap pre-filter).
//   3. For the top candidates, look for an 8-byte pointer to that string's
//      buffer, then check for a url::Parsed struct at ptr+32: eight
//      (begin,len) int32 pairs for scheme/username/password/host/port/
//      path/query/ref. If those offsets, applied to the string, reproduce
//      its own components exactly, the string is a real GURL::spec_, not
//      leftover text in history/cache/IPC buffers.
//
// The ptr+32 offset is specific to this GURL/std::string ABI (libc++,
// 24-byte long-string representation) and this Chromium build. Re-derive
// it (see tools/find_parsed_offset.py) if the target build differs.
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

namespace {

constexpr size_t kMaxRegionSize = 128 * 1024 * 1024;
constexpr size_t kMaxCandidateLen = 500;
constexpr size_t kMinCandidateLen = 8;
constexpr size_t kMaxAddrsPerCandidate = 200;
constexpr int kTopKToValidate = 40;
constexpr int64_t kParsedStructOffset = 32;  // validated: ptr_field_addr + 32

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

  // --- Pass 2: single linear scan for pointers to shortlisted strings ---
  std::unordered_map<uint64_t, int> target_addr_to_cand;
  for (size_t i = 0; i < cands.size(); i++) {
    if (!ParseComponents(cands[i].text, cands[i].expected)) continue;
    for (uint64_t a : cands[i].addrs) target_addr_to_cand[a] = (int)i;
  }

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
      uint64_t parsed_addr = (r.start + off) + kParsedStructOffset;
      int32_t comp[16];
      if (!ReadBytes(regions, parsed_addr, sizeof(comp), reinterpret_cast<uint8_t*>(comp)))
        continue;
      int score = 0;
      for (int k = 0; k < 8; k++) {
        int32_t eb = c.expected[2 * k], el = c.expected[2 * k + 1];
        int32_t b = comp[2 * k], l = comp[2 * k + 1];
        if (el == -1) { if (l == -1) score++; }
        else { if (b == eb && l == el) score += 2; }
      }
      if (score == 11) c.valid_refs++;
    }
  }

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
