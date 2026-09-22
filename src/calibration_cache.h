// Small on-disk cache for the per-build ABI offsets that chrome_url_scan
// and webkit_url_scan derive by brute-force calibration.
//
// The brute-force search is a runtime fact about a specific *binary*, not
// about a specific running process: it only changes when the browser is
// rebuilt/updated. A poller that re-derives it on every invocation is
// wasting most of its runtime re-deriving something it already knows.
//
// Cache key: a cheap fingerprint of the target binary (resolved
// /proc/<pid>/exe path + st_size + st_mtime -- no hashing of the binary's
// contents, since Chromium/WebKit binaries run 200MB-1GB+). Two processes
// of the same on-disk binary share a fingerprint and a cache entry; a
// rebuild changes size/mtime and misses the cache, triggering a fresh
// calibration that overwrites the stale entry.
//
// Cache file: a hand-rolled JSON map, one entry per fingerprint, stored at
// ~/.cache/browser-memory/<tool>_calibration.json. The parser below only
// needs to understand the exact shape this file writes -- it is not a
// general-purpose JSON library.
#pragma once

#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_map>
#include <utility>

#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

namespace calib_cache {

inline uint64_t Fnv1a64(const std::string& s) {
  uint64_t h = 1469598103934665603ULL;
  for (unsigned char c : s) {
    h ^= c;
    h *= 1099511628211ULL;
  }
  return h;
}

struct ExeFingerprint {
  bool ok = false;
  std::string key;   // hex fingerprint; the cache map key
  std::string path;  // resolved exe path, kept for the cache file's benefit
  int64_t size = 0;
  int64_t mtime = 0;
};

// Cheap per-binary fingerprint: resolved exe path + size + mtime, hashed.
// Deliberately not a content hash of the binary -- these binaries run
// 200MB-1GB+, and identity by path+size+mtime is enough to notice a
// rebuild/update (the recalibration fallback below covers the rare case
// where that's not enough).
inline ExeFingerprint ComputeFingerprint(int pid) {
  ExeFingerprint fp;
  char link_path[64];
  snprintf(link_path, sizeof(link_path), "/proc/%d/exe", pid);
  char resolved[4096];
  ssize_t n = readlink(link_path, resolved, sizeof(resolved) - 1);
  if (n <= 0) return fp;
  resolved[n] = '\0';
  fp.path = resolved;

  struct stat st;
  if (stat(resolved, &st) != 0) return fp;
  fp.size = (int64_t)st.st_size;
  fp.mtime = (int64_t)st.st_mtime;

  char buf[4096 + 64];
  snprintf(buf, sizeof(buf), "%s|%lld|%lld", resolved, (long long)fp.size,
           (long long)fp.mtime);
  uint64_t h = Fnv1a64(buf);
  char hex[17];
  snprintf(hex, sizeof(hex), "%016llx", (unsigned long long)h);
  fp.key = hex;
  fp.ok = true;
  return fp;
}

struct CacheEntry {
  std::string exe;
  int64_t size = 0;
  int64_t mtime = 0;
  std::unordered_map<std::string, int64_t> fields;  // e.g. "offset", "delta"
};

inline std::string CacheDir() {
  const char* home = getenv("HOME");
  std::string home_str;
  if (home && *home) {
    home_str = home;
  } else {
    struct passwd* pw = getpwuid(getuid());
    if (pw && pw->pw_dir) home_str = pw->pw_dir;
  }
  if (home_str.empty()) home_str = "/tmp";
  return home_str + "/.cache/browser-memory";
}

inline bool EnsureDir(const std::string& path) {
  std::string cur;
  size_t pos = 0;
  if (path.empty()) return false;
  if (path[0] == '/') {
    cur = "/";
    pos = 1;
  }
  while (pos <= path.size()) {
    size_t next = path.find('/', pos);
    std::string comp = (next == std::string::npos) ? path.substr(pos)
                                                     : path.substr(pos, next - pos);
    if (!comp.empty()) {
      cur += comp;
      mkdir(cur.c_str(), 0755);  // ignore EEXIST/errors; checked below
      cur += "/";
    }
    if (next == std::string::npos) break;
    pos = next + 1;
  }
  struct stat st;
  return stat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}

inline std::string CacheFilePath(const std::string& tool_name) {
  return CacheDir() + "/" + tool_name + "_calibration.json";
}

// ---- minimal JSON, scoped to exactly the shape SaveCache() writes ----

struct JsonParser {
  const char* p;
  const char* end;
  bool ok = true;

  void SkipWs() {
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
  }

  bool Expect(char c) {
    SkipWs();
    if (p < end && *p == c) {
      p++;
      return true;
    }
    ok = false;
    return false;
  }

  bool ParseString(std::string* out) {
    SkipWs();
    if (p >= end || *p != '"') {
      ok = false;
      return false;
    }
    p++;
    out->clear();
    while (p < end && *p != '"') {
      if (*p == '\\' && p + 1 < end) {
        p++;
        char c = *p;
        switch (c) {
          case 'n': out->push_back('\n'); break;
          case 't': out->push_back('\t'); break;
          case '"': out->push_back('"'); break;
          case '\\': out->push_back('\\'); break;
          case '/': out->push_back('/'); break;
          default: out->push_back(c); break;
        }
        p++;
      } else {
        out->push_back(*p);
        p++;
      }
    }
    if (p >= end) {
      ok = false;
      return false;
    }
    p++;  // closing quote
    return true;
  }

  bool ParseNumber(int64_t* out) {
    SkipWs();
    const char* start = p;
    if (p < end && (*p == '-' || *p == '+')) p++;
    while (p < end && isdigit((unsigned char)*p)) p++;
    if (p == start) {
      ok = false;
      return false;
    }
    *out = strtoll(std::string(start, p).c_str(), nullptr, 10);
    return true;
  }
};

inline bool ParseEntryObject(JsonParser* jp, CacheEntry* entry) {
  if (!jp->Expect('{')) return false;
  jp->SkipWs();
  if (jp->p < jp->end && *jp->p == '}') {
    jp->p++;
    return true;
  }
  while (true) {
    std::string key;
    if (!jp->ParseString(&key)) return false;
    if (!jp->Expect(':')) return false;
    jp->SkipWs();
    if (key == "exe") {
      if (!jp->ParseString(&entry->exe)) return false;
    } else if (key == "size") {
      if (!jp->ParseNumber(&entry->size)) return false;
    } else if (key == "mtime") {
      if (!jp->ParseNumber(&entry->mtime)) return false;
    } else if (key == "fields") {
      if (!jp->Expect('{')) return false;
      jp->SkipWs();
      if (jp->p < jp->end && *jp->p == '}') {
        jp->p++;
      } else {
        while (true) {
          std::string fkey;
          if (!jp->ParseString(&fkey)) return false;
          if (!jp->Expect(':')) return false;
          int64_t fval = 0;
          if (!jp->ParseNumber(&fval)) return false;
          entry->fields[fkey] = fval;
          jp->SkipWs();
          if (jp->p < jp->end && *jp->p == ',') {
            jp->p++;
            continue;
          }
          break;
        }
        if (!jp->Expect('}')) return false;
      }
    } else {
      // unknown/forward-compat field: skip a string or a number
      if (jp->p < jp->end && *jp->p == '"') {
        std::string sval;
        if (!jp->ParseString(&sval)) return false;
      } else {
        int64_t nval;
        if (!jp->ParseNumber(&nval)) return false;
      }
    }
    jp->SkipWs();
    if (jp->p < jp->end && *jp->p == ',') {
      jp->p++;
      continue;
    }
    break;
  }
  return jp->Expect('}');
}

inline std::unordered_map<std::string, CacheEntry> LoadCache(const std::string& tool_name) {
  std::unordered_map<std::string, CacheEntry> cache;
  std::string path = CacheFilePath(tool_name);
  FILE* f = fopen(path.c_str(), "rb");
  if (!f) return cache;
  std::string data;
  char buf[4096];
  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), f)) > 0) data.append(buf, n);
  fclose(f);

  JsonParser jp{data.c_str(), data.c_str() + data.size()};
  if (!jp.Expect('{')) return cache;
  jp.SkipWs();
  if (jp.p < jp.end && *jp.p == '}') return cache;
  while (jp.ok) {
    std::string key;
    if (!jp.ParseString(&key)) break;
    if (!jp.Expect(':')) break;
    CacheEntry entry;
    if (!ParseEntryObject(&jp, &entry)) break;
    cache[key] = entry;
    jp.SkipWs();
    if (jp.p < jp.end && *jp.p == ',') {
      jp.p++;
      continue;
    }
    break;
  }
  return cache;
}

inline std::string JsonEscape(const std::string& s) {
  std::string out;
  for (char c : s) {
    if (c == '"' || c == '\\') {
      out.push_back('\\');
      out.push_back(c);
    } else if (c == '\n') {
      out += "\\n";
    } else {
      out.push_back(c);
    }
  }
  return out;
}

// Writes via a temp file + rename so a poller reading the cache mid-write
// never observes a partial file.
inline bool SaveCache(const std::string& tool_name,
                       const std::unordered_map<std::string, CacheEntry>& cache) {
  if (!EnsureDir(CacheDir())) return false;
  std::string path = CacheFilePath(tool_name);
  std::string tmp_path = path + ".tmp." + std::to_string(getpid());
  FILE* f = fopen(tmp_path.c_str(), "wb");
  if (!f) return false;
  fprintf(f, "{\n");
  bool first_entry = true;
  for (const auto& [key, entry] : cache) {
    if (!first_entry) fprintf(f, ",\n");
    first_entry = false;
    fprintf(f, "  \"%s\": {\n", key.c_str());
    fprintf(f, "    \"exe\": \"%s\",\n", JsonEscape(entry.exe).c_str());
    fprintf(f, "    \"size\": %lld,\n", (long long)entry.size);
    fprintf(f, "    \"mtime\": %lld,\n", (long long)entry.mtime);
    fprintf(f, "    \"fields\": {");
    bool first_field = true;
    for (const auto& [fkey, fval] : entry.fields) {
      if (!first_field) fprintf(f, ", ");
      first_field = false;
      fprintf(f, "\"%s\": %lld", fkey.c_str(), (long long)fval);
    }
    fprintf(f, "}\n  }");
  }
  fprintf(f, "\n}\n");
  fclose(f);
  if (rename(tmp_path.c_str(), path.c_str()) != 0) {
    remove(tmp_path.c_str());
    return false;
  }
  return true;
}

}  // namespace calib_cache
