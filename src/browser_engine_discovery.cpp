// Linux browser-engine process discovery. This intentionally does not scan
// process memory or URLs; it inventories executable artifacts visible in
// /proc and records the evidence used to recognize supported engine families.
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cctype>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <fcntl.h>
#include <iomanip>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

namespace {

constexpr uint64_t kDefaultArtifactBudget = 128ULL * 1024 * 1024;
constexpr uint64_t kDefaultSweepBudget = 1024ULL * 1024 * 1024;
constexpr size_t kMaxReportedGaps = 256;

std::atomic<bool> g_stop(false);

struct Options {
  std::string proc_root = "/proc";
  bool watch = false;
  unsigned interval_seconds = 5;
  uint64_t artifact_budget = kDefaultArtifactBudget;
  uint64_t sweep_budget = kDefaultSweepBudget;
};

struct ProcessMeta {
  int pid = 0;
  int ppid = 0;
  uint64_t start_time = 0;
  std::string exe;
  std::string command_line;
};

struct Evidence {
  std::string kind;
  std::string detail;
};

struct FamilyFinding {
  std::string family;
  std::string status;
  std::vector<Evidence> evidence;
};

struct ArtifactFinding {
  std::string identity;
  std::string display_path;
  bool complete = true;
  std::vector<FamilyFinding> families;
};

struct ProcessFinding {
  ProcessMeta meta;
  std::string role = "unknown";
  std::vector<ArtifactFinding> artifacts;
  std::vector<FamilyFinding> associated;
  std::vector<std::string> relationships;
};

struct Gap {
  int pid;
  std::string stage;
  std::string reason;
};

struct Sweep {
  std::string started;
  std::string finished;
  size_t enumerated = 0;
  size_t inspected = 0;
  size_t unknown_processes = 0;
  size_t cache_hits = 0;
  size_t total_gaps = 0;
  size_t access_denied = 0;
  size_t disappeared = 0;
  uint64_t bytes_read = 0;
  bool budget_exhausted = false;
  std::vector<Gap> gaps;
  std::map<std::string, std::string> unrecognized_artifacts;
  std::map<std::string, std::string> incomplete_artifacts;
  std::vector<ProcessFinding> findings;
};

struct CacheEntry {
  ArtifactFinding finding;
};

using Cache = std::map<std::string, CacheEntry>;

std::string JoinPath(const std::string& a, const std::string& b) {
  return a + (a.empty() || a.back() == '/' ? "" : "/") + b;
}

std::string Json(const std::string& value) {
  std::ostringstream out;
  out << '"';
  for (unsigned char c : value) {
    switch (c) {
      case '"': out << "\\\""; break;
      case '\\': out << "\\\\"; break;
      case '\b': out << "\\b"; break;
      case '\f': out << "\\f"; break;
      case '\n': out << "\\n"; break;
      case '\r': out << "\\r"; break;
      case '\t': out << "\\t"; break;
      default:
        if (c < 0x20) {
          out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
              << static_cast<int>(c) << std::dec;
        } else {
          out << c;
        }
    }
  }
  out << '"';
  return out.str();
}

std::string IsoNow() {
  auto now = std::chrono::system_clock::now();
  std::time_t value = std::chrono::system_clock::to_time_t(now);
  struct tm utc {};
  gmtime_r(&value, &utc);
  char buffer[32];
  strftime(buffer, sizeof(buffer), "%Y-%m-%dT%H:%M:%SZ", &utc);
  return buffer;
}

bool IsPid(const char* name) {
  if (!name || !*name) return false;
  for (const char* p = name; *p; ++p)
    if (*p < '0' || *p > '9') return false;
  return true;
}

bool ReadAll(const std::string& path, std::string* out) {
  int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) return false;
  char buffer[4096];
  out->clear();
  for (;;) {
    ssize_t count = read(fd, buffer, sizeof(buffer));
    if (count > 0) out->append(buffer, static_cast<size_t>(count));
    else if (count == 0) break;
    else if (errno != EINTR) { close(fd); return false; }
  }
  close(fd);
  return true;
}

std::string ReadLink(const std::string& path) {
  std::vector<char> buffer(256);
  for (;;) {
    ssize_t size = readlink(path.c_str(), buffer.data(), buffer.size());
    if (size < 0) return "";
    if (static_cast<size_t>(size) < buffer.size())
      return std::string(buffer.data(), static_cast<size_t>(size));
    buffer.resize(buffer.size() * 2);
  }
}

bool ReadMeta(const Options& options, int pid, ProcessMeta* meta, int* error) {
  std::string base = JoinPath(options.proc_root, std::to_string(pid));
  std::string stat;
  if (!ReadAll(JoinPath(base, "stat"), &stat)) {
    *error = errno;
    return false;
  }
  size_t close = stat.rfind(')');
  if (close == std::string::npos || close + 2 >= stat.size()) {
    *error = EINVAL;
    return false;
  }
  std::istringstream fields(stat.substr(close + 2));
  std::vector<std::string> values;
  std::string value;
  while (fields >> value) values.push_back(value);
  // values[0] is field 3 (state), values[1] field 4 (ppid), and values[19]
  // field 22 (starttime).
  if (values.size() <= 19) { *error = EINVAL; return false; }
  try {
    meta->pid = pid;
    meta->ppid = std::stoi(values[1]);
    meta->start_time = std::stoull(values[19]);
  } catch (...) {
    *error = EINVAL;
    return false;
  }
  meta->exe = ReadLink(JoinPath(base, "exe"));
  std::string command;
  if (ReadAll(JoinPath(base, "cmdline"), &command)) {
    std::replace(command.begin(), command.end(), '\0', ' ');
    while (!command.empty() && command.back() == ' ') command.pop_back();
    meta->command_line = command;
  }
  return true;
}

std::string ErrorKind(int error) {
  if (error == EACCES || error == EPERM) return "access-denied";
  if (error == ENOENT || error == ESRCH) return "disappeared";
  return std::string("error: ") + strerror(error);
}

void AddGap(Sweep* sweep, int pid, const std::string& stage, int error) {
  ++sweep->total_gaps;
  if (error == EACCES || error == EPERM) ++sweep->access_denied;
  if (error == ENOENT || error == ESRCH) ++sweep->disappeared;
  if (sweep->gaps.size() < kMaxReportedGaps)
    sweep->gaps.push_back({pid, stage, ErrorKind(error)});
}

std::string Lower(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return value;
}

std::string BaseName(const std::string& path) {
  size_t slash = path.rfind('/');
  return slash == std::string::npos ? path : path.substr(slash + 1);
}

std::string FileIdentity(const struct stat& st) {
  std::ostringstream out;
  out << std::hex << static_cast<uint64_t>(st.st_dev) << ':'
      << static_cast<uint64_t>(st.st_ino) << std::dec << ':'
      << static_cast<uint64_t>(st.st_size) << ':'
      << static_cast<int64_t>(st.st_mtim.tv_sec) << '.' << st.st_mtim.tv_nsec << ':'
      << static_cast<int64_t>(st.st_ctim.tv_sec) << '.' << st.st_ctim.tv_nsec;
  return out.str();
}

bool Contains(const std::vector<unsigned char>& bytes, const std::string& needle) {
  if (needle.empty() || bytes.size() < needle.size()) return false;
  return std::search(bytes.begin(), bytes.end(), needle.begin(), needle.end()) != bytes.end();
}

struct Signature {
  const char* family;
  const char* first;
  const char* second;
};

// Keep the complete markers out of this detector's own binary. Otherwise a
// process running the detector would appear to contain all three engines.
const Signature kSignatures[] = {
  {"blink/chromium", "Chrome_", "RendererMain"},
  {"blink/chromium", "ContentMain", "Runner"},
  {"blink/chromium", "content::", "ContentMain"},
  {"blink/chromium", "blink::", "Web"},
  {"blink/chromium", "cef_execute_", "process"},
  {"blink/chromium", "QtWebEngine", "Core"},
  {"gecko", "XRE_", "Main"},
  {"gecko", "XRE", "Main"},
  {"gecko", "NS_Init", "XPCOM2"},
  {"gecko", "nsStandard", "URL"},
  {"gecko", "GeckoChild", "ProcessHost"},
  {"gecko", "XRE_Get", "Bootstrap"},
  {"gecko", "SetGecko", "ProcessType"},
  {"gecko", "mozilla::", "dom::"},
  {"webkit", "WebKitWeb", "ProcessMain"},
  {"webkit", "WebKitNetwork", "Process"},
  {"webkit", "WebProcess", "Pool"},
  {"webkit", "WebCore", "::"},
  {"webkit", "WTF::", "URL"},
  {"webkit", "webkit_web_", "view"},
};

std::vector<std::string> NameCandidates(const std::string& path) {
  std::string name = Lower(BaseName(path));
  std::vector<std::string> result;
  auto add = [&](const std::string& family) {
    if (std::find(result.begin(), result.end(), family) == result.end()) result.push_back(family);
  };
  if (name.find("libcef") != std::string::npos ||
      name.find("qtwebengine") != std::string::npos ||
      name.find("chromium") != std::string::npos || name.find("chrome") != std::string::npos ||
      name.find("electron") != std::string::npos) add("blink/chromium");
  if (name.find("libxul") != std::string::npos || name.find("firefox") != std::string::npos ||
      name.find("gecko") != std::string::npos) add("gecko");
  if (name.find("webkit") != std::string::npos &&
      name.find("qtwebengine") == std::string::npos) add("webkit");
  return result;
}

ArtifactFinding AnalyzeArtifact(int fd, const std::string& path,
                                const struct stat& st, const Options& options,
                                uint64_t* remaining, Sweep* sweep) {
  ArtifactFinding result;
  result.identity = FileIdentity(st);
  result.display_path = path;
  uint64_t wanted = std::min<uint64_t>(static_cast<uint64_t>(st.st_size), options.artifact_budget);
  uint64_t allowed = std::min<uint64_t>(wanted, *remaining);
  std::vector<unsigned char> bytes(static_cast<size_t>(allowed));
  size_t done = 0;
  while (done < bytes.size()) {
    ssize_t count = pread(fd, bytes.data() + done, bytes.size() - done,
                          static_cast<off_t>(done));
    if (count > 0) done += static_cast<size_t>(count);
    else if (count < 0 && errno == EINTR) continue;
    else break;
  }
  bytes.resize(done);
  *remaining -= done;
  sweep->bytes_read += done;
  result.complete = done == static_cast<uint64_t>(st.st_size);
  if (!result.complete && (*remaining == 0 || wanted < static_cast<uint64_t>(st.st_size)))
    sweep->budget_exhausted = true;

  std::map<std::string, std::vector<Evidence>> found;
  // ELF magic is checked before interpreting binary markers. The scanner does
  // not trust a pathname to establish that an artifact is executable code.
  bool elf = bytes.size() >= 4 && bytes[0] == 0x7f && bytes[1] == 'E' &&
             bytes[2] == 'L' && bytes[3] == 'F';
  if (elf) {
    for (const Signature& signature : kSignatures) {
      std::string marker = std::string(signature.first) + signature.second;
      if (Contains(bytes, marker))
        found[signature.family].push_back({"binary-feature", marker});
    }
  }
  for (const std::string& family : NameCandidates(path))
    found[family].push_back({"name-lead", BaseName(path)});

  for (auto& item : found) {
    size_t binary_features = 0;
    for (const Evidence& evidence : item.second)
      if (evidence.kind == "binary-feature") ++binary_features;
    FamilyFinding finding;
    finding.family = item.first;
    finding.status = binary_features >= 2 ? "probable" : "candidate";
    finding.evidence = std::move(item.second);
    result.families.push_back(std::move(finding));
  }
  return result;
}

bool InspectFd(int fd, const std::string& path, const Options& options,
               uint64_t* remaining, Cache* cache, Sweep* sweep,
               ArtifactFinding* result) {
  struct stat st {};
  if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) return false;
  std::string identity = FileIdentity(st);
  auto cached = cache->find(identity);
  if (cached != cache->end()) {
    *result = cached->second.finding;
    result->display_path = path;
    ++sweep->cache_hits;
    return true;
  }
  uint64_t needed = std::min<uint64_t>(static_cast<uint64_t>(st.st_size),
                                       options.artifact_budget);
  bool cacheable = *remaining >= needed;
  *result = AnalyzeArtifact(fd, path, st, options, remaining, sweep);
  if (cacheable) (*cache)[identity] = {*result};
  return true;
}

struct Mapping {
  std::string range;
  std::string path;
  uint64_t device = 0;
  uint64_t inode = 0;
};

bool ReadMappings(const Options& options, int pid, std::vector<Mapping>* mappings,
                  bool* has_uninspectable_executable, int* error) {
  std::string base = JoinPath(JoinPath(options.proc_root, std::to_string(pid)), "maps");
  FILE* file = fopen(base.c_str(), "r");
  if (!file) { *error = errno; return false; }
  char* line = nullptr;
  size_t capacity = 0;
  while (getline(&line, &capacity, file) >= 0) {
    unsigned long long start = 0, end = 0, offset = 0, inode = 0;
    char perms[5] = {}, dev[32] = {}, path[4096] = {};
    int count = sscanf(line, "%llx-%llx %4s %llx %31s %llu %4095[^\n]",
                       &start, &end, perms, &offset, dev, &inode, path);
    if (count < 6 || strchr(perms, 'x') == nullptr) continue;
    if (inode == 0) {
      *has_uninspectable_executable = true;
      continue;
    }
    std::ostringstream range;
    range << std::hex << start << '-' << end;
    std::string display = count == 7 ? path : "";
    while (!display.empty() && display.front() == ' ') display.erase(display.begin());
    unsigned dev_major = 0, dev_minor = 0;
    if (sscanf(dev, "%x:%x", &dev_major, &dev_minor) != 2) continue;
    mappings->push_back({range.str(), display,
                         static_cast<uint64_t>(makedev(dev_major, dev_minor)), inode});
  }
  free(line);
  fclose(file);
  return true;
}

int OpenMapping(const std::string& process_dir, const Mapping& mapping) {
  std::string handle = JoinPath(JoinPath(process_dir, "map_files"), mapping.range);
  int fd = open(handle.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd >= 0) return fd;

  // map_files is permission-gated on some kernels. A path lookup through the
  // target's root is acceptable only if it still resolves to the exact device
  // and inode recorded in maps. This rejects deleted/replaced files.
  if (mapping.path.empty() || mapping.path.front() != '/' ||
      (mapping.path.size() >= 10 &&
       mapping.path.compare(mapping.path.size() - 10, 10, " (deleted)") == 0))
    return -1;
  std::string rooted = JoinPath(JoinPath(process_dir, "root"), mapping.path.substr(1));
  fd = open(rooted.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) return -1;
  struct stat st {};
  if (fstat(fd, &st) != 0 || static_cast<uint64_t>(st.st_dev) != mapping.device ||
      static_cast<uint64_t>(st.st_ino) != mapping.inode) {
    close(fd);
    errno = ESTALE;
    return -1;
  }
  return fd;
}

std::string InferRole(const ProcessMeta& meta) {
  std::string cmd = Lower(meta.command_line);
  auto has = [&](const char* value) { return cmd.find(value) != std::string::npos; };
  if (has("--type=renderer") || has("-contentproc") || has("webkitwebprocess"))
    return "renderer/content";
  if (has("--type=gpu-process") || has("webkitgpu")) return "gpu";
  if (has("--type=utility")) {
    if (has("network")) return "network";
    return "utility";
  }
  if (has("webkitnetworkprocess")) return "network";
  if (has("--type=")) return "supporting/unknown";
  return "controller-or-unknown";
}

std::vector<std::string> LocalFamilies(const ProcessFinding& finding) {
  std::vector<std::string> result;
  for (const ArtifactFinding& artifact : finding.artifacts)
    for (const FamilyFinding& family : artifact.families)
      if (std::find(result.begin(), result.end(), family.family) == result.end())
        result.push_back(family.family);
  return result;
}

void AddRelations(std::vector<ProcessFinding>* findings) {
  std::map<int, size_t> by_pid;
  for (size_t i = 0; i < findings->size(); ++i) by_pid[(*findings)[i].meta.pid] = i;
  size_t original_size = findings->size();
  for (size_t i = 0; i < original_size; ++i) {
    ProcessFinding& child = (*findings)[i];
    std::vector<std::string> families = LocalFamilies(child);
    if (families.empty() || child.meta.ppid <= 0) continue;
    auto parent_it = by_pid.find(child.meta.ppid);
    if (parent_it == by_pid.end()) continue;
    ProcessFinding& parent = (*findings)[parent_it->second];
    std::ostringstream relation;
    relation << "parent pid " << parent.meta.pid << " hosts engine-bearing child pid "
             << child.meta.pid;
    child.relationships.push_back(relation.str());
    parent.relationships.push_back(relation.str());
    std::vector<std::string> parent_local = LocalFamilies(parent);
    for (const std::string& family : families) {
      if (std::find(parent_local.begin(), parent_local.end(), family) == parent_local.end())
        parent.associated.push_back({family, "associated-only",
                                     {{"parentage", "direct engine-bearing child " +
                                                     std::to_string(child.meta.pid)}}});
    }
  }
}

Sweep RunSweep(const Options& options, Cache* cache) {
  Sweep sweep;
  sweep.started = IsoNow();
  DIR* directory = opendir(options.proc_root.c_str());
  if (!directory) {
    AddGap(&sweep, 0, "enumerate", errno);
    sweep.finished = IsoNow();
    return sweep;
  }
  std::vector<int> pids;
  while (dirent* entry = readdir(directory))
    if (IsPid(entry->d_name)) pids.push_back(atoi(entry->d_name));
  closedir(directory);
  std::sort(pids.begin(), pids.end());
  sweep.enumerated = pids.size();
  uint64_t remaining = options.sweep_budget;

  // Keep all successfully inspected processes until relationships have been
  // derived. Unknowns are omitted from results but counted in coverage.
  for (int pid : pids) {
    ProcessMeta before;
    int error = 0;
    if (!ReadMeta(options, pid, &before, &error)) {
      AddGap(&sweep, pid, "metadata", error);
      continue;
    }
    std::string process_dir = JoinPath(options.proc_root, std::to_string(pid));
    ProcessFinding finding;
    finding.meta = before;
    finding.role = InferRole(before);
    std::set<std::string> identities;

    int exe_fd = open(JoinPath(process_dir, "exe").c_str(), O_RDONLY | O_CLOEXEC);
    if (exe_fd >= 0) {
      ArtifactFinding artifact;
      if (InspectFd(exe_fd, before.exe, options, &remaining, cache, &sweep, &artifact)) {
        identities.insert(artifact.identity);
        if (!artifact.complete)
          sweep.incomplete_artifacts.emplace(artifact.identity, artifact.display_path);
        if (artifact.families.empty())
          sweep.unrecognized_artifacts.emplace(artifact.identity, artifact.display_path);
        finding.artifacts.push_back(std::move(artifact));
      }
      close(exe_fd);
    } else {
      AddGap(&sweep, pid, "executable", errno);
    }

    std::vector<Mapping> mappings;
    bool anonymous_executable = false;
    if (!ReadMappings(options, pid, &mappings, &anonymous_executable, &error)) {
      AddGap(&sweep, pid, "maps", error);
      continue;
    }
    if (anonymous_executable)
      AddGap(&sweep, pid, "executable-mapping", ENOTSUP);
    std::set<std::pair<uint64_t, uint64_t>> mapped_files;
    for (const Mapping& mapping : mappings) {
      if (!mapped_files.insert({mapping.device, mapping.inode}).second) continue;
      int fd = OpenMapping(process_dir, mapping);
      if (fd < 0) {
        AddGap(&sweep, pid, "mapped-artifact", errno);
        continue;
      }
      ArtifactFinding artifact;
      if (InspectFd(fd, mapping.path, options, &remaining, cache, &sweep, &artifact) &&
          identities.insert(artifact.identity).second) {
        if (!artifact.complete)
          sweep.incomplete_artifacts.emplace(artifact.identity, artifact.display_path);
        if (artifact.families.empty())
          sweep.unrecognized_artifacts.emplace(artifact.identity, artifact.display_path);
        finding.artifacts.push_back(std::move(artifact));
      }
      close(fd);
    }

    ProcessMeta after;
    if (!ReadMeta(options, pid, &after, &error) || after.start_time != before.start_time) {
      AddGap(&sweep, pid, "identity-revalidation", error ? error : ESTALE);
      continue;
    }
    ++sweep.inspected;
    bool recognized = false;
    for (const ArtifactFinding& artifact : finding.artifacts)
      if (!artifact.families.empty()) recognized = true;
    if (!recognized) ++sweep.unknown_processes;
    sweep.findings.push_back(std::move(finding));
  }
  AddRelations(&sweep.findings);
  sweep.findings.erase(
      std::remove_if(sweep.findings.begin(), sweep.findings.end(),
                     [](const ProcessFinding& finding) {
                       bool local = false;
                       for (const ArtifactFinding& artifact : finding.artifacts)
                         if (!artifact.families.empty()) local = true;
                       return !local && finding.associated.empty();
                     }),
      sweep.findings.end());
  sweep.finished = IsoNow();
  return sweep;
}

void PrintEvidence(const std::vector<Evidence>& evidence) {
  std::cout << '[';
  for (size_t i = 0; i < evidence.size(); ++i) {
    if (i) std::cout << ',';
    std::cout << "{\"kind\":" << Json(evidence[i].kind)
              << ",\"detail\":" << Json(evidence[i].detail) << '}';
  }
  std::cout << ']';
}

void PrintFamily(const FamilyFinding& family) {
  std::cout << "{\"family\":" << Json(family.family)
            << ",\"status\":" << Json(family.status) << ",\"evidence\":";
  PrintEvidence(family.evidence);
  std::cout << '}';
}

void PrintSweep(const Sweep& sweep, const Options& options,
                const std::map<std::string, std::pair<std::string, std::string>>& observed) {
  std::cout << "{\"mode\":" << Json(options.watch ? "watch" : "snapshot")
            << ",\"visibility_scope\":{\"proc_root\":" << Json(options.proc_root)
            << ",\"claim\":\"visible processes only; container/permission boundaries may hide others\"}"
            << ",\"started_at\":" << Json(sweep.started)
            << ",\"finished_at\":" << Json(sweep.finished)
            << ",\"coverage\":{\"processes_enumerated\":" << sweep.enumerated
            << ",\"processes_inspected\":" << sweep.inspected
            << ",\"unknown_processes\":" << sweep.unknown_processes
            << ",\"unrecognized_artifacts\":" << sweep.unrecognized_artifacts.size()
            << ",\"incomplete_artifacts\":" << sweep.incomplete_artifacts.size()
            << ",\"cache_hits\":" << sweep.cache_hits
            << ",\"artifact_bytes_read\":" << sweep.bytes_read
            << ",\"analysis_budget_exhausted\":" << (sweep.budget_exhausted ? "true" : "false")
            << ",\"access_denied\":" << sweep.access_denied
            << ",\"disappeared\":" << sweep.disappeared
            << ",\"gap_count\":" << sweep.total_gaps
            << ",\"reported_gap_count\":" << sweep.gaps.size()
            << ",\"gaps_truncated\":"
            << (sweep.total_gaps > sweep.gaps.size() ? "true" : "false")
            << "},\"inspection_gaps\":[";
  for (size_t i = 0; i < sweep.gaps.size(); ++i) {
    if (i) std::cout << ',';
    std::cout << "{\"pid\":" << sweep.gaps[i].pid
              << ",\"stage\":" << Json(sweep.gaps[i].stage)
              << ",\"reason\":" << Json(sweep.gaps[i].reason) << '}';
  }
  auto print_artifact_list = [](const std::map<std::string, std::string>& artifacts) {
    std::cout << '[';
    bool first = true;
    for (const auto& artifact : artifacts) {
      if (!first) std::cout << ',';
      first = false;
      std::cout << "{\"identity\":" << Json(artifact.first)
                << ",\"observed_path\":" << Json(artifact.second) << '}';
    }
    std::cout << ']';
  };
  std::cout << "],\"unrecognized_artifacts\":";
  print_artifact_list(sweep.unrecognized_artifacts);
  std::cout << ",\"incomplete_artifacts\":";
  print_artifact_list(sweep.incomplete_artifacts);
  std::cout << ",\"processes\":[";
  for (size_t i = 0; i < sweep.findings.size(); ++i) {
    if (i) std::cout << ',';
    const ProcessFinding& finding = sweep.findings[i];
    std::string key = std::to_string(finding.meta.pid) + ":" + std::to_string(finding.meta.start_time);
    auto times = observed.find(key);
    std::cout << "{\"pid\":" << finding.meta.pid
              << ",\"start_time_ticks\":" << finding.meta.start_time
              << ",\"ppid\":" << finding.meta.ppid
              << ",\"executable\":" << Json(finding.meta.exe)
              << ",\"command_line\":" << Json(finding.meta.command_line)
              << ",\"role\":{\"value\":" << Json(finding.role)
              << ",\"status\":\"inferred\"}";
    if (times != observed.end())
      std::cout << ",\"first_observed_at\":" << Json(times->second.first)
                << ",\"last_observed_at\":" << Json(times->second.second);
    std::cout << ",\"artifacts\":[";
    bool first_artifact = true;
    for (const ArtifactFinding& artifact : finding.artifacts) {
      if (artifact.families.empty()) continue;
      if (!first_artifact) std::cout << ',';
      first_artifact = false;
      std::cout << "{\"identity\":" << Json(artifact.identity)
                << ",\"observed_path\":" << Json(artifact.display_path)
                << ",\"analysis_complete\":" << (artifact.complete ? "true" : "false")
                << ",\"engines\":[";
      for (size_t j = 0; j < artifact.families.size(); ++j) {
        if (j) std::cout << ',';
        PrintFamily(artifact.families[j]);
      }
      std::cout << "]}";
    }
    std::cout << "],\"associated_engines\":[";
    for (size_t j = 0; j < finding.associated.size(); ++j) {
      if (j) std::cout << ',';
      PrintFamily(finding.associated[j]);
    }
    std::cout << "],\"relationships\":[";
    for (size_t j = 0; j < finding.relationships.size(); ++j) {
      if (j) std::cout << ',';
      std::cout << Json(finding.relationships[j]);
    }
    std::cout << "]}";
  }
  std::cout << "]}\n";
}

uint64_t Mib(const char* value) {
  char* end = nullptr;
  unsigned long long parsed = strtoull(value, &end, 10);
  if (!value[0] || !end || *end || parsed > UINT64_MAX / (1024 * 1024)) return 0;
  return parsed * 1024 * 1024;
}

void Usage(const char* argv0) {
  std::cerr << "usage: " << argv0
            << " [--watch] [--interval SECONDS] [--artifact-budget-mib MIB]"
               " [--sweep-budget-mib MIB] [--proc-root PATH]\n";
}

bool ParseOptions(int argc, char** argv, Options* options) {
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    auto next = [&]() -> const char* { return ++i < argc ? argv[i] : nullptr; };
    if (arg == "--watch") options->watch = true;
    else if (arg == "--interval") {
      const char* value = next();
      if (!value || !(options->interval_seconds = static_cast<unsigned>(atoi(value)))) return false;
    } else if (arg == "--artifact-budget-mib") {
      const char* value = next();
      if (!value || !(options->artifact_budget = Mib(value))) return false;
    } else if (arg == "--sweep-budget-mib") {
      const char* value = next();
      if (!value || !(options->sweep_budget = Mib(value))) return false;
    } else if (arg == "--proc-root") {
      const char* value = next();
      if (!value) return false;
      options->proc_root = value;
    } else if (arg == "--help" || arg == "-h") {
      Usage(argv[0]);
      exit(0);
    } else return false;
  }
  return true;
}

void Stop(int) { g_stop.store(true); }

}  // namespace

int main(int argc, char** argv) {
  Options options;
  if (!ParseOptions(argc, argv, &options)) {
    Usage(argv[0]);
    return 2;
  }
  signal(SIGINT, Stop);
  signal(SIGTERM, Stop);
  Cache cache;
  std::map<std::string, std::pair<std::string, std::string>> observed;
  do {
    Sweep sweep = RunSweep(options, &cache);
    if (options.watch) {
      for (const ProcessFinding& finding : sweep.findings) {
        std::string key = std::to_string(finding.meta.pid) + ":" +
                          std::to_string(finding.meta.start_time);
        auto inserted = observed.emplace(key, std::make_pair(sweep.started, sweep.finished));
        if (!inserted.second) inserted.first->second.second = sweep.finished;
      }
    }
    PrintSweep(sweep, options, observed);
    std::cout.flush();
    if (!options.watch) break;
    for (unsigned i = 0; i < options.interval_seconds * 10 && !g_stop.load(); ++i)
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
  } while (!g_stop.load());
  return 0;
}
