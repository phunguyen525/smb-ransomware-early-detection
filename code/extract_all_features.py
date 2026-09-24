#!/usr/bin/env python3
"""
extract_all_features.py — feature library for the sliding-window pipeline.

Not run directly. extract_sliding.py imports it for the API groups, the path
classification, the process-tree selection and the pcap parsing; the 42 features
themselves are assembled there.
"""
import math, re, subprocess
from collections import Counter, defaultdict
from datetime import datetime

# Normalise a call's arguments to a dict, whichever shape CAPE wrote them in.
def get_args(call):
    """CAPE writes call arguments either as a dict or as a list of {name, value}."""
    a = call.get("arguments", [])
    if isinstance(a, dict): return a
    out = {}
    for x in a:
        if isinstance(x, dict): out[x.get("name")] = x.get("value")
    return out


# cmd.exe is deliberately absent: a benign workload is a .bat, so cmd.exe IS the
# submitted sample and the work happens in the tools it spawns.
SYSTEM_PROCS = {"explorer.exe","svchost.exe","services.exe","lsass.exe","csrss.exe",
                "winlogon.exe","smss.exe","wininit.exe","dwm.exe","sihost.exe",
                "runtimebroker.exe","taskhostw.exe","ctfmon.exe","fontdrvhost.exe",
                "audiodg.exe","spoolsv.exe","searchapp.exe","searchindexer.exe",
                "shellexperiencehost.exe","startmenuexperiencehost.exe","textinputhost.exe",
                "backgroundtaskhost.exe","sppsvc.exe","dashost.exe","taskeng.exe",
                "msdtc.exe","wmiprvse.exe","wmiadap.exe","werfault.exe","wercon.exe",
                "wermgr.exe","microsoftedgeupdate.exe","smartscreen.exe","mobsync.exe",
                "securityhealthhost.exe","slui.exe","conhost.exe","dllhost.exe",
                "musnotification.exe","musnotificationux.exe","unsecapp.exe"}

# Convert a CAPE timestamp string to epoch seconds; None if it cannot be parsed.
def parse_ts(s):
    """CAPE timestamps are 'YYYY-MM-DD HH:MM:SS,mmm', not epoch floats."""
    try:
        base = datetime.strptime(s[:19], "%Y-%m-%d %H:%M:%S")
        ms = float("0." + s.split(",")[1]) if "," in s else 0.0
        return base.timestamp() + ms
    except Exception:
        return None

# Sort key for merging calls from several processes in time order.
def _call_time(c):
    t = parse_ts(c.get("timestamp", ""))
    return t if t is not None else 0.0

# Merge the whole submitted process tree into one call list.
def pick_malware_process(d):
    """The whole submitted process tree, merged into one call list in timestamp order.
    """
    b = d.get("behavior", {})
    procs = [p for p in (b.get("processes") or []) if p.get("calls")]
    if not procs:
        return {"calls": [], "process_name": "", "process_id": 0}

    by_pid = {p.get("process_id"): p for p in procs}
    children = {}
    for p in procs:
        children.setdefault(p.get("parent_id"), []).append(p)

    def is_sys(p): return (p.get("process_name", "") or "").lower() in SYSTEM_PROCS

    target = (d.get("info") or {}).get("target", {})
    tname = ""
    if isinstance(target, dict):
        f = target.get("file")
        if isinstance(f, dict):
            tname = (f.get("name") or "").lower()
    seed = None
    if tname:
        m = [p for p in procs if (p.get("process_name", "") or "").lower() == tname]
        if m: seed = max(m, key=lambda p: len(p.get("calls", [])))
    if seed is None:
        ns = [p for p in procs if not is_sys(p)]
        seed = max(ns or procs, key=lambda p: len(p.get("calls", [])))

    root, seen = seed, {seed.get("process_id")}
    while True:
        par = by_pid.get(root.get("parent_id"))
        if par is None or is_sys(par) or par.get("process_id") in seen: break
        seen.add(par.get("process_id")); root = par

    tree, stack = [], [root]
    while stack:
        p = stack.pop()
        tree.append(p)
        for ch in children.get(p.get("process_id"), []):
            if ch.get("process_id") not in {q.get("process_id") for q in tree}:
                stack.append(ch)

    if len(tree) == 1:
        return root

    merged = []
    for p in tree: merged.extend(p.get("calls") or [])
    merged.sort(key=_call_time)
    return {"calls": merged,
            "process_name": root.get("process_name", ""),
            "process_id": root.get("process_id", 0),
            "merged_from": [p.get("process_name", "") for p in tree]}


# ══════════════════════════ path classification ═══════════════════════════════

# The NapierOne naming scheme, NNNN-type_rN_NNNN.ext. A file whose name matches this
# and carries extra characters after it has had a suffix appended by a sample.
_NAPIER_FALLBACK = re.compile(r'\d{4}-[a-z0-9]+_r\d+_\d+\.[a-z0-9]{1,6}', re.IGNORECASE)

# The filename at the end of a path, whichever slash it uses.
def _path_basename(v):
    v2 = v.replace("/", "\\")
    return v2.rsplit("\\", 1)[-1] if "\\" in v2 else v2


# Argument names that hold a filesystem path. Buffer above all is excluded: it may
# merely contain a path as data. A benign workload runs `dir /b /s "Z:\2022\*.*"` and
# cmd.exe writes the listing to a pipe through NtWriteFile, so every one of those
# writes carries a corpus filename in its Buffer. 
PATH_ARG_KEYS = {"FileName", "HandleName", "FilePath", "DirectoryName", "PathName",
                 "ExistingFileName", "NewFileName", "OriginalFileName", "lpFileName",
                 "ObjectAttributes", "DestinationPath", "SourcePath", "TargetFileName",
                 "ApplicationName", "ImagePathName"}

# The argument values that are paths, filtered by parameter name.
def path_args(args):
    """Argument values that are paths, not payloads carrying a path."""
    return [v for k, v in args.items() if k in PATH_ARG_KEYS and isinstance(v, str)]

# Classify where a path points: the share, local storage, or neither.
def path_drive(v):
    """'Z' for the share, 'C' for local storage, None otherwise.

    The share is reached either as a mapped drive or through a UNC form, and both
    must classify as 'Z': Hive addresses it only as \\Device\\Mup\\. The bare Win32
    \\\\server\\share form is deliberately not matched, since raw binary arguments are
    repr'd starting with two backslashes and would false-positive.
    """
    if not isinstance(v, str): return None
    vl = v.lower().replace("/", "\\")
    if vl.startswith("z:") or vl.startswith("\\??\\z:"):     return "Z"
    if "\\device\\mup\\" in vl:                              return "Z"
    if "\\??\\unc\\" in vl or vl.startswith("\\\\?\\unc\\"): return "Z"
    if vl.startswith("c:") or vl.startswith("\\??\\c:"):     return "C"
    return None

# True when a corpus filename has had a ransom suffix appended.
def is_encrypted_path(v):
    """A corpus file whose name has had a suffix appended."""
    if not isinstance(v, str): return False
    if path_drive(v) is None: return False
    base = _path_basename(v)
    m = _NAPIER_FALLBACK.search(base)
    if not m: return False
    return len(base) > m.end()

# The drive of an encrypted corpus file, or None if the path is not one.
def encrypted_drive(v):
    if not is_encrypted_path(v): return None
    return path_drive(v)

# True for the filenames families use for their ransom notes.
def _is_ransom_note(fn):
    f = fn.lower()
    return any(k in f for k in ("readme", "info.txt", "info.hta", "how to", "recover",
                                "decrypt", "restore", "!!!", "return files",
                                "files encrypted", "_readme"))

# True for a corpus data file on either drive, excluding ransom notes.
def _is_napier_data_path(v):
    """A corpus data file on either drive -- not a ransom note."""
    if not isinstance(v, str): return False
    if path_drive(v) is None: return False
    base = _path_basename(v)
    if _is_ransom_note(base): return False
    return bool(_NAPIER_FALLBACK.search(base))

# Key that matches a read and a later write of the same file.
def _rbo_key(p):
    """Identity key for read-before-overwrite: (drive, basename).

    path_drive collapses UNC and mapped-Z into one, so a UNC read matches a
    mapped-drive rename of the same file. A read on C: and a write on Z: -- robocopy
    copying -- give different keys and correctly do not match.
    """
    dr = path_drive(p)
    if dr is None: return None
    return (dr, _path_basename(p).lower())


# ══════════════════════════ buffer entropy ════════════════════════════════════
# Decode CAPE's escaped Buffer string back to raw bytes.
def _unescape_buf(s):
    """Raw bytes from CAPE's escaped Buffer string."""
    if not isinstance(s, str) or not s: return b""
    out = bytearray(); i = 0; L = len(s)
    while i < L:
        c = s[i]
        if c == '\\' and i + 1 < L:
            n = s[i + 1]
            if n == 'x' and i + 3 < L:
                try:
                    out.append(int(s[i + 2:i + 4], 16)); i += 4; continue
                except ValueError:
                    pass
            m = {'n': 10, 't': 9, 'r': 13, '\\': 92}
            if n in m: out.append(m[n]); i += 2; continue
        out.append(ord(c) & 0xff); i += 1
    return bytes(out)

# Shannon entropy of one I/O buffer, in bits per byte.
def _buf_entropy(s, minbytes=16):
    """Shannon entropy of an I/O buffer. None if too few bytes were captured.

    CAPE truncates buffers to roughly 256 bytes, which is enough to separate
    ciphertext from plaintext. Measuring the buffer rather than the resulting file
    is what makes the signal survive intermittent encryption.
    """
    b = _unescape_buf(s)
    if len(b) < minbytes: return None
    cnt = Counter(b); tot = len(b)
    return -sum((n / tot) * math.log2(n / tot) for n in cnt.values())


def mean(xs):
    xs = [x for x in xs if x is not None]
    return sum(xs) / len(xs) if xs else 0.0


# ══════════════════════════ tshark ════════════════════════════════════════════
# Run tshark and return one list of field values per frame.
def tshark(pcap, fields, dfilter=None, timeout=900):
    cmd = ["tshark", "-r", pcap, "-T", "fields", "-E", "separator=|"]
    if dfilter: cmd += ["-Y", dfilter]
    for f in fields: cmd += ["-e", f]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=timeout)
        rows = []
        for line in out.decode(errors="ignore").splitlines():
            parts = line.split("|")
            while len(parts) < len(fields): parts.append("")
            rows.append(parts)
        return rows
    except Exception:
        return []

# String to int
def si(s):
    try: return int(s.strip(), 0)
    except Exception: return 0

# String to float
def sf(s):
    try: return float(s.strip())
    except Exception: return 0.0


# ══════════════════════════ API groups ════════════════════════════════════════

KEYGEN = {"CryptGenKey","CryptAcquireContext","CryptAcquireContextA","CryptAcquireContextW",
          "BCryptGenerateSymmetricKey","BCryptGenerateKeyPair","CryptImportKey",
          "CryptDeriveKey","BCryptImportKey"}

# The map/unmap cycle alone. A family that maps a file, transforms the bytes with CPU
# instructions and unmaps issues no write call, so this is the only trace it leaves.
MMAP = {"NtMapViewOfSection","NtMapViewOfSectionEx",
        "NtUnmapViewOfSection","NtUnmapViewOfSectionEx"}

HANDLE_ENUM = {"NtQuerySystemInformation","CreateToolhelp32Snapshot","Process32FirstW",
               "Process32NextW","NtQueryObject","GetHandleInformation","NtDuplicateObject",
               "Thread32First","Thread32Next"}

THREAD = {"NtCreateThreadEx","CreateThread","RtlCreateUserThread","CreateRemoteThread",
          "CreateRemoteThreadEx","NtCreateThread"}

# Presence alone is the signal. NtAllocateVirtualMemory without the Ex suffix is
# excluded: every allocation in every process calls it.
INJECT = {"WriteProcessMemory","NtWriteVirtualMemory","VirtualAllocEx",
          "NtAllocateVirtualMemoryEx","QueueUserAPC","NtQueueApcThread",
          "NtQueueApcThreadEx","SetThreadContext","NtSetContextThread"}

# Conditional. NtProtectVirtualMemory is called by the CRT, the loader and every JIT,
# so counting the bare API made the injection flag constant across both classes. Only
# a write-and-execute protection counts.
INJECT_RWX = {"NtProtectVirtualMemory","VirtualProtectEx","NtProtectVirtualMemoryEx"}

# True when a memory-protection call requests write-and-execute.
def _is_rwx_protect(args):
    """True for PAGE_EXECUTE_READWRITE (0x40) or PAGE_EXECUTE_WRITECOPY (0x80).
    CAPE logs the value either as a name or as a number."""
    for k in ("Protection", "NewAccessProtection", "NewProtect", "flProtect", "Win32Protect"):
        v = args.get(k)
        if v is None: continue
        s = str(v).strip().lower()
        if s in ("64", "128"): return True
        if any(t in s for t in ("execute_readwrite", "executereadwrite",
                                "execute_writecopy", "executewritecopy",
                                "0x40", "0x80", "rwx")): return True
    return False



NTWRITE = {"NtWriteFile","WriteFile"}
NTREAD  = {"NtReadFile","ReadFile"}

TRAVERSAL = {"FindFirstFileW","FindFirstFileA","FindFirstFileExW","FindNextFileW",
             "FindNextFileA","NtQueryDirectoryFile","NtQueryDirectoryFileEx"}

REG_WRITE = {"RegSetValueExW","RegSetValueExA","RegCreateKeyExW","RegCreateKeyExA",
             "NtSetValueKey","RegSetKeyValueW","NtCreateKey"}

RENAME = {"MoveFileWithProgressW","MoveFileWithProgressExW","MoveFileWithProgressTransactedW",
          "MoveFileW","MoveFileA","MoveFileExW","MoveFileTransactedW","MoveFileTransactedA",
          "NtSetInformationFile","SetFileInformationByHandle"}

DELETE = {"DeleteFileW","DeleteFileA","NtDeleteFile","SetFileDispositionInformation"}



# ══════════════════════════ SMB2 ══════════════════════════════════════════════

# Commands carrying no data payload. Opening, closing and querying a file transfer no
# content, so counting them recovers the file count that byte volume conceals.
SHORT_CMDS = {0, 1, 2, 3, 4, 5, 6, 7, 11, 12, 13, 14, 16, 17}

SMB_CREATE = 5
SMB_QUERYDIR, SMB_SETINFO = 14, 17
INFO_RENAME, INFO_DISPOSITION = 0x0a, 0x0d

# Align the capture clock to the host trace by matching a shared filename.
def pcap_host_offset(pcap, calls, ef_parse_ts=None, want=20):
    """The capture epoch corresponding to t=0 of the host trace.

    The two sensors run on different clocks: API calls carry the guest's, the capture
    carries the analysis host's. The guest reverts to a snapshot before every run and
    its clock resumes from whatever it read when the snapshot was taken, so the offset
    is neither the timezone difference nor constant -- measured from five to thirty-one
    seconds, and differing systematically between benign and ransomware because they
    were detonated in different batches. Subtracting a fixed offset does not align them.

    A single event visible to both does. When the sample opens a corpus file on the
    share, the host records the path and the capture records an SMB2 CREATE carrying
    the same basename; the median difference over the first few such files gives an
    offset good to a few tens of milliseconds, independent of either clock's absolute
    value.

    Returns None when no shared filename can be matched, which happens for samples
    that never touch the share and whose network features are empty anyway.
    """
    if not calls: return None
    pt = ef_parse_ts or parse_ts
    t0 = pt(calls[0].get("timestamp", ""))
    if t0 is None: return None

    # The whole trace is scanned, not a prefix: a 7-Zip run reaches its first corpus
    # file on the share at call 7,664 of 51,346. Any API that names a file will do --
    # a batch rename loop appears as MoveFileWithProgressTransactedW and a deletion as
    # DeleteFileW, and requiring the NapierOne pattern would lose names that already
    # carry an appended extension.
    NAMED = ("NtCreateFile", "NtOpenFile", "DeleteFileW", "NtDeleteFile",
             "MoveFileWithProgressW", "MoveFileWithProgressTransactedW",
             "NtSetInformationFile", "CopyFileW", "CopyFileExW")
    host_first = {}
    for c in calls:
        if c.get("api") not in NAMED: continue
        ts = pt(c.get("timestamp", ""))
        if ts is None: continue
        for v in path_args(get_args(c)):
            if path_drive(v) != "Z": continue
            b = v.replace("/", "\\").split("\\")[-1]
            if not b or "*" in b or "?" in b: continue     # wildcards never appear on the wire
            if b not in host_first: host_first[b] = ts - t0
            break
        if len(host_first) >= want: break
    if not host_first: return None

    rows = tshark(pcap, ["frame.time_epoch", "smb2.filename"], "smb2.cmd==5")
    net_first = {}
    for r in rows:
        ep = sf(r[0])
        if ep == 0.0 or not r[1].strip(): continue
        for f in r[1].split(","):
            b = f.strip().replace("/", "\\").split("\\")[-1]
            if b and b not in net_first: net_first[b] = ep

    deltas = [net_first[b] - host_first[b] for b in host_first if b in net_first]
    if not deltas: return None
    deltas.sort()
    return deltas[len(deltas) // 2]

# Count SMB2 operations and byte volume per second from the capture.
def _net_persecond(pcap, t0_abs=None):
    rows = tshark(pcap, ["frame.time_epoch", "smb2.cmd", "smb2.write_length",
                         "smb2.read_length", "smb2.flags.response",
                         "smb2.file_info.infolevel"], "smb2.cmd")
    t0 = t0_abs
    wsec = defaultdict(int) # -> w_smb_write_bps      / cum_smb_write_bytes
    rsec = defaultdict(int) # -> w_smb_read_bps       / cum_smb_read_bytes
    csec = defaultdict(int) # -> w_smb_shortcmd_rate  / cum_smb_shortcmd

    ren = defaultdict(int)  # -> w_smb_rename_rate
    dele = defaultdict(int) # -> w_smb_delete_rate
                            #    ren + dele -> w_smb_destructive_rate / cum_smb_destructive

    qdir = defaultdict(int) # -> w_smb_querydir_rate  / cum_smb_querydir
    crea = defaultdict(int) # -> w_smb_create_rate    / cum_smb_create
    for r in rows:
        ep = sf(r[0]) #frame time
        if ep == 0.0: continue
        if t0 is None: t0 = ep
        s = int(ep - t0) # s: which second the packet belong to
        cmds = [si(x) for x in r[1].split(",") if x.strip() != ""] # command codes
        wl = sum(si(x) for x in r[2].split(",")) if r[2].strip() else 0 # bytes written
        rl = sum(si(x) for x in r[3].split(",")) if r[3].strip() else 0 # bytes read
        respf = [x.strip() for x in r[4].split(",") if x.strip() != ""] # 0 = request, 1 = response
        is_req = (not respf) or any(x in ("0", "0x00000000", "False") for x in respf)
        infos = [si(x) for x in r[5].split(",") if x.strip() != ""]  # 10 = rename, 13 = delete
        if wl > 0: wsec[s] += wl # e.g: wsec = {0: 12000, 1: 340000, 2: 511000, 3: 498000}
        if rl > 0: rsec[s] += rl
        for c in cmds:
            if c in SHORT_CMDS: csec[s] += 1
            if not is_req: continue
            if c == SMB_QUERYDIR: qdir[s] += 1
            elif c == SMB_CREATE: crea[s] += 1
            elif c == SMB_SETINFO:
                if INFO_RENAME in infos:      ren[s] += 1
                if INFO_DISPOSITION in infos: dele[s] += 1
    return {"w": wsec, "r": rsec, "c": csec, "ren": ren, "del": dele,
            "qdir": qdir, "crea": crea}

# Count frame bytes per second in each direction.
def bytedir_persecond(pcap, t0_abs=None):

    rows = tshark(pcap, ["frame.time_epoch", "ip.dst", "frame.len"], "tcp.port==445")
    out = defaultdict(int) # -> w_smb_bytes_out_bps  / cum_smb_bytes_out
    inn = defaultdict(int) # -> w_smb_bytes_in_bps   / cum_smb_bytes_in
                           #    out and inn -> w_smb_byte_ratio
    t0 = t0_abs
    for r in rows:
        ep = sf(r[0]) # frame time
        if ep == 0.0: continue
        if t0 is None: t0 = ep
        s = int(ep - t0); ln = si(r[2]) # s: which second, ln: frame size in bytes
        if r[1].strip() == "192.168.122.1": # 192.168.122.1 is the analysis host, so a frame addressed to it is outbound
            out[s] += ln
        else:
            inn[s] += ln
    return dict(out), dict(inn)
