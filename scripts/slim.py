#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""save-my-tokens：coding agent 配置体检的取证脚本和备份回滚脚本。

只用 Python 标准库。
  scan      只读。扫 Claude Code / Codex / Antigravity 的配置和近 N 天会话日志，输出证据。
  backup    改动之前，把要动的路径原样存一份。
  set       改 JSON / TOML 里的一个键（文件必须已在备份里）。
  move      搬一个文件或目录（两头都必须已在备份里）。
  seal      改完后记下结果，供回滚时判断文件有没有被别人再动过。
  rollback  还原到备份时的样子，逐项校验 sha256。
  list      列出备份。
  status    对比上次 scan，列出变过但没有备份覆盖的文件。
  selftest  在系统临时目录里造假 HOME，自检 backup → set → seal → rollback。Windows 上 backup 前会自动跑。
  skills    一次改很多个 skill 的状态（整组或点名），只写 skillOverrides，skill 文件不动。
            加 --agent agy 改 Antigravity 的：只写 ~/.gemini/config/skills.json 的排除名单。
  show      从 scan 的 json 里取一组 skill 的完整名单，不用重扫。
  compare   改之前、改之后各一份 scan 的 json，对比新开会话第一次请求的实测用量。

除 scan 外，写入只发生在 HOME 和 backup 时用 --root 声明的目录里。
"""
import argparse
import copy
import datetime
import difflib
import fnmatch
import glob
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import sys
import time
from collections import Counter, defaultdict

try:
    import tomllib
except ImportError:  # Python < 3.11
    tomllib = None

VERSION = "0.3.0"
STORE = ".save-my-tokens"
HERE = os.path.dirname(os.path.abspath(__file__))
SWITCHES = os.path.join(os.path.dirname(HERE), "references", "switches.json")

SECRET_RE = re.compile(
    r"(token|secret|passw|credential|cookie|bearer|api[_-]?key|auth|account|(^|_)key$)", re.I)
RARE_RE = re.compile(
    r"(release|rollback|roll-back|deploy|migrat|incident|hotfix|backup|restore|recover|disaster|"
    r"发版|回滚|部署|迁移|事故|应急|备份|恢复|故障)", re.I)
IGNORE_NAMES = {".DS_Store"}
# /doctor prompt-audit 背后的官方说明文件（anthropics/skills 仓库）
PROMPT_AUDIT_URL = "https://raw.githubusercontent.com/anthropics/skills/main/skills/claude-api/shared/prompt-audit.md"
MISSING = object()


def die(msg, code=2):
    print("错误：" + msg, file=sys.stderr)
    sys.exit(code)


def is_windows():
    """真 Windows，或为了在别的系统上测 Windows 分支而设了 SAVE_MY_TOKENS_TREAT_AS_WINDOWS=1。"""
    return os.name == "nt" or os.environ.get("SAVE_MY_TOKENS_TREAT_AS_WINDOWS") == "1"


def utf8_console():
    """报告里有 ⚠、→ 这类字符；Windows 中文系统默认 GBK，输出编码统一成 UTF-8，写不了的字符替换掉而不是报错。"""
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass


# 没显式给 --home 时，由环境变量 CLAUDE_CONFIG_DIR / CODEX_HOME 指定的配置目录；None 表示用默认的 ~/.claude、~/.codex
CONF = {"claude": None, "codex": None}


def claude_dir(home):
    return CONF["claude"] or os.path.join(home, ".claude")


def codex_dir(home):
    return CONF["codex"] or os.path.join(home, ".codex")


def claude_json_path(home):
    """设了 CLAUDE_CONFIG_DIR 后 .claude.json 在哪，文档快照里查不到，宁可不读。"""
    return None if CONF["claude"] else os.path.join(home, ".claude.json")


# ---------------------------------------------------------------- 基础工具

def expand(p, home):
    if p == "~":
        return home
    if p.startswith("~/") or p.startswith("~" + os.sep):
        return os.path.join(home, p[2:])
    return os.path.abspath(p)


def show(p, home):
    if p == home:
        return "~"
    if p.startswith(home + os.sep):
        return "~" + p[len(home):]
    return p


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_text(p, limit=None):
    try:
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            return f.read(limit) if limit else f.read()
    except OSError:
        return ""


KNOWN_SECRETS = set()       # 读配置时见到的凭据值：之后任何输出里出现都遮掉
PLAIN_VALUE_RE = re.compile(r"(?i)^(true|false|on|off|yes|no|null|none|[0-9.]+[a-z%]?)$")
SECRET_SHAPES = (
    re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(r"(?i)\b([A-Za-z0-9_.-]*(?:token|secret|passw(?:or)?d|api[_-]?key|apikey|credential|cookie|authorization)[A-Za-z0-9_.-]*)"
               r"(\s*[=:：]\s*)[\"'`]?[^\s\"'`,;，；。)）]{6,}"),
    re.compile(r"\b(?:sk|pk|rk)-[A-Za-z0-9_-]{16,}|\bgh[pousr]_[A-Za-z0-9]{20,}|\bxox[abprs]-[A-Za-z0-9-]{10,}|\bAKIA[0-9A-Z]{16}\b"
               r"|\bAIza[0-9A-Za-z_-]{30,}|\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"),
)


# 读配置时把凭据值记下来，之后整份报告里出现都遮掉。记宽了会把普通的词也遮掉（真实配置里见过：
# 项目路径、仓库名里带 token 字样，下面挂的文件名、会话编号全被当成凭据），所以分两档：
#   键名明确是凭据的（API_KEY、*_TOKEN、secret、password、headers 下面的）：值是一整串、不像文件名就记；
#   键名只是沾边的（SECRET_RE 认的 account、auth、带 token 的词）：键得是个普通的字段名，值还得是 40 个字符以上、
#   字母数字混着的一整串（账号编号、套餐名、主机名这些比它短，不算）
STRICT_SECRET_KEY_RE = re.compile(
    r"(?i)(api[_-]?key|secret|passw|bearer|credential|cookie|private[_-]?key|access[_-]?key|auth[_-]?token|authorization"
    r"|(^|[_-])token$|(^|[_-])key$)")
FIELD_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,48}$")           # 路径、仓库名、带 @ 的插件名都不算
NOT_SECRET_KEY_RE = re.compile(r"(?i)(max|min|limit|(?<!ac)count|budget|date|time|author|model|name|url|path|file|dir|id$)")
ONE_STRING_RE = re.compile(r"^[A-Za-z0-9._~+=:@%-]+$")          # 一整串，没有空格和斜杠：不是句子，也不是路径
FILE_LIKE_RE = re.compile(r"(?i)\.(md|json|jsonl|txt|toml|ya?ml|py|sh|js|ts|db|log|html?)$")
DATE_LIKE_RE = re.compile(r"^\d{4}-\d\d-\d\d")


def secret_key_tier(k):
    """一个键名有多像凭据：2 明确是，1 沾边，0 不是。"""
    if not isinstance(k, str):
        return 0
    if k == "headers" or STRICT_SECRET_KEY_RE.search(k):
        return 2 if FIELD_NAME_RE.match(k) else 0
    if SECRET_RE.search(k) and FIELD_NAME_RE.match(k) and not NOT_SECRET_KEY_RE.search(k):
        return 1
    return 0


def note_secrets(v, tier=0):
    """走一遍配置，把凭据值记进 KNOWN_SECRETS（tier 见 secret_key_tier，子项沿用上层最高的一档）。"""
    if isinstance(v, dict):
        for k, x in v.items():
            note_secrets(x, max(tier, secret_key_tier(k)))
    elif isinstance(v, list):
        for x in v:
            note_secrets(x, tier)
    elif tier and isinstance(v, str):
        m = re.match(r"(?i)(?:bearer|basic)\s+(\S{8,})$", v)
        core = m.group(1) if m else v
        if (not ONE_STRING_RE.match(core) or PLAIN_VALUE_RE.match(core) or FILE_LIKE_RE.search(core)
                or DATE_LIKE_RE.match(core)):
            return
        if tier == 2 and len(core) >= 8:
            KNOWN_SECRETS.add(core)
        elif tier == 1 and len(core) >= 40 and re.search(r"\d", core) and re.search(r"[A-Za-z]", core):
            KNOWN_SECRETS.add(core)


def hide_known(text, as_json=False):
    """把读配置时见过的凭据值从一段输出里遮掉（as_json：text 是 JSON 文本，按转义后的样子找）。"""
    for sec in sorted(KNOWN_SECRETS, key=len, reverse=True):
        needle = json.dumps(sec, ensure_ascii=False)[1:-1] if as_json else sec
        if needle in text:
            text = text.replace(needle, "<已遮掉>")
    return text


def scrub(text):
    """回显规则文件、描述这类自由文本之前用：见过的凭据值遮掉，样子像凭据的（key=值、Bearer、常见前缀的密钥）也遮掉。"""
    if not isinstance(text, str) or not text:
        return text
    text = hide_known(text)
    text = SECRET_SHAPES[0].sub(lambda m: m.group(1) + " <已遮掉>", text)
    text = SECRET_SHAPES[1].sub(lambda m: m.group(1) + m.group(2) + "<已遮掉>", text)
    return SECRET_SHAPES[2].sub("<已遮掉>", text)


def mask_secrets(v, hot=False):
    """给 set / list 的输出用：一个值里键名像凭据的、env 和 headers 下面的，一律遮掉。"""
    if isinstance(v, dict):
        return {k: mask_secrets(x, hot or k in ("env", "headers") or bool(isinstance(k, str) and SECRET_RE.search(k))) for k, x in v.items()}
    if isinstance(v, list):
        return [mask_secrets(x, hot) for x in v]
    if isinstance(v, str):
        return "<已遮掉>" if hot and not PLAIN_VALUE_RE.match(v) else scrub(v)
    return v


def load_json_file(p, config=True):
    """config=False：读的不是用户的配置（开关清单、scan 写出的 json），不拿它认凭据。"""
    try:
        with open(p, "r", encoding="utf-8-sig") as f:  # -sig：Windows 记事本存的文件可能带 BOM
            d = json.load(f)
            if config:
                note_secrets(d)
            return d, None
    except FileNotFoundError:
        return None, "absent"
    except (OSError, ValueError) as e:
        return None, str(e)


def ver_tuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", v or "")[:3])


def iso_utc(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def parse_now(s):
    if not s:
        return time.time()
    s = s.replace("Z", "+00:00")
    d = datetime.datetime.fromisoformat(s)
    if d.tzinfo is None:
        d = d.replace(tzinfo=datetime.timezone.utc)
    return d.timestamp()


def iso_to_ts(s):
    try:
        return parse_now(s[:19] + "+00:00")
    except ValueError:
        return None


# ---------------------------------------------------------------- TOML（读）

def _split_key(s):
    parts = []
    for m in re.finditer(r'\s*(?:"((?:[^"\\]|\\.)*)"|\'([^\']*)\'|([A-Za-z0-9_-]+))\s*(?:\.|$)', s):
        parts.append(next(g for g in m.groups() if g is not None))
    return parts


def _mini_value(s):
    s = s.strip()
    if not s:
        return None
    if s[0] == '"':
        m = re.match(r'"((?:[^"\\]|\\.)*)"', s)
        if m:
            try:
                return json.loads(m.group(0))
            except ValueError:
                return m.group(1)
    if s[0] == "'":
        m = re.match(r"'([^']*)'", s)
        return m.group(1) if m else None
    if s[0] == "[":
        end = s.rfind("]")
        if end < 0:
            return None
        parts = re.findall(r'"(?:[^"\\]|\\.)*"|\'[^\']*\'|[^,\s]+', s[1:end])
        return [_mini_value(x) for x in parts]
    s = s.split("#")[0].strip()
    if s in ("true", "false"):
        return s == "true"
    try:
        return int(s.replace("_", ""))
    except ValueError:
        pass
    try:
        return float(s)
    except ValueError:
        return s


HEADER_RE = re.compile(r"^\s*(\[\[?)\s*([^\[\]]+?)\s*(\]\]?)\s*(#.*)?$")


def mini_toml(text):
    """没有 tomllib 时的降级解析：只认表头和单行的标量 / 标量数组。"""
    root = {}
    cur = root
    for line in text.split("\n"):
        m = HEADER_RE.match(line)
        if m:
            parts = _split_key(m.group(2))
            cur = root
            for i, k in enumerate(parts):
                last = i == len(parts) - 1
                if last and m.group(1) == "[[":
                    cur = cur.setdefault(k, [])
                    if isinstance(cur, list):
                        cur.append({})
                        cur = cur[-1]
                else:
                    nxt = cur.setdefault(k, {})
                    cur = nxt[-1] if isinstance(nxt, list) and nxt else nxt
                if not isinstance(cur, dict):
                    cur = {}
            continue
        m = re.match(r'^\s*("(?:[^"\\]|\\.)*"|[A-Za-z0-9_-]+)\s*=\s*(.*)$', line)
        if m and isinstance(cur, dict):
            key = _split_key(m.group(1))
            if key:
                cur[key[0]] = _mini_value(m.group(2))
    return root


def load_toml_file(p):
    """返回 (数据, 是否降级解析, 错误)。"""
    try:
        with open(p, "rb") as f:
            raw = f.read().decode("utf-8", "replace")
    except FileNotFoundError:
        return None, False, "absent"
    except OSError as e:
        return None, False, str(e)
    if tomllib:
        try:
            d = tomllib.loads(raw)
        except Exception as e:  # tomllib.TOMLDecodeError
            return None, False, str(e)
        note_secrets(d)
        return d, False, None
    d = mini_toml(raw)
    note_secrets(d)
    return d, True, None


# ---------------------------------------------------------------- 清单：skill / agent / MCP

def frontmatter(text):
    if not text.startswith("---"):
        return {}
    out, key = {}, None
    for ln in text.split("\n")[1:]:
        if ln.strip() == "---":
            break
        m = re.match(r"^([A-Za-z0-9_-]+):\s*(.*)$", ln)
        if m:
            key, v = m.group(1), m.group(2).strip()
            if v in (">", "|", ">-", "|-", ">+", "|+"):
                v = ""
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                v = v[1:-1]
            out[key] = v
        elif key and ln.strip() and ln[:1] in (" ", "\t"):
            out[key] = (out[key] + " " + ln.strip()).strip()
    return out


def list_skills(base, scope, only=None):
    items = []
    if not os.path.isdir(base):
        return items
    for d in sorted(os.listdir(base)):
        if d.startswith(".") or (only is not None and d not in only):
            continue
        p = os.path.join(base, d)
        md = os.path.join(p, "SKILL.md")
        if not os.path.isfile(md):
            continue
        fm = frontmatter(read_text(md, 20000))
        st = os.lstat(p)
        born = min(getattr(st, "st_birthtime", st.st_mtime), st.st_mtime)
        link = os.path.islink(p)
        items.append({
            "name": fm.get("name") or d, "dir": d, "path": p, "md": md, "scope": scope,
            "symlink": link, "target": os.readlink(p) if link else None,
            "desc_chars": len(fm.get("description", "")),
            "desc": scrub(fm.get("description", "")[:200]),
            "manual_only": fm.get("disable-model-invocation", "").lower() == "true",
            "installed_ts": born,
        })
    return items


def list_agents(base, scope):
    items = []
    if not os.path.isdir(base):
        return items
    for f in sorted(os.listdir(base)):
        if f.startswith(".") or not f.endswith(".md"):
            continue
        p = os.path.join(base, f)
        fm = frontmatter(read_text(p, 20000))
        items.append({"name": fm.get("name") or f[:-3], "path": p, "scope": scope})
    return items


def norm_server(name):
    return re.sub(r"[^A-Za-z0-9]", "_", name or "").lower()


def mcp_brief(name, cfg, scope):
    cfg = cfg if isinstance(cfg, dict) else {}
    kind = cfg.get("type") or ("http" if cfg.get("url") else "stdio")
    return {"name": name, "scope": scope, "transport": kind,
            "alwaysLoad": bool(cfg.get("alwaysLoad")),
            "enabled": cfg.get("enabled", True) is not False,
            "enabled_tools": cfg.get("enabled_tools") if isinstance(cfg.get("enabled_tools"), list) else None,
            "disabled_tools": cfg.get("disabled_tools") if isinstance(cfg.get("disabled_tools"), list) else None}


# ---------------------------------------------------------------- 日志扫描

def new_use():
    return {"n": 0, "last": "", "cwds": Counter()}


def bump(d, key, ts, cwd=None):
    u = d.setdefault(key, new_use())
    u["n"] += 1
    if ts and ts > u["last"]:
        u["last"] = ts
    if cwd:
        u["cwds"][cwd] += 1


CWD_RE = re.compile(rb'"cwd":\s*"((?:[^"\\]|\\.)*)"')
VER_RE = re.compile(rb'"version":\s*"(\d+\.\d+\.\d+)"')
CMD_RE = re.compile(r"<command-name>/?([^<\s]+)</command-name>")
CC_NEEDLES = (b'"Skill"', b'"Agent"', b'"Task"', b'"mcp__')
TOOL_USE_RE = re.compile(rb'"type":\s*"tool_use",\s*"id":\s*"([^"]+)",\s*"name":\s*"([^"]+)"')


TS_RE = re.compile(rb'"timestamp":\s*"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)')
USAGE_RE = re.compile(rb'"usage":\s*\{')
U_IN_RE = re.compile(rb'"input_tokens":\s*(\d+)')
U_CC_RE = re.compile(rb'"cache_creation_input_tokens":\s*(\d+)')
U_CR_RE = re.compile(rb'"cache_read_input_tokens":\s*(\d+)')
MODEL_RE = re.compile(rb'"model":\s*"([^"]+)"')
MSGID_RE = re.compile(rb'"id":\s*"(msg_[^"]+)"')
CTX_BIN = 100000          # 请求大小按 10 万 token 一档统计
BIG_REWRITE = 100000      # 多大的历史没命中缓存算「整段重算」


def str_chars(o, depth=0):
    """一个对象里所有字符串值的总长度（最多往下三层）。用来量日志里各种附带信息的大小。"""
    if isinstance(o, str):
        return len(o)
    if depth >= 3:
        return 0
    if isinstance(o, dict):
        return sum(str_chars(v, depth + 1) for k, v in o.items() if k != "type")
    if isinstance(o, list):
        return sum(str_chars(v, depth + 1) for v in o)
    return 0


def note_head(head, line):
    """新开会话时，Claude Code 会把这次请求带了什么记进日志：规则文件、skill 清单、工具说明……
    这里只量每一块的字符数，不保留内容。"""
    if len(line) > 4000000:
        return
    try:
        rec = json.loads(line)
    except ValueError:
        return
    if not isinstance(rec, dict):
        return
    parts = head["parts"]
    if rec.get("type") == "api-request-shape":
        shape = rec.get("shape") if isinstance(rec.get("shape"), dict) else {}
        if head["tools"] is not None:
            return          # 只看第一份：后面的是会话中途工具变了之后的
        parts["system"] = str_chars(shape.get("system"))
        tools = {"builtin": {"n": 0, "chars": 0}, "mcp": {}, "items": []}
        for t in shape.get("tools") or []:
            if not isinstance(t, dict):
                continue
            size = len(json.dumps(t, ensure_ascii=False))
            name = str(t.get("name") or "")
            if name.startswith("mcp__") and name.count("__") >= 2:
                srv = tools["mcp"].setdefault(name.split("__", 2)[1], {"n": 0, "chars": 0})
            else:
                srv = tools["builtin"]
            srv["n"] += 1
            srv["chars"] += size
            if name and name != "DeferredToolPlaceholder":
                tools["items"].append([name, size])       # 只记名字和大小，说明原文不留
        head["tools"] = tools
        parts["builtin_tools"] = tools["builtin"]["chars"]
        parts["mcp_tools"] = sum(v["chars"] for v in tools["mcp"].values())
        return
    a = rec.get("attachment")
    if rec.get("type") != "attachment" or not isinstance(a, dict):
        return
    kind = a.get("type")
    if isinstance(rec.get("entrypoint"), str):
        head["entrypoint"] = rec["entrypoint"]
    if kind == "skill_listing":
        if a.get("isInitial") and isinstance(a.get("content"), str):
            head["listing"] = True
            parts["skills"] = len(a["content"])
            head["skill_count"] = a.get("skillCount") or len(a.get("names") or [])
    elif kind == "instructions":
        for f in a.get("files") or []:
            if isinstance(f, dict) and isinstance(f.get("content"), str):
                head["files"].append({"path": str(f.get("path") or ""), "kind": str(f.get("type") or ""),
                                      "chars": len(f["content"])})
        parts["rules"] = sum(f["chars"] for f in head["files"])
    elif kind == "mcp_instructions_delta":
        parts["mcp_notes"] = parts.get("mcp_notes", 0) + str_chars(a.get("addedBlocks"))
    elif kind == "deferred_tools_delta":
        parts["deferred"] = parts.get("deferred", 0) + str_chars(a.get("addedLines"))
        head["deferred_n"] = head.get("deferred_n", 0) + len(a.get("addedNames") or [])
        head.setdefault("deferred_names", []).extend(str(n) for n in a.get("addedNames") or [] if isinstance(n, str))
    elif kind == "agent_listing_delta":
        parts["agents"] = parts.get("agents", 0) + str_chars(a.get("addedLines"))
    elif kind == "hook_success":
        if a.get("hookEvent") == "SessionStart" and isinstance(a.get("content"), str):
            parts["hooks"] = parts.get("hooks", 0) + len(a["content"])
    elif kind != "prompt_snapshot":
        parts["other"] = parts.get("other", 0) + str_chars(a)


def open_log(path):
    """打开一个会话日志。Codex 会把旧会话压成 .jsonl.zst：Python 3.14+ 用标准库解，
    否则试系统里的 zstd 命令，都没有就返回 None（调用方会记一笔「读不了」）。"""
    if not path.endswith(".zst"):
        return open(path, "rb")
    try:
        from compression import zstd
        return zstd.open(path, "rb")
    except ImportError:
        pass
    exe = shutil.which("zstd")
    if exe:
        import subprocess
        return subprocess.Popen([exe, "-dcq", path], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout
    return None


def note_first_ts(r, line, cutoff_iso):
    """记下每个文件第一条带时间的记录，用来判断日志往前覆盖到哪天。"""
    m = TS_RE.search(line)
    if not m:
        return False
    t = m.group(1).decode()
    if t < cutoff_iso:
        r["older_evidence"] = True
    elif not r["earliest"] or t < r["earliest"]:
        r["earliest"] = t
    return True


def iter_jsonl(root, cutoff):
    """产出 (路径, mtime, 大小, 是否在时间窗内)。窗外的文件只用来判断日志覆盖了多久。"""
    for dp, _dn, fn in os.walk(root):
        for f in fn:
            if not (f.endswith(".jsonl") or f.endswith(".jsonl.zst")):
                continue
            p = os.path.join(dp, f)
            try:
                st = os.stat(p)
            except OSError:
                continue
            yield p, st.st_mtime, st.st_size, st.st_mtime >= cutoff


def scan_claude_logs(home, cutoff):
    root = os.path.join(claude_dir(home), "projects")
    cutoff_iso = iso_utc(cutoff)
    r = {"present": os.path.isdir(root), "files": 0, "bytes": 0, "older_evidence": False, "earliest": "",
         "unreadable": 0, "version": None, "cwds": Counter(), "skill_model": {}, "skill_user": {},
         "agents": {}, "mcp": {}, "listings": [],
         "tool_calls": Counter(),                        # 每个工具（内置的和 MCP 的）被调了几次
         # 下面几样都是从日志里的用量数字直接数出来的
         "starts": [],                                   # 每个新会话的第一次请求
         "req": {"main": {}, "sub": {}},                 # 请求数和输入 token，按模型
         "bins": Counter(), "bin_tokens": Counter(),     # 主会话请求按大小分档
         "peaks": [],                                    # 每个会话文件里最大的一次请求
         "rewrites": {},                                 # 没命中缓存、整段重算的请求
         "agent_model": Counter(),                       # 派子代理时指定了什么模型
         "dispatches": [],                               # 主会话每一次派子代理：谁派的、派给谁、标题
         "sub_runs": {}}                                 # 每个子代理自己发了多少次请求，按派它的那次调用的 id
    if not r["present"]:
        return r
    seen = set()
    seen_msg = set()
    seen_tu = set()
    for p, mtime, size, inwin in iter_jsonl(root, cutoff):
        if not inwin:
            r["older_evidence"] = True
            continue
        is_sub = (os.sep + "subagents" + os.sep) in p
        file_cwd = None
        head = None if is_sub else {"parts": {}, "files": [], "tools": None, "listing": False, "lines": 0}
        prev_ts, prev_model, peak, copied, file_msgs = None, None, 0, False, set()
        sub_models = Counter()
        try:
            fh = open_log(p)
        except OSError:
            fh = None
        if fh is None:
            r["unreadable"] += 1
            continue
        r["files"] += 1
        r["bytes"] += size
        got_ts = False
        with fh:
            for line in fh:
                if not got_ts and b'"timestamp"' in line:
                    got_ts = note_first_ts(r, line, cutoff_iso)
                if file_cwd is None and b'"cwd"' in line:
                    m = CWD_RE.search(line)
                    if m:
                        try:
                            file_cwd = json.loads(b'"' + m.group(1) + b'"')
                        except ValueError:
                            file_cwd = ""
                        if file_cwd and not is_sub:
                            r["cwds"][file_cwd] += 1
                        v = VER_RE.search(line)
                        if v:
                            vs = v.group(1).decode()
                            if ver_tuple(vs) > ver_tuple(r["version"]):
                                r["version"] = vs
                if head is not None:
                    head["lines"] += 1
                    if head["lines"] > 400:
                        head = None
                    elif b'"attachment"' in line or b'"api-request-shape"' in line:
                        note_head(head, line)
                # 每次请求的用量：输入 = 新输入 + 写入缓存 + 读缓存，就是这次请求带的全部上下文
                if b'"usage"' in line and b'"assistant"' in line:
                    um = USAGE_RE.search(line)
                    mi = MSGID_RE.search(line)
                    mid = mi.group(1) if mi else None
                    if um and mid and mid in file_msgs:
                        pass                             # 同一次回复被拆成几条记录，用量是同一份
                    elif um and mid and mid in seen_msg:
                        copied = True                    # 续接会话时抄过来的旧记录，数过了
                    elif um:
                        if mid:
                            seen_msg.add(mid)
                            file_msgs.add(mid)
                        at = um.end()
                        a, b_, c_ = U_IN_RE.search(line, at), U_CC_RE.search(line, at), U_CR_RE.search(line, at)
                        cc, cr = (int(b_.group(1)) if b_ else 0), (int(c_.group(1)) if c_ else 0)
                        ctx = (int(a.group(1)) if a else 0) + cc + cr
                        tss = TS_RE.findall(line)
                        uts = tss[-1].decode() if tss else ""
                        mm = MODEL_RE.search(line)
                        model = mm.group(1).decode("utf-8", "replace") if mm else "?"
                        side = is_sub or b'"isSidechain":true' in line or b'"isSidechain": true' in line
                        inwin_req = not uts or uts >= cutoff_iso
                        if ctx and model != "<synthetic>":
                            if is_sub:
                                sub_models[model] += 1
                            if inwin_req:
                                slot = r["req"]["sub" if side else "main"].setdefault(model, {"n": 0, "tokens": 0})
                                slot["n"] += 1
                                slot["tokens"] += ctx
                            if not side:
                                if inwin_req:
                                    b = min(ctx // CTX_BIN, 10)
                                    r["bins"][b] += 1
                                    r["bin_tokens"][b] += ctx
                                    peak = max(peak, ctx)
                                    if prev_ts is None:
                                        if head is not None and head["listing"] and not copied:
                                            r["starts"].append({
                                                "ts": uts, "cwd": file_cwd or "", "tokens": ctx, "model": model,
                                                "parts": head["parts"], "files": head["files"], "tools": head["tools"],
                                                "skill_count": head.get("skill_count"), "deferred_n": head.get("deferred_n"),
                                                "deferred_names": head.get("deferred_names") or [],
                                                "entrypoint": head.get("entrypoint")})
                                    elif ctx >= BIG_REWRITE and cr < ctx * 0.1:
                                        gap = iso_to_ts(uts) - iso_to_ts(prev_ts) if uts and prev_ts else 0
                                        why = ("换了模型" if model != prev_model else "隔了 1 小时以上" if gap > 3600
                                               else "隔了 5 分钟到 1 小时" if gap > 300 else "其他原因")
                                        w = r["rewrites"].setdefault(why, {"n": 0, "tokens": 0})
                                        w["n"] += 1
                                        w["tokens"] += ctx
                                prev_ts, prev_model = uts or prev_ts or "", model
                                head = None
                # Claude Code 新开会话时会把发给模型的 skill 清单记进日志：这是实测值，不是我们算的
                if not is_sub and b'"skill_listing"' in line and len(line) < 400000:
                    try:
                        att = json.loads(line)
                    except ValueError:
                        att = None
                    a = att.get("attachment") if isinstance(att, dict) else None
                    if (isinstance(a, dict) and a.get("type") == "skill_listing" and a.get("isInitial")
                            and isinstance(a.get("content"), str)):
                        lts = (att.get("timestamp") or "")[:19]
                        if lts >= cutoff_iso:
                            names = a.get("names") if isinstance(a.get("names"), list) else []
                            r["listings"].append({"ts": lts, "count": a.get("skillCount") or len(names),
                                                  "chars": len(a["content"]), "cwd": att.get("cwd") or file_cwd or ""})
                    continue
                if b'"tool_use"' in line and b'"assistant"' in line:
                    tss = TS_RE.findall(line)
                    if not tss or tss[-1].decode() >= cutoff_iso:
                        for tid, tname in TOOL_USE_RE.findall(line):
                            if tid not in seen_tu:
                                seen_tu.add(tid)
                                r["tool_calls"][tname.decode("utf-8", "replace")] += 1
                is_tool = b'"tool_use"' in line and any(n in line for n in CC_NEEDLES)
                is_cmd = (not is_tool) and b"<command-name>" in line
                if not (is_tool or is_cmd):
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                ts = (rec.get("timestamp") or "")[:19]
                if ts and ts < cutoff_iso:
                    continue
                msg = rec.get("message")
                if not isinstance(msg, dict):
                    continue
                content = msg.get("content")
                cwd = rec.get("cwd") or file_cwd
                if rec.get("type") == "assistant" and isinstance(content, list):
                    for b in content:
                        if not isinstance(b, dict) or b.get("type") != "tool_use":
                            continue
                        bid = b.get("id")
                        if bid:
                            if bid in seen:
                                continue
                            seen.add(bid)
                        name = b.get("name") or ""
                        inp = b.get("input") if isinstance(b.get("input"), dict) else {}
                        if name == "Skill" and inp.get("skill"):
                            bump(r["skill_model"], str(inp["skill"]), ts, cwd)
                        elif name in ("Agent", "Task"):
                            r["agent_model"][str(inp.get("model") or "")] += 1
                            if not is_sub and not rec.get("isSidechain") and bid:
                                r["dispatches"].append({
                                    "id": bid, "ts": ts, "cwd": cwd or "", "main": str(msg.get("model") or "?"),
                                    "to": str(inp.get("model") or ""), "type": str(inp.get("subagent_type") or ""),
                                    "title": clip(str(inp.get("description") or ""), 80)})
                            if inp.get("subagent_type"):
                                bump(r["agents"], str(inp["subagent_type"]), ts, cwd)
                        elif name.startswith("mcp__"):
                            parts = name.split("__", 2)
                            if len(parts) == 3:
                                u = r["mcp"].setdefault(parts[1], {"n": 0, "last": "", "tools": Counter()})
                                u["n"] += 1
                                u["tools"][parts[2]] += 1
                                if ts > u["last"]:
                                    u["last"] = ts
                elif rec.get("type") == "user":
                    if isinstance(content, str):
                        text = content
                    elif isinstance(content, list):
                        text = "\n".join(b.get("text", "") for b in content
                                         if isinstance(b, dict) and b.get("type") == "text")
                    else:
                        text = ""
                    names = CMD_RE.findall(text)
                    if not names:
                        continue
                    uid = rec.get("uuid")
                    if uid:
                        if uid in seen:
                            continue
                        seen.add(uid)
                    for n in names:
                        bump(r["skill_user"], n, ts, cwd)
        if peak:
            r["peaks"].append(peak)
        if is_sub and sub_models:
            # 子代理日志旁边的 .meta.json 记着它是主会话哪一次 Agent 调用派出来的
            meta, _e = load_json_file(re.sub(r"\.jsonl(\.zst)?$", "", p) + ".meta.json", config=False)
            tid = meta.get("toolUseId") if isinstance(meta, dict) else None
            if isinstance(tid, str):
                run = r["sub_runs"].setdefault(tid, {"reqs": 0, "models": Counter()})
                run["reqs"] += sum(sub_models.values())
                run["models"].update(sub_models)
    return r


CODEX_MCP_RE = re.compile(r"tools\.mcp__([A-Za-z0-9_]+?)__([A-Za-z0-9_]+)")
CODEX_SKILL_RE = re.compile(r"(?:(\.claude|\.codex|\.agents)/)?skills/([A-Za-z0-9_.-]+)/SKILL\.md")
CODEX_VER_RE = re.compile(rb'"cli_version":\s*"(\d+\.\d+\.\d+)"')


def scan_codex_logs(home, cutoff):
    base = codex_dir(home)
    cutoff_iso = iso_utc(cutoff)
    r = {"present": False, "files": 0, "bytes": 0, "older_evidence": False, "earliest": "", "unreadable": 0,
         "version": None, "cwds": Counter(), "mcp": {}, "skill_reads": {}}
    seen = set()
    for sub in ("sessions", "archived_sessions"):
        root = os.path.join(base, sub)
        if not os.path.isdir(root):
            continue
        r["present"] = True
        for p, mtime, size, inwin in iter_jsonl(root, cutoff):
            if not inwin:
                r["older_evidence"] = True
                continue
            file_cwd = None
            try:
                fh = open_log(p)
            except OSError:
                fh = None
            if fh is None:
                r["unreadable"] += 1
                continue
            r["files"] += 1
            r["bytes"] += size
            got_ts = False
            with fh:
                for line in fh:
                    if not got_ts and b'"timestamp"' in line:
                        got_ts = note_first_ts(r, line, cutoff_iso)
                    if file_cwd is None and b'"session_meta"' in line:
                        m = CWD_RE.search(line)
                        if m:
                            try:
                                file_cwd = json.loads(b'"' + m.group(1) + b'"')
                            except ValueError:
                                file_cwd = ""
                            if file_cwd:
                                r["cwds"][file_cwd] += 1
                        v = CODEX_VER_RE.search(line)
                        if v and ver_tuple(v.group(1).decode()) > ver_tuple(r["version"]):
                            r["version"] = v.group(1).decode()
                        continue
                    if b'"custom_tool_call"' not in line and b'"function_call"' not in line:
                        continue
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    pl = rec.get("payload")
                    if not isinstance(pl, dict) or pl.get("type") not in ("custom_tool_call", "function_call"):
                        continue
                    ts = (rec.get("timestamp") or "")[:19]
                    if ts and ts < cutoff_iso:
                        continue
                    cid = pl.get("call_id") or pl.get("id")
                    if cid:
                        if cid in seen:
                            continue
                        seen.add(cid)
                    text = pl.get("input") if pl.get("type") == "custom_tool_call" else pl.get("arguments")
                    text = text if isinstance(text, str) else json.dumps(text, ensure_ascii=False)
                    calls = [(m.group(1), m.group(2)) for m in CODEX_MCP_RE.finditer(text)]
                    ns = pl.get("namespace") or ""
                    if pl.get("type") == "function_call" and ns.startswith("mcp__"):
                        calls.append((ns[5:], pl.get("name") or "?"))
                    for server, tool in calls:
                        u = r["mcp"].setdefault(server, {"n": 0, "last": "", "tools": Counter()})
                        u["n"] += 1
                        u["tools"][tool] += 1
                        if ts > u["last"]:
                            u["last"] = ts
                    for name in {m.group(2) for m in CODEX_SKILL_RE.finditer(text)}:
                        bump(r["skill_reads"], name, ts, file_cwd)
    return r


# ---------------------------------------------------------------- Antigravity（Google 的反重力：命令行 agy、桌面 app、IDE）
#
# 下面这些结论的出处，逐条写在 references/antigravity.md 里：官方文档的哪一页，或者用真的 agy 在隔离目录里做的哪个实验。
#   配置在 ~/.gemini/config/（规则、skill、MCP、hook）和 ~/.gemini/GEMINI.md；
#   每个入口各有一个数据目录：命令行 ~/.gemini/antigravity-cli/、桌面 app ~/.gemini/antigravity/、IDE ~/.gemini/antigravity-ide/；
#   数据目录里 brain/<会话>/.system_generated/logs/transcript.jsonl 是会话日志，每次模型回复带 input_tokens 和 cache_read_tokens；
#   conversations/<会话>.db 是会话库，里面留着最后一次请求的全文（系统提示每一段、每个工具的说明）。

AGY_ENTRY = {"antigravity": "桌面 app", "antigravity-cli": "命令行", "antigravity-ide": "IDE"}
AGY_DOT = (".agents", ".agent", "_agents", "_agent")        # 官方认的四种写法，新项目用 .agents
AGY_RULE_NAMES = ("AGENTS.md", "GEMINI.md")
AGY_RULE_CAP = 24000                                        # 每个规则文件的上限（字节），超了在行边界截断
AGY_SKILL_RE = re.compile(r"skills/([A-Za-z0-9_.-]+)/SKILL\.md")
AGY_INLINE_RE = re.compile(r"@\[[^\]\n]*\]\(([^)\n]+)\)")   # @[标签](路径)：把那个文件的内容展开进规则；单写 @路径 不展开
AGY_TAG_RE = re.compile(r"^<([a-z_]+)>\n", re.M)
AGY_RULE_BLOCK_RE = re.compile(r"<RULE\[([^\]\n]+)\]>\n(.*?)</RULE\[[^\]\n]+\]>", re.S)
AGY_SKILL_LINE_RE = re.compile(r"^- (\S+) \((/[^)\n]+|[A-Za-z]:[^)\n]+)\): ", re.M)
AGY_POINTER_RE = re.compile(r"^- (?:file://)?(/\S+?): ", re.M)


def gemini_dir(home):
    return os.path.join(home, ".gemini")


def agy_app_dirs(home):
    """~/.gemini 下面有会话记录的数据目录（里面有 brain/ 的）。"""
    g = gemini_dir(home)
    if not os.path.isdir(g):
        return []
    return [d for d in sorted(os.listdir(g)) if d != "config" and os.path.isdir(os.path.join(g, d, "brain"))]


def agy_sqlite(path):
    """只读打开 Antigravity 的 SQLite 库。immutable=1：不建 -shm / -wal，不拿锁，库正被用着也不受影响；
    代价是还没落盘的最新几步读不到。"""
    import sqlite3
    import urllib.parse
    return sqlite3.connect("file:%s?mode=ro&immutable=1" % urllib.parse.quote(path), uri=True)


def pb_fields(b):
    """把一段 protobuf 拆成 [(字段号, 线型, 值)]。拆不动返回 None。只解到这里用得着的程度。"""
    out, i, n = [], 0, len(b)
    try:
        while i < n:
            key = shift = 0
            while True:
                y = b[i]
                i += 1
                key |= (y & 0x7F) << shift
                shift += 7
                if not y & 0x80:
                    break
            f, wt = key >> 3, key & 7
            if f == 0:
                return None
            if wt == 0:
                v = shift = 0
                while True:
                    y = b[i]
                    i += 1
                    v |= (y & 0x7F) << shift
                    shift += 7
                    if not y & 0x80:
                        break
            elif wt == 2:
                ln = shift = 0
                while True:
                    y = b[i]
                    i += 1
                    ln |= (y & 0x7F) << shift
                    shift += 7
                    if not y & 0x80:
                        break
                if i + ln > n:
                    return None
                v = b[i:i + ln]
                i += ln
            elif wt == 1:
                v = b[i:i + 8]
                i += 8
            elif wt == 5:
                v = b[i:i + 4]
                i += 4
            else:
                return None
            out.append((f, wt, v))
    except IndexError:
        return None
    return out


def pb_text(v):
    try:
        return v.decode("utf-8")
    except (UnicodeDecodeError, AttributeError):
        return None


def agy_split_tags(system):
    """整段系统提示按顶层的 <名字>…</名字> 切开。会话库里没有分段记录时的退路。"""
    out, i = [], 0
    while True:
        m = AGY_TAG_RE.search(system, i)
        if not m:
            return out
        end = system.find("</%s>" % m.group(1), m.end())
        if end < 0:
            i = m.end()
            continue
        end += len(m.group(1)) + 3
        out.append((m.group(1), system[m.start():end]))
        i = end


def agy_mcp_listing(text):
    """系统提示的 <mcp_servers> 一段：每个 server 下面哪些工具是 Eager（整份说明常驻）、哪些是 Lazy（只列名字）。"""
    out, cur, mode = {}, None, None
    body = text.split("```")[-1]            # 前面是格式说明，里面也有一个示例用的 # <serverName>
    for ln in body.split("\n"):
        s = ln.strip()
        if s.startswith("# "):
            cur = out.setdefault(s[2:].strip(), {"eager": [], "lazy": []})
            mode = None
        elif s in ("Eager:", "Lazy:"):
            mode = s[:-1].lower()
        elif s and cur is not None and mode and not s.startswith("<"):
            cur[mode].append(s)
    return out


def agy_shape(db):
    """会话库里留着的那一次请求（Antigravity 只留每个会话最后一次请求的全文）：系统提示每一段多大、
    加载了哪些规则和 skill、带了哪些工具说明。只量大小、记名字和路径，内容不留。认不出格式返回 None。"""
    try:
        con = agy_sqlite(db)
        try:
            row = con.execute("select data from gen_metadata order by idx desc limit 1").fetchone()
        finally:
            con.close()
    except Exception:       # 库不存在、表不存在、这个 Python 没带 sqlite3：都当作量不出来
        return None
    if not row or not isinstance(row[0], (bytes, bytearray)):
        return None
    req = next((v for f, wt, v in pb_fields(bytes(row[0])) or [] if f == 1 and wt == 2), None)
    inner = pb_fields(req) if req else None
    if not inner:
        return None
    system, sections, decls, bad = None, [], [], 0
    for f, wt, v in inner:
        if wt != 2:
            continue
        if f == 1 and system is None:
            system = pb_text(v)
        elif f == 16:
            d = {ff: pb_text(vv) for ff, w_, vv in pb_fields(v) or [] if w_ == 2 and ff in (1, 2)}
            if d.get(1) and d.get(2) and d[2].lstrip().startswith("<" + d[1]):
                sections.append((d[1], d[2]))
            else:
                bad += 1            # 这一段记录认不出来
        elif f == 8:
            d = {ff: vv for ff, w_, vv in pb_fields(v) or [] if w_ == 2 and ff in (1, 2, 3)}
            name = pb_text(d.get(1, b""))
            if name and re.fullmatch(r"[A-Za-z0-9_.:-]{1,120}", name):
                decls.append([name, len(pb_text(d.get(2, b"")) or "") + len(pb_text(d.get(3, b"")) or "") + len(name)])
            else:
                bad += 1
    # 系统提示全文里也有每一段：分段记录缺了或坏了的，从全文里补回来；补不回来就标成「明细不完整」，不把缺的当成 0
    have = set(n_ for n_, _t in sections)
    for n_, t in (agy_split_tags(system) if system else []):
        if n_ not in have:
            sections.append((n_, t))
            have.add(n_)
            bad = max(bad - 1, 0)
    if not sections:
        return None
    by = dict(sections)
    parts = {"rules": len(by.get("user_rules", "")), "skills": len(by.get("skills", "")),
             "mcp_list": len(by.get("mcp_servers", "")), "agents": len(by.get("subagents", "")),
             "system": sum(len(t) for n_, t in sections if n_ not in ("user_rules", "skills", "mcp_servers", "subagents"))}
    files = [{"path": lbl, "kind": "", "chars": len(body)} for lbl, body in AGY_RULE_BLOCK_RE.findall(by.get("user_rules", ""))]
    pointers = AGY_POINTER_RE.findall(by.get("user_rules", "").split("conditional rules", 1)[-1]) if "conditional rules" in by.get("user_rules", "") else []
    listed = AGY_SKILL_LINE_RE.findall(by.get("skills", ""))
    servers = agy_mcp_listing(by["mcp_servers"]) if "mcp_servers" in by else {}
    eager = {"mcp_%s_%s" % (srv, t): srv for srv, v in servers.items() for t in v["eager"]}
    tools = {"builtin": {"n": 0, "chars": 0}, "mcp": {}, "items": []}
    for name, size in decls:
        srv = eager.get(name)
        if srv is None and name.startswith("mcp_"):
            # 清单里对不上的 mcp_ 工具（比如 IDE 自己带进来的）：按已知 server 名的最长前缀归类，归不了就单独一类
            srv = max((s for s in servers if name.startswith("mcp_%s_" % s)), key=len, default="（未知 server）")
        slot = tools["mcp"].setdefault(srv, {"n": 0, "chars": 0}) if srv else tools["builtin"]
        slot["n"] += 1
        slot["chars"] += size
        tools["items"].append([name, size, srv])
    parts["builtin_tools"] = tools["builtin"]["chars"]
    parts["mcp_tools"] = sum(v["chars"] for v in tools["mcp"].values())
    return {"parts": parts, "files": files, "pointers": pointers, "tools": tools, "partial": bad > 0,
            "skill_count": len(listed), "skill_paths": [p for _n, p in listed], "skill_names": [n_ for n_, _p in listed],
            "lazy": {srv: v["lazy"] for srv, v in servers.items()}, "servers": sorted(servers),
            "sections": [[n_, len(t)] for n_, t in sections]}


def agy_db_model(db):
    """会话库最后一次请求用的模型（例：gemini-4-neon-high）。桌面 app 的日志不记模型，用它补。读不出返回 None。"""
    try:
        con = agy_sqlite(db)
        try:
            row = con.execute("select data from gen_metadata order by idx desc limit 1").fetchone()
        finally:
            con.close()
    except Exception:
        return None
    if not row or not isinstance(row[0], (bytes, bytearray)):
        return None
    meta = next((v for f, wt, v in pb_fields(bytes(row[0])) or [] if f == 3 and wt == 2), None)
    name = next((pb_text(v) for f, wt, v in pb_fields(meta) or [] if f == 28 and wt == 2), None) if meta else None
    return name if name and re.fullmatch(r"[A-Za-z0-9_.:-]{3,80}", name) else None


def agy_arg(v):
    """transcript 里工具参数的值是再编了一层的 JSON 字符串（"\\"demo\\""）。"""
    if isinstance(v, str) and v[:1] in '"[{':
        try:
            return json.loads(v)
        except ValueError:
            pass
    return v


def agy_summaries(base):
    """会话摘要库：每个会话在哪个目录开的、是不是别的会话派出来的子代理、标题。
    返回 (每个会话的信息, 库里有没有「父会话」这一列)。读不了返回 ({}, False)。"""
    out = {}
    p = os.path.join(base, "conversation_summaries.db")
    if not os.path.isfile(p):
        return out, False
    try:
        import urllib.parse
        con = agy_sqlite(p)
        try:
            cols = set(r[1] for r in con.execute("pragma table_info(conversation_summaries)"))
            want = [c for c in ("conversation_id", "workspace_uris", "parent_conversation_id", "agent_name", "title") if c in cols]
            if "conversation_id" not in want:
                return out, False
            for row in con.execute("select %s from conversation_summaries" % ",".join(want)):
                d = dict(zip(want, row))
                cwds = []
                try:
                    for u in json.loads(d.get("workspace_uris") or "[]"):
                        if isinstance(u, str) and u.startswith("file://"):
                            cwds.append(urllib.parse.unquote(u[7:]).rstrip("/") or "/")
                except ValueError:
                    pass
                out[d["conversation_id"]] = {"cwd": cwds[0] if cwds else "", "cwds": cwds, "parent": d.get("parent_conversation_id") or "",
                                             "agent": d.get("agent_name") or "", "title": d.get("title") or ""}
        finally:
            con.close()
    except Exception:
        return {}, False
    return out, "parent_conversation_id" in cols


AGY_USER_INPUT_RE = re.compile(rb'"type":\s*"USER_INPUT"')


def scan_agy_logs(home, cutoff):
    g = gemini_dir(home)
    cutoff_iso = iso_utc(cutoff)
    r = {"present": False, "dirs": [], "files": 0, "bytes": 0, "older_evidence": False, "earliest": "", "unreadable": 0,
         "version": None, "cwds": Counter(), "starts": [], "req": {"main": {}, "sub": {}},
         "bins": Counter(), "bin_tokens": Counter(), "peaks": [], "rewrites": {}, "checkpoints": [],
         "skill_reads": {}, "skill_read_paths": {}, "mcp": {}, "raw_mcp_tools": {}, "agents": {}, "agent_model": Counter(),
         "tool_calls": Counter(), "sub_runs": [], "no_db": 0, "model_from_db": 0, "model_unknown": 0, "wal_pending": 0,
         "kind_unknown": 0, "start_no_usage": 0, "partial_shape": 0}
    for app in agy_app_dirs(home):
        base = os.path.join(g, app)
        r["present"] = True
        r["dirs"].append(app)
        meta, has_parent_col = agy_summaries(base)
        for cid in sorted(os.listdir(os.path.join(base, "brain"))):
            p = os.path.join(base, "brain", cid, ".system_generated", "logs", "transcript.jsonl")
            try:
                st = os.stat(p)
            except OSError:
                continue
            if st.st_mtime < cutoff:
                r["older_evidence"] = True
                continue
            row = meta.get(cid)
            info = row or {"cwd": "", "cwds": [], "parent": "", "agent": "", "title": ""}
            cwd = info["cwd"]
            r["files"] += 1
            r["bytes"] += st.st_size
            # 这个会话是用户自己开的还是别的会话派出来的子代理：摘要库里有这一行、也有「父会话」这一列时听它的；
            # 查不到时看日志：用户开的会话开头有一条用户输入，子代理的没有（实机 126 个会话无一例外）。两头都没有就算身份不明，单列。
            role = ("sub" if row["parent"] else "main") if (row is not None and has_parent_col) else None
            has_user = False
            prev_ctx, prev_ts, model, peak, first, reqs, read_here = None, None, "?", 0, None, 0, set()
            pr_seen, no_usage_first, in_window = 0, False, False
            sub_models = Counter()
            sess_req = {}
            try:
                fh = open(p, "rb")
            except OSError:
                r["unreadable"] += 1
                continue
            with fh:
                for line in fh:
                    if b'"PLANNER_RESPONSE"' not in line and b'"CHECKPOINT"' not in line:
                        if not pr_seen and not has_user and AGY_USER_INPUT_RE.search(line):
                            has_user = True
                        continue
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    if not isinstance(rec, dict) or rec.get("type") not in ("PLANNER_RESPONSE", "CHECKPOINT"):
                        if isinstance(rec, dict) and rec.get("type") == "USER_INPUT" and not pr_seen:
                            has_user = True
                        continue
                    if role is None:
                        role = "main" if has_user else "unknown"
                    if role == "unknown":
                        in_window = in_window or str(rec.get("created_at") or "")[:19] >= cutoff_iso
                        continue
                    is_sub = role == "sub"
                    ts = str(rec.get("created_at") or "")[:19]
                    if ts:
                        if ts < cutoff_iso:
                            r["older_evidence"] = True
                        elif not r["earliest"] or ts < r["earliest"]:
                            r["earliest"] = ts
                    inwin = not ts or ts >= cutoff_iso
                    try:
                        cr = int(rec.get("cache_read_tokens") or 0)
                        ctx = int(rec.get("input_tokens") or 0) + cr      # 这次请求带的全部上下文 = 新输入 + 读缓存
                    except (TypeError, ValueError):
                        cr = ctx = 0
                    if rec["type"] == "CHECKPOINT":
                        # 一次压缩（自动的或 /compact）：记下压缩前会话长到多大
                        if inwin and prev_ctx and not is_sub:
                            r["checkpoints"].append({"before": prev_ctx, "entry": app})
                        prev_ctx = None       # 压缩后的下一次请求本来就不读旧缓存，不算「整段重算」
                        continue
                    pr_seen += 1
                    if isinstance(rec.get("model"), str) and rec["model"]:
                        model = rec["model"]
                    if pr_seen == 1 and not ctx and not is_sub:
                        # 第一条模型回复没有可用的用量：这个会话的开局量不出来，不拿后面某一次请求顶替
                        first = False
                        no_usage_first = inwin
                    if ctx:
                        reqs += 1
                        if is_sub:
                            sub_models[model] += 1
                        if inwin:
                            slot = sess_req.setdefault(model, {"n": 0, "tokens": 0})
                            slot["n"] += 1
                            slot["tokens"] += ctx
                        if not is_sub and inwin:
                            b = min(ctx // CTX_BIN, 10)
                            r["bins"][b] += 1
                            r["bin_tokens"][b] += ctx
                            peak = max(peak, ctx)
                            if first is None:
                                first = {"ts": ts, "cwd": cwd, "cwds": info["cwds"], "tokens": ctx, "model": model, "entrypoint": app, "cid": cid}
                            elif prev_ctx and ctx >= BIG_REWRITE and cr < ctx * 0.1:
                                gap = iso_to_ts(ts) - iso_to_ts(prev_ts) if ts and prev_ts else 0
                                why = "隔了 1 小时以上" if gap > 3600 else "隔了 5 分钟到 1 小时" if gap > 300 else "其他原因"
                                w = r["rewrites"].setdefault(why, {"n": 0, "tokens": 0})
                                w["n"] += 1
                                w["tokens"] += ctx
                        if first is None and not is_sub:
                            first = False          # 第一次请求在时间窗之前：这个会话不算窗口内新开的
                        prev_ctx, prev_ts = ctx, ts or prev_ts
                    if not inwin:
                        continue
                    for tc in rec.get("tool_calls") or []:
                        if not isinstance(tc, dict) or not isinstance(tc.get("name"), str):
                            continue
                        name = tc["name"]
                        args = tc.get("args") if isinstance(tc.get("args"), dict) else {}
                        r["tool_calls"][name] += 1
                        if name == "read_file":
                            # Antigravity 没有专门的 Skill 工具：用一个 skill 就是读它的 SKILL.md。同一个会话读几段只算一次。
                            # 按文件的真实路径记（同名的 skill、放在自定义目录的 skill 才分得清），另按目录名记一份给别的 agent 的 skill 对账用
                            path_arg = str(agy_arg(args.get("Path")) or "")
                            if path_arg.startswith("file://"):
                                path_arg = path_arg[7:]
                            if os.path.basename(path_arg) == "SKILL.md" and os.path.isabs(path_arg):
                                key = os.path.realpath(os.path.dirname(path_arg))
                                if key not in read_here:
                                    read_here.add(key)
                                    bump(r["skill_read_paths"], key, ts, cwd)
                                sk = os.path.basename(os.path.dirname(path_arg))
                                if ("name", sk) not in read_here:
                                    read_here.add(("name", sk))
                                    bump(r["skill_reads"], sk, ts, cwd)
                        elif name == "call_mcp_tool":
                            srv, tool = str(agy_arg(args.get("ServerName")) or "?"), str(agy_arg(args.get("ToolName")) or "?")
                            u = r["mcp"].setdefault(srv, {"n": 0, "last": "", "tools": Counter()})
                            u["n"] += 1
                            u["tools"][tool] += 1
                            u["last"] = max(u["last"], ts)
                        elif name.startswith("mcp_"):
                            u = r["raw_mcp_tools"].setdefault(name, {"n": 0, "last": ""})    # 常驻（eager）的 MCP 工具，归到哪个 server 等读了配置再定
                            u["n"] += 1
                            u["last"] = max(u["last"], ts)
                        elif name == "invoke_subagent":
                            r["agent_model"][str(agy_arg(args.get("Model")) or "")] += 1
                            kind = str(agy_arg(args.get("TypeName")) or "")
                            if kind:
                                bump(r["agents"], kind, ts, cwd)
            if role == "unknown":
                if in_window:
                    r["kind_unknown"] += 1
                continue
            is_sub = role == "sub"
            if cwd and not is_sub and role == "main":
                r["cwds"][cwd] += 1
            if no_usage_first:
                r["start_no_usage"] += 1
            db = os.path.join(base, "conversations", cid + ".db")
            if "?" in sess_req or "?" in sub_models or (first and first["model"] == "?"):
                # 这个会话的日志没记模型（桌面 app 多数如此）：用会话库里最后一次请求的模型顶上
                dbm = agy_db_model(db)
                if dbm:
                    r["model_from_db"] += sess_req.get("?", {"n": 0})["n"]
                    if "?" in sess_req:
                        old = sess_req.pop("?")
                        slot = sess_req.setdefault(dbm, {"n": 0, "tokens": 0})
                        slot["n"] += old["n"]
                        slot["tokens"] += old["tokens"]
                    if "?" in sub_models:
                        sub_models[dbm] += sub_models.pop("?")
                    if first and first["model"] == "?":
                        first["model"] = dbm
                else:
                    r["model_unknown"] += sess_req.get("?", {"n": 0})["n"]
            for mdl, v in sess_req.items():
                slot = r["req"]["sub" if is_sub else "main"].setdefault(mdl, {"n": 0, "tokens": 0})
                slot["n"] += v["n"]
                slot["tokens"] += v["tokens"]
            if peak:
                r["peaks"].append(peak)
            if is_sub and reqs:
                r["sub_runs"].append({"reqs": reqs, "type": info["agent"], "title": clip(info["title"], 60),
                                      "model": sub_models.most_common(1)[0][0] if sub_models else "", "cwd": cwd})
            if first:
                shape = agy_shape(db)
                if shape is None:
                    r["no_db"] += 1
                else:
                    if shape.get("partial"):
                        r["partial_shape"] += 1
                    try:
                        # 只读方式打开读不到 -wal 里还没并入主库的改动。实机上 -wal 都是 0 字节；不是的话明说可能偏旧
                        if os.path.getsize(db + "-wal") > 0:
                            r["wal_pending"] += 1
                    except OSError:
                        pass
                first.update({"parts": (shape or {}).get("parts") or {}, "files": (shape or {}).get("files") or [],
                              "tools": (shape or {}).get("tools"), "skill_count": (shape or {}).get("skill_count"),
                              "skill_paths": (shape or {}).get("skill_paths") or [], "pointers": (shape or {}).get("pointers") or [],
                              "lazy": (shape or {}).get("lazy") or {}, "servers": (shape or {}).get("servers") or [],
                              "partial": bool((shape or {}).get("partial")),
                              "deferred_n": sum(len(v) for v in ((shape or {}).get("lazy") or {}).values()),
                              "deferred_names": []})
                r["starts"].append(first)
    return r


def agy_trigger(path):
    """~/.gemini/config/rules/ 和 .agents/rules/ 下的规则文件靠开头的 trigger 决定什么时候加载。
    没写、或写了不认识的值，Antigravity 直接丢掉这个文件，不报错。"""
    t = frontmatter(read_text(path, 4000)).get("trigger", "")
    return t if t in ("always_on", "model_decision", "glob", "manual") else None


def agy_inlines(path, home, depth=0, seen=None):
    """规则文件里 @[标签](路径) 指到的文件：内容会被展开进规则，算进这份规则的大小。"""
    seen = seen if seen is not None else set()
    out = []
    if depth >= 4:
        return out
    base = os.path.dirname(path)
    for m in AGY_INLINE_RE.finditer(strip_code(read_text(path))):
        raw = m.group(1).strip()
        p = expand(raw, home) if raw.startswith("~") else os.path.normpath(os.path.join(base, raw))
        if os.path.isfile(p) and os.path.realpath(p) not in seen:
            seen.add(os.path.realpath(p))
            out.append(p)
            out.extend(agy_inlines(p, home, depth + 1, seen))
    return out


def agy_rules_at(d, home, rd=None):
    """一个目录这一层的规则。返回 (每次都整份加载的, 只给路径和描述的, 被丢掉的)。
    rules/ 只扫一层，子目录里的不算（要靠 rules.json 点名，这里不展开）。"""
    loaded, pointers, dropped = [], [], []
    for sub in ([rd] if rd else [os.path.join(d, x, "rules") for x in AGY_DOT]):
        if not os.path.isdir(sub):
            continue
        for f in sorted(os.listdir(sub)):
            p = os.path.join(sub, f)
            if not f.endswith(".md") or not os.path.isfile(p):
                continue
            t = agy_trigger(p)
            if t == "always_on":
                loaded.append(p)
            elif t == "model_decision":
                pointers.append(p)
            elif t is None:
                dropped.append(p)
    return loaded, pointers, dropped


def agy_global(home):
    """每个 Antigravity 会话都加载的规则：四个全局文件（存在几个就加载几个，不是二选一）加上 config/rules/ 里 always_on 的。"""
    g = gemini_dir(home)
    files = [p for p in (os.path.join(g, "AGENTS.md"), os.path.join(g, "GEMINI.md"),
                         os.path.join(g, "config", "AGENTS.md"), os.path.join(g, "config", "GEMINI.md")) if os.path.isfile(p)]
    loaded, pointers, dropped = agy_rules_at(None, home, os.path.join(g, "config", "rules"))
    files += loaded
    for f in list(files):
        files.extend(agy_inlines(f, home))
    return files, pointers, dropped


def agy_dirs(cwd, home):
    """Antigravity 从工作目录往上找规则和 skill，到仓库根（有 .git 的那层）为止。返回 (目录列表, 是否在仓库里)。
    不在仓库里时只看工作目录本身（官方文档这么写；1.5.18 在系统临时目录里做过对照实验，上级目录的规则和 .agents 都没加载，
    把上级目录登记成 Antigravity 的项目也一样）。"""
    d, dirs = os.path.abspath(cwd), []
    while True:
        dirs.append(d)
        if os.path.exists(os.path.join(d, ".git")):
            return dirs, True
        up = os.path.dirname(d)
        if up == d:
            return [os.path.abspath(cwd)], False
        d = up


def agy_chain(cwd, home):
    files, pointers, dropped = [], [], []
    dirs, in_repo = agy_dirs(cwd, home)
    for d in dirs:
        for sub in ("",) + AGY_DOT:
            for n in AGY_RULE_NAMES:            # 同一层的 AGENTS.md 和 GEMINI.md 都加载，不是二选一
                p = os.path.join(d, sub, n) if sub else os.path.join(d, n)
                if os.path.isfile(p):
                    files.append(p)
        a, b, c = agy_rules_at(d, home)
        files += a
        pointers += b
        dropped += c
    for f in list(files):
        files.extend(agy_inlines(f, home))
    return files, pointers, dropped, in_repo


def agy_manifest(path):
    """skills.json：entries 是额外要加载的目录（每项可以带 include_only / exclude），顶层 exclude 是要藏起来的 skill 的目录名。
    返回 (entries, exclude, 错误, 有没有脚本不展开的 inherits)。"""
    d, err = load_json_file(path)
    if not isinstance(d, dict):
        return [], [], (None if err == "absent" else err or "顶层不是对象"), False
    strs = lambda v: [x for x in v or [] if isinstance(x, str)] if isinstance(v, list) else []
    entries = [{"path": e["path"], "include_only": strs(e.get("include_only")) if "include_only" in e else None, "exclude": strs(e.get("exclude"))}
               for e in d.get("entries") or [] if isinstance(e, dict) and isinstance(e.get("path"), str)]
    return entries, strs(d.get("exclude")), None, bool(d.get("inherits"))


def agy_entry_skills(entry, base_dir, scope):
    """清单里一项 entries 实际点到的 skill：path 可以是一个放着很多 skill 的目录（只扫一层），也可以就是一个 skill 的目录；
    exclude 去掉点名的，include_only 只留点名的（可以点到嵌套一层以下的，比如 database/migrate-schema）。"""
    root = entry["path"] if os.path.isabs(entry["path"]) else os.path.join(base_dir, entry["path"])
    if os.path.isfile(os.path.join(root, "SKILL.md")):
        return list_skills(os.path.dirname(root.rstrip(os.sep)), scope, only=[os.path.basename(root.rstrip(os.sep))])
    if entry["include_only"] is not None:
        out = []
        for name in entry["include_only"]:
            sub = os.path.join(root, *name.split("/"))
            out += list_skills(os.path.dirname(sub), scope, only=[os.path.basename(sub)])
        return out
    return [it for it in list_skills(root, scope) if it["dir"] not in entry["exclude"]]


def agy_rule_size(path, home, depth=0, seen=None):
    """一个规则文件在 Antigravity 眼里有多大（字节）：@[标签](路径) 换成那个文件去掉开头 frontmatter 之后的正文，再量。
    官方的 24,000 字节上限是按这个展开后的大小算的。"""
    seen = seen if seen is not None else set()
    text = read_text(path)
    total = len(text.encode("utf-8"))
    if depth >= 4:
        return total
    base = os.path.dirname(path)
    for m in AGY_INLINE_RE.finditer(strip_code(text)):
        raw = m.group(1).strip()
        p = expand(raw, home) if raw.startswith("~") else os.path.normpath(os.path.join(base, raw))
        if os.path.isfile(p) and os.path.realpath(p) not in seen:
            seen.add(os.path.realpath(p))
            body = re.sub(r"\A---\r?\n.*?\r?\n---\r?\n", "", read_text(p), flags=re.S)
            sub_total = agy_rule_size(p, home, depth + 1, seen) - (len(read_text(p).encode("utf-8")) - len(body.encode("utf-8")))
            total += sub_total - len(m.group(0).encode("utf-8"))
    return total


# ---------------------------------------------------------------- 规则文件与重复

CLAUDE_NAMES =("CLAUDE.md", "CLAUDE.local.md", os.path.join(".claude", "CLAUDE.md"))
IMPORT_RE = re.compile(r"(?:^|(?<=[\s(（:：]))@((?:\\ |[^\s`\"'()（）,，。;；])+)")


def ancestors(cwd, home):
    out, d = [], cwd
    for _ in range(14):
        out.append(d)
        parent = os.path.dirname(d)
        if d == home or parent == d:
            break
        d = parent
    return out


def git_root(cwd, home):
    for d in ancestors(cwd, home):
        if os.path.exists(os.path.join(d, ".git")):
            return d
    return cwd


def broken_links(base):
    """skills 目录下指向不存在位置的软链：skill 已经用不了，入口还留着。"""
    out = []
    if not os.path.isdir(base):
        return out
    for d in sorted(os.listdir(base)):
        p = os.path.join(base, d)
        if os.path.islink(p) and not os.path.exists(p):
            out.append({"path": p, "target": os.readlink(p)})
    return out


def missing_imports(path, home):
    """规则文件里写了 @路径、但那个文件不存在的。只认带扩展名的，避免把 @某人、@scope/包名 算进来。"""
    out = []
    base = os.path.dirname(path)
    for m in IMPORT_RE.finditer(strip_code(read_text(path))):
        raw = m.group(1).replace("\\ ", " ")
        cands = (raw, raw.rstrip(".,;:!?)]}"))
        if not re.search(r"\.[A-Za-z0-9]{1,5}$", cands[1]) or "@" in raw or "://" in raw:
            continue
        ok = False
        for cand in cands:
            p = expand(cand, home) if cand.startswith("~") else os.path.normpath(os.path.join(base, cand))
            if os.path.exists(p):
                ok = True
                break
        if not ok and cands[1] not in out:
            out.append(cands[1])
    return out


def strip_code(text):
    out, fence = [], False
    for ln in text.split("\n"):
        s = ln.strip()
        if s.startswith("```") or s.startswith("~~~"):
            fence = not fence
            out.append("")
            continue
        out.append("" if fence else re.sub(r"`[^`]*`", " ", ln))
    return "\n".join(out)


def imports_of(path, home, depth=0, seen=None):
    seen = seen if seen is not None else set()
    found = []
    if depth >= 4:
        return found
    base = os.path.dirname(path)
    for m in IMPORT_RE.finditer(strip_code(read_text(path))):
        raw = m.group(1).replace("\\ ", " ")
        for cand in (raw, raw.rstrip(".")):
            p = expand(cand, home) if cand.startswith("~") else os.path.normpath(os.path.join(base, cand))
            if os.path.isfile(p):
                rp = os.path.realpath(p)
                if rp not in seen:
                    seen.add(rp)
                    found.append(p)
                    found.extend(imports_of(p, home, depth + 1, seen))
                break
    return found


def rules_in(d, rd=None):
    out = []
    rd = rd or os.path.join(d, ".claude", "rules")
    if os.path.isdir(rd):
        for dp, _dn, fn in os.walk(rd):
            for f in sorted(fn):
                if f.endswith(".md"):
                    out.append(os.path.join(dp, f))
    return out


def claude_global(home):
    files = []
    g = os.path.join(claude_dir(home), "CLAUDE.md")
    if os.path.isfile(g):
        files.append(g)
    files.extend(rules_in(home, os.path.join(claude_dir(home), "rules")))
    for f in list(files):
        files.extend(imports_of(f, home))
    return files


def claude_chain(cwd, home, excludes):
    files, has_claude = [], False
    for d in ancestors(cwd, home):
        for n in CLAUDE_NAMES:
            if d == home and n.startswith(".claude"):
                continue  # 用户级文件单算
            p = os.path.join(d, n)
            if os.path.isfile(p):
                files.append(p)
                has_claude = True
        if d != home:
            files.extend(rules_in(d))
    if not has_claude:
        for d in ancestors(cwd, home):
            p = os.path.join(d, "AGENTS.md")
            if os.path.isfile(p):
                files.append(p)
    # 先按 claudeMdExcludes 排除，再展开 @import：被排除的文件，它 import 的内容也不会加载
    files = [f for f in files if not any(fnmatch.fnmatch(f, pat) for pat in excludes)]
    for f in list(files):
        files.extend(imports_of(f, home))
    return files


def claude_excluded(cwd, home, excludes):
    """这个目录往上，哪些规则文件被 settings.json 的 claudeMdExcludes 排除了。"""
    out = []
    for d in ancestors(cwd, home):
        for n in CLAUDE_NAMES + ("AGENTS.md",):
            p = os.path.join(d, n)
            if os.path.isfile(p) and any(fnmatch.fnmatch(p, pat) for pat in excludes):
                out.append(p)
    return out


def codex_chain(cwd, home):
    root = git_root(cwd, home)
    files = []
    for d in ancestors(cwd, home):
        p = os.path.join(d, "AGENTS.md")
        if os.path.isfile(p):
            files.append(p)
        if d == root:
            break
    return files


def norm_rule(s):
    s = re.sub(r"^\s*([-*+>]|\d+[.)、])\s+", "", s)
    return re.sub(r"[\W_]+", "", s, flags=re.UNICODE).lower()


def weight(s):
    return sum(2 if ord(c) > 0x2E80 else 1 for c in s)


def units_of(path):
    out, fence = [], False
    for i, ln in enumerate(read_text(path).split("\n"), 1):
        s = ln.strip()
        if s.startswith("```") or s.startswith("~~~"):
            fence = not fence
            continue
        if fence or not s or s.startswith("#"):
            continue
        if re.fullmatch(r"@\S+", s) or re.fullmatch(r"[|\s:-]+", s):
            continue
        n = norm_rule(s)
        if weight(n) < 16:
            continue
        out.append((i, s, n))
        if len(out) >= 600:
            break
    return out


def compare_units(ua, ub):
    exact, near = [], []
    index = {}
    for b in ub:
        index.setdefault(b[2], b)
    for a in ua:
        if a[2] in index:
            exact.append((a, index[a[2]]))
            continue
        best = None
        for b in ub:
            la, lb = len(a[2]), len(b[2])
            if min(la, lb) / max(la, lb) < 0.6:
                continue
            sm = difflib.SequenceMatcher(None, a[2], b[2], autojunk=False)
            if sm.real_quick_ratio() < 0.75 or sm.quick_ratio() < 0.75:
                continue
            ratio = sm.ratio()
            if ratio >= 0.75 and (best is None or ratio > best[0]):
                best = (ratio, b)
        if best:
            near.append((a, best[1], round(best[0], 2)))
    return exact, near


# ---------------------------------------------------------------- scan 主流程

def clip(s, n=110):
    s = s.replace("\n", " ")
    return s if len(s) <= n else s[:n] + "…"


def ref_patterns(name):
    e = re.escape(name)
    return re.compile(r"(?:(?<![\w/-])/%s(?![\w-])|`%s`|skills/%s(?![\w-])|「%s」|%s\s*skill)" % (e, e, e, e, e))


def quantile(xs, q):
    """xs 已排序。取分位数，不插值。"""
    return xs[min(len(xs) - 1, int(len(xs) * q))] if xs else 0


HEADING_RE = re.compile(r"^(#{1,3})\s+(.+?)\s*#*\s*$")


def sections_of(path):
    """按一、二、三级标题把规则文件切成几节，量每节多少字符。代码块里的 # 不算标题。"""
    out, cur, fence = [], None, False
    for i, ln in enumerate(read_text(path).split("\n"), 1):
        if ln.lstrip().startswith("```"):
            fence = not fence
        m = None if fence else HEADING_RE.match(ln)
        if m:
            cur = {"title": scrub(clip(m.group(2), 40)), "level": len(m.group(1)), "line": i, "chars": 0}
            out.append(cur)
        if cur is not None:
            cur["chars"] += len(ln) + 1
    return out


SKILL_GROUPS = (
    ("A", "一次没用，也找不到留着的理由", "可以关掉，或只留手动"),
    ("B", "一次没用，但有理由先留着", "逐个看 ⚠ 再定，默认保留"),
    ("C", "只有你手敲过，模型没主动调过", "适合改成「只能手动调」"),
    ("D", "模型只主动调过一两次", "名字说得清的可以「只留名字」"),
    ("E", "在用", "不动"),
)


def skill_group(s):
    if s["total"] == 0:
        return "B" if s["flags"] else "A"
    other = s["codex_reads"] + s.get("agy_reads", 0)        # 别的 agent 按路径读它：改 Claude Code 这边的状态管不到，算在用
    if s["model_calls"] == 0 and other == 0:
        return "C"
    if s["model_calls"] <= 2 and other == 0:
        return "D"
    return "E"


BIG_HANDOFF = 100     # 子代理自己发了这么多次请求，算「大派工」。依据见 delegation_summary 的说明


def delegation_summary(dispatches, sub_runs):
    """主会话派子代理的账：按主模型分，派给各模型多少次；哪些派工大到像是把整件活交了出去。
    一次派工有多大，看那个子代理自己向模型发了多少次请求（它的日志里带用量的回复条数）。
    阈值取 100：查一个事实、搜几个文件、读材料出摘要这类分出去的小活，通常几次到几十次请求就交回；
    上百次请求意味着子代理自己读了、改了、验了一长串，计划和中途的决定多半也是它做的。
    这只是把候选挑出来，是不是用户有意整件交出去的，脚本分不出来。"""
    if not dispatches:
        return None
    by_main = {}
    rows = []
    for d in dispatches:
        run = sub_runs.get(d["id"])
        to = d["to"] or (run["models"].most_common(1)[0][0] if run else "")
        slot = by_main.setdefault(d["main"], {"n": 0, "to": Counter()})
        slot["n"] += 1
        slot["to"][d["to"] or "（没指定）"] += 1
        if run:
            rows.append({"ts": d["ts"], "cwd": d["cwd"], "main": d["main"], "to": to, "type": d["type"],
                         "title": d["title"], "reqs": run["reqs"]})
    sizes = sorted(r["reqs"] for r in rows)
    big = sorted([r for r in rows if r["reqs"] >= BIG_HANDOFF], key=lambda r: -r["reqs"])
    return {"total": len(dispatches), "measured": len(rows), "threshold": BIG_HANDOFF,
            "by_main": {m: {"n": v["n"], "to": dict(v["to"].most_common())} for m, v in
                        sorted(by_main.items(), key=lambda kv: -kv[1]["n"])},
            "median_reqs": quantile(sizes, 0.5) if sizes else None, "max_reqs": sizes[-1] if sizes else None,
            "big_n": len(big), "big": big[:20],
            # 最近的几件小活：给规则里的例子当素材
            "small": sorted([r for r in rows if r["reqs"] < BIG_HANDOFF], key=lambda r: r["ts"], reverse=True)[:12]}


BARE_TOOL_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]*$")


def tool_server(name):
    parts = name.split("__", 2)
    return parts[1] if name.startswith("mcp__") and len(parts) == 3 else None


def tools_table(start, calls, deny):
    """最近一次有记录的新开会话里，发给模型的每个工具：整份带着（常驻）还是只列了名字（按需）、多大、近期调了几次。
    常驻的来自那次请求的工具清单；按需的来自 Claude Code 记下的「延迟加载的工具名」。"""
    if not start or not (start.get("tools") or {}).get("items"):
        return None
    loaded = [(n, c) for n, c in start["tools"]["items"]]
    names = set(n for n, _c in loaded)
    lazy = sorted(set(n for n in start.get("deferred_names") or [] if n not in names))
    rows = [{"name": n, "server": tool_server(n), "load": "常驻", "chars": c} for n, c in loaded]
    rows += [{"name": n, "server": tool_server(n), "load": "按需", "chars": None} for n in lazy]
    # 同一个来源的排在一起（编号连着，用户才能说「12–20 整组关」）：常驻说明最大的来源在前；来源内先常驻（从大到小）后按需
    weight_ = Counter()
    for r in rows:
        weight_[r["server"] or ""] += r["chars"] or 0
    rows.sort(key=lambda r: (-weight_[r["server"] or ""], r["server"] or "", r["load"] != "常驻", -(r["chars"] or 0), r["name"]))
    denied = set(d for d in deny if isinstance(d, str))
    for i, r in enumerate(rows):
        r["n"] = i + 1
        r["calls"] = calls.get(r["name"], 0)
        # 这份清单是那次会话当时的；之后才加进 permissions.deny 的，标出来
        r["denied"] = r["name"] in denied or bool(r["server"] and "mcp__" + r["server"] in denied)
    return {"ts": start.get("ts"), "cwd": start.get("cwd"), "entrypoint": start.get("entrypoint"),
            # ToolSearch 这个工具在场，就是延迟加载开着；不在场时，「按需」名单里的工具其实也整份带着
            "tool_search": "ToolSearch" in names,
            "listed_but_loaded": len([n for n in start.get("deferred_names") or [] if n in names]),
            "items": rows,
            "deny": sorted(d for d in deny if isinstance(d, str) and BARE_TOOL_RE.match(d))}


def startup_summary(starts, now):
    """新开会话第一次请求的实测。只留统计和最近一次的明细，不把每个会话都写进 json。"""
    if not starts:
        return None
    starts = sorted(starts, key=lambda s: s["ts"])
    toks = sorted(s["tokens"] for s in starts)
    week = iso_utc(now - 7 * 86400)
    recent = sorted(s["tokens"] for s in starts if s["ts"] >= week)
    by_cwd = defaultdict(list)
    for s in starts:
        by_cwd[s["cwd"]].append(s)
    rows = []
    for cwd, ss in sorted(by_cwd.items(), key=lambda kv: -len(kv[1]))[:6]:
        t = sorted(x["tokens"] for x in ss)
        rows.append({"cwd": cwd, "n": len(ss), "median": quantile(t, 0.5), "latest": ss[-1]["tokens"],
                     "latest_ts": ss[-1]["ts"], "latest_parts": ss[-1]["parts"]})
    # 拿哪一次来看明细：最近 7 天新开会话最多的那个目录里最近的一次，最能代表用户平时的开局
    pool = [s for s in starts if s["ts"] >= week] or starts
    busiest = Counter(s["cwd"] for s in pool).most_common(1)[0][0]
    focus = [s for s in pool if s["cwd"] == busiest][-1]
    return {"n": len(starts), "median": quantile(toks, 0.5), "p25": quantile(toks, 0.25), "p75": quantile(toks, 0.75),
            "p90": quantile(toks, 0.9), "min": toks[0], "max": toks[-1],
            "recent7": {"n": len(recent), "median": quantile(recent, 0.5)} if recent else None,
            "latest": starts[-1], "focus": focus, "by_cwd": rows,
            "has_shape": any(s.get("tools") is not None for s in starts)}


def context_summary(cl):
    bins = cl.get("bins") or Counter()
    n = sum(bins.values())
    if not n:
        return None
    tok = cl["bin_tokens"]
    total = sum(tok.values())
    over = {}
    for label, b0 in (("200k", 2), ("400k", 4), ("500k", 5)):
        over[label] = {"requests": sum(v for b, v in bins.items() if b >= b0),
                       "tokens": sum(v for b, v in tok.items() if b >= b0)}
    peaks = sorted(cl.get("peaks") or [])
    rw = cl.get("rewrites") or {}
    return {"requests": n, "tokens": total, "bins": {str(b): bins[b] for b in sorted(bins)},
            "bin_tokens": {str(b): tok[b] for b in sorted(tok)}, "over": over,
            "sessions": len(peaks), "peak_median": quantile(peaks, 0.5), "peak_p90": quantile(peaks, 0.9),
            "peak_max": peaks[-1] if peaks else 0,
            "sessions_over": {"400k": sum(1 for p in peaks if p >= 400000), "500k": sum(1 for p in peaks if p >= 500000)},
            "rewrites": {"n": sum(v["n"] for v in rw.values()), "tokens": sum(v["tokens"] for v in rw.values()), "by": rw}}


def auto_memory(c_dir, settings, env, cwds):
    """Claude Code 自带的自动记忆：每个项目一份 MEMORY.md，开头 200 行或 25KB 每个会话都加载。"""
    files = []
    by_slug = {re.sub(r"[^A-Za-z0-9]", "-", c): c for c in cwds}      # 目录名是路径换掉符号得来的，对得上的还原成路径
    for p in glob.glob(os.path.join(c_dir, "projects", "*", "memory", "MEMORY.md")):
        try:
            size = os.path.getsize(p)
        except OSError:
            continue
        lines = read_text(p).count("\n") + 1
        slug = os.path.basename(os.path.dirname(os.path.dirname(p)))
        files.append({"path": p, "project": by_slug.get(slug), "bytes": size, "lines": lines,
                      "over_limit": lines > 200 or size > 25000})
    files.sort(key=lambda f: -f["bytes"])
    off = settings.get("autoMemoryEnabled") is False or str(env.get("CLAUDE_CODE_DISABLE_AUTO_MEMORY")) == "1"
    return {"enabled": not off, "count": len(files), "files": files[:8]}


def do_scan(args, home):
    now = parse_now(args.now)
    cutoff = now - args.days * 86400
    ev = {"tool": "save-my-tokens", "version": VERSION, "home": home, "days": args.days,
          "now": iso_utc(now), "window_start": iso_utc(cutoff), "files": {}}

    def track(p):
        if p and os.path.isfile(p):
            try:
                ev["files"][p] = sha256_file(p)
            except OSError:
                pass

    c_dir, x_dir = claude_dir(home), codex_dir(home)
    has_claude, has_codex = os.path.isdir(c_dir), os.path.isdir(x_dir)
    cl = scan_claude_logs(home, cutoff) if has_claude else {"present": False, "cwds": Counter(), "files": 0}
    cx = scan_codex_logs(home, cutoff) if has_codex else {"present": False, "cwds": Counter(), "files": 0}
    g_dir = gemini_dir(home)
    # ~/.gemini 单独存在不算（旧的 Gemini CLI 也用这个目录）：要有 config/ 或者某个入口的数据目录
    has_agy = os.path.isdir(os.path.join(g_dir, "config")) or bool(agy_app_dirs(home))
    ag = scan_agy_logs(home, cutoff) if has_agy else {"present": False, "cwds": Counter(), "files": 0}

    # ---- Claude Code 配置
    settings_p = os.path.join(c_dir, "settings.json")
    settings, s_err = load_json_file(settings_p)
    settings = settings if isinstance(settings, dict) else {}
    local, _ = load_json_file(os.path.join(c_dir, "settings.local.json"))
    local = local if isinstance(local, dict) else {}
    env = settings.get("env") if isinstance(settings.get("env"), dict) else {}
    track(settings_p)
    track(os.path.join(c_dir, "settings.local.json"))
    overrides = {}
    for src in (settings, local):
        if isinstance(src.get("skillOverrides"), dict):
            overrides.update(src["skillOverrides"])
    cc_version = args.cc_version or cl.get("version")

    claude = {"present": has_claude, "version": cc_version,
              "version_source": "参数" if args.cc_version else ("日志" if cc_version else None),
              "settings_error": None if s_err in (None, "absent") else s_err,
              "log_files": cl.get("files", 0), "log_bytes": cl.get("bytes", 0)}

    # ---- 项目：取近 N 天实际开过会话的目录
    cwd_all = Counter()
    for c, n in cl["cwds"].items():
        cwd_all[c] += n
    for c, n in cx["cwds"].items():
        cwd_all[c] += n
    for c, n in ag["cwds"].items():
        cwd_all[c] += n
    excludes = [expand(x, home) for x in settings.get("claudeMdExcludes", []) if isinstance(x, str)]
    # 同一个仓库常有多个 worktree：规则文件内容完全相同的并成一组；
    # 目录名相同但内容有出入的最多留 3 个，且不占「前几个项目」的名额。
    projects, seen_sig = [], {}
    explicit = [os.path.realpath(expand(p, home)) for p in (args.project or [])]
    cands = explicit + [c for c, _ in cwd_all.most_common(400) if c not in explicit]
    names, per_name = set(), Counter()
    for cwd in cands:
        if cwd == home or not os.path.isdir(cwd):
            continue
        cfiles = claude_chain(cwd, home, excludes) if has_claude else []
        xfiles = codex_chain(cwd, home) if has_codex else []
        afiles, apointers, adropped, a_repo = agy_chain(cwd, home) if has_agy else ([], [], [], True)
        if not cfiles and not xfiles and not afiles and not os.path.isdir(os.path.join(cwd, ".claude")) and not (
                has_agy and any(os.path.isdir(os.path.join(cwd, x)) for x in AGY_DOT)):
            continue
        sig = tuple(sorted(sha256_file(f) for f in set(cfiles + xfiles + afiles)))
        if sig in seen_sig and sig:
            seen_sig[sig]["same_as"].append(cwd)
            seen_sig[sig]["sessions"] += cwd_all.get(cwd, 0)
            continue
        name = os.path.basename(cwd)
        if cwd not in explicit:
            if per_name[name] >= 3 or (name not in names and len(names) >= args.max_projects):
                continue
            names.add(name)
            per_name[name] += 1
        proj = {"cwd": cwd, "sessions": cwd_all.get(cwd, 0), "claude_files": cfiles,
                "codex_files": xfiles, "agy_files": afiles, "agy_pointers": apointers, "agy_dropped": adropped,
                "agy_in_repo": a_repo, "same_as": [],
                "excluded": claude_excluded(cwd, home, excludes) if has_claude and excludes else []}
        seen_sig[sig] = proj
        projects.append(proj)
    ev["projects"] = projects

    # ---- skill
    skills = list_skills(os.path.join(c_dir, "skills"), "user") if has_claude else []
    user_md = {}
    for s in skills:
        s["also_in"] = []
        user_md[s["dir"]] = sha256_file(s["md"])
    seen_ps = {}
    for pr in projects:
        if not has_claude:
            break
        found = []
        for cwd in [pr["cwd"]] + pr["same_as"][:12]:   # 规则文件相同的 worktree 也看一眼
            found += list_skills(os.path.join(cwd, ".claude", "skills"), "project:" + cwd)
        for s in found:
            h = sha256_file(s["md"])
            if (s["dir"], h) in seen_ps:      # 另一个 worktree 里一模一样的同一个 skill
                seen_ps[(s["dir"], h)]["also_in"].append(s["scope"].split(":", 1)[1])
                continue
            s["also_in"] = []
            if s["dir"] in user_md:           # 用户级已经有一个同名的
                s["twin"] = "内容相同" if user_md[s["dir"]] == h else "内容不同"
            seen_ps[(s["dir"], h)] = s
            skills.append(s)
    # ~/.claude.json 只读其中三样：skillUsage、mcpServers、projects[*].mcpServers
    cj = claude_json_path(home)
    usage_cc, _ = load_json_file(cj) if has_claude and cj else (None, None)
    usage_cc = usage_cc if isinstance(usage_cc, dict) else {}
    skill_usage = {}
    for k, v in (usage_cc.get("skillUsage") or {}).items():
        if isinstance(v, dict) and v.get("lastUsedAt"):
            n = k.rsplit(":", 1)[-1]
            skill_usage[n] = max(skill_usage.get(n, 0), v["lastUsedAt"] / 1000.0)

    def by_last_seg(d):
        out = {}
        for k, u in d.items():
            n = k.rsplit(":", 1)[-1]
            o = out.setdefault(n, new_use())
            o["n"] += u["n"]
            o["last"] = max(o["last"], u["last"])
            o["cwds"].update(u["cwds"])
        return out

    sm, su = by_last_seg(cl.get("skill_model", {})), by_last_seg(cl.get("skill_user", {}))
    sr = cx.get("skill_reads", {})
    ar = ag.get("skill_reads", {})

    # 引用语料：规则文件、其他 skill、subagent 定义、hooks
    agents = (list_agents(os.path.join(c_dir, "agents"), "user") if has_claude else [])
    for pr in projects:
        agents += list_agents(os.path.join(pr["cwd"], ".claude", "agents"), "project:" + pr["cwd"])
    global_claude = claude_global(home) if has_claude else []
    global_codex = [p for p in [os.path.join(x_dir, "AGENTS.md")] if os.path.isfile(p)]
    global_agy, agy_gpointers, agy_gdropped = agy_global(home) if has_agy else ([], [], [])
    corpus = []
    for f in set(global_claude + global_codex + global_agy +
                 [f for pr in projects for f in pr["claude_files"] + pr["codex_files"] + pr["agy_files"]]):
        corpus.append((f, read_text(f)))
        track(f)
    for a in agents:
        corpus.append((a["path"], read_text(a["path"])))
        track(a["path"])
    if settings.get("hooks"):
        corpus.append((settings_p + "（hooks）", json.dumps(settings["hooks"], ensure_ascii=False)))
    skill_texts = {s["path"]: (s["dir"], read_text(s["md"])) for s in skills}

    known = set()
    for s in skills:
        track(s["md"])
        names = {s["name"], s["dir"]}
        known |= names
        state = overrides.get(s["name"], overrides.get(s["dir"], "on"))
        if state == "on" and s["manual_only"]:
            state = "user-invocable-only"
        s["state"] = state
        s["model_calls"] = sum(sm.get(n, new_use())["n"] for n in names)
        s["user_calls"] = sum(su.get(n, new_use())["n"] for n in names)
        s["codex_reads"] = sum(sr.get(n, new_use())["n"] for n in names)
        # Antigravity 常把 ~/.gemini/config/skills 下的条目软链到 Claude 的 skill 目录：它读过，这个 skill 就有人在用
        s["agy_reads"] = max([ar.get(n, new_use())["n"] for n in names]) if has_agy else 0
        s["last"] = max([sm.get(n, new_use())["last"] for n in names] +
                        [su.get(n, new_use())["last"] for n in names] +
                        [sr.get(n, new_use())["last"] for n in names] +
                        ([ar.get(n, new_use())["last"] for n in names] if s["agy_reads"] else []))
        cw = Counter()
        for n in names:
            cw.update(sm.get(n, new_use())["cwds"])
            cw.update(su.get(n, new_use())["cwds"])
        s["cwds"] = dict(cw.most_common(3))
        s["total"] = s["model_calls"] + s["user_calls"] + s["codex_reads"] + s["agy_reads"]
        flags = []
        if s["total"] == 0:
            pat = ref_patterns(s["dir"])
            refs = [f for f, t in corpus if pat.search(t)]
            refs += [p for p, (d, t) in skill_texts.items() if d != s["dir"] and pat.search(t)]
            if refs:
                s["referenced_by"] = sorted(set(refs))[:6]
                flags.append("被点名引用")
            if RARE_RE.search(s["dir"] + " " + s["desc"]):
                flags.append("像低频保命项")
            age = (now - s["installed_ts"]) / 86400
            lu = max(skill_usage.get(n, 0) for n in names)
            if age < args.days and not (lu and lu < s["installed_ts"]):
                # skillUsage 里有更早的使用记录时，说明只是文件被重建过，不算新装
                flags.append("装了才 %d 天" % max(age, 0))
            if lu and lu >= cutoff:
                flags.append("skillUsage 记着 %s 用过，日志里没数到" % iso_utc(lu)[:10])
            elif lu:
                s["last_ever"] = iso_utc(lu)[:10]
        s["flags"] = flags
    claude["skills"] = skills
    listings = sorted(cl.get("listings") or [], key=lambda d: d["ts"])
    claude["listing"] = ({"latest": listings[-1], "samples": len(listings),
                          "min": min(d["count"] for d in listings), "max": max(d["count"] for d in listings)}
                         if listings else None)
    claude["broken_skill_links"] = broken_links(os.path.join(c_dir, "skills")) if has_claude else []
    claude["other_skill_calls"] = {k: v["n"] for k, v in sm.items() if k not in known}
    claude["skill_usage_source"] = bool(skill_usage)
    # 用户级、模型看得见的 skill 按用法分成几组：几百个的时候不用一个个过
    groups_sum = {g: {"n": 0, "desc_chars": 0} for g, _t, _a in SKILL_GROUPS}
    for s in skills:
        if s["scope"] == "user" and s["state"] in ("on", "name-only"):
            s["group"] = skill_group(s)
            groups_sum[s["group"]]["n"] += 1
            groups_sum[s["group"]]["desc_chars"] += s["desc_chars"] if s["state"] == "on" else 0
    claude["skill_groups"] = groups_sum

    # ---- 实测：开局带了多少、会话长到多大、哪个模型在跑
    claude["startup"] = startup_summary(cl.get("starts") or [], now)
    st_ = claude["startup"]
    perms = settings.get("permissions") if isinstance(settings.get("permissions"), dict) else {}
    deny_ = perms.get("deny") if isinstance(perms.get("deny"), list) else []
    pick = ((st_.get("focus") if (st_.get("focus") or {}).get("tools") else st_.get("latest")) if st_ else None)
    claude["tools"] = tools_table(pick, cl.get("tool_calls") or {}, deny_)
    # 不同入口（命令行、桌面 app、IDE）开的会话，工具清单不一样：每个别的入口各留最近一次
    alt = {}
    for s_ in sorted(cl.get("starts") or [], key=lambda x: x["ts"]):
        ep = s_.get("entrypoint")
        if ep and claude["tools"] and ep != claude["tools"].get("entrypoint") and (s_.get("tools") or {}).get("items"):
            alt[ep] = s_
    claude["tools_alt"] = {ep: tools_table(s_, cl.get("tool_calls") or {}, deny_) for ep, s_ in alt.items()}
    claude["context"] = context_summary(cl)
    claude["requests_by_model"] = cl.get("req") or {"main": {}, "sub": {}}
    am = cl.get("agent_model") or Counter()
    claude["agent_calls"] = {"total": sum(am.values()), "no_model": am.get("", 0),
                             "by_model": {k: v for k, v in am.most_common() if k}}
    claude["delegation"] = delegation_summary(cl.get("dispatches") or [], cl.get("sub_runs") or {})
    claude["auto_memory"] = auto_memory(c_dir, settings, env, list(cl["cwds"])) if has_claude else None
    ms = settings.get("modelSettings") if isinstance(settings.get("modelSettings"), dict) else {}
    claude["compact_window"] = {
        "env": env.get("CLAUDE_CODE_AUTO_COMPACT_WINDOW"), "settings": settings.get("autoCompactWindow"),
        "per_model": {k: v.get("autoCompactWindow") for k, v in ms.items()
                      if isinstance(v, dict) and v.get("autoCompactWindow") is not None},
        "disabled": settings.get("autoCompactEnabled") is False or str(env.get("DISABLE_AUTO_COMPACT")) == "1"}

    # ---- subagent
    known_agents = set()
    for a in agents:
        known_agents.add(a["name"])
        u = cl.get("agents", {}).get(a["name"], new_use())
        a["calls"], a["last"] = u["n"], u["last"]
    claude["agents"] = agents
    claude["builtin_agent_calls"] = {k: v["n"] for k, v in cl.get("agents", {}).items() if k not in known_agents}

    # ---- MCP（Claude Code）
    mcps = []
    for name, cfg in (usage_cc.get("mcpServers") or {}).items():
        mcps.append(mcp_brief(name, cfg, "user（~/.claude.json）"))
    for pr in projects:
        pj = (usage_cc.get("projects") or {}).get(pr["cwd"]) or {}
        for name, cfg in (pj.get("mcpServers") or {}).items():
            mcps.append(mcp_brief(name, cfg, "local:" + pr["cwd"]))
        mj, _ = load_json_file(os.path.join(pr["cwd"], ".mcp.json"))
        for name, cfg in ((mj or {}).get("mcpServers") or {}).items():
            mcps.append(mcp_brief(name, cfg, "project:" + pr["cwd"]))
    used = {norm_server(k): v for k, v in cl.get("mcp", {}).items()}
    matched = set()
    for m in mcps:
        u = used.get(norm_server(m["name"]))
        matched.add(norm_server(m["name"]))
        m["calls"] = u["n"] if u else 0
        m["last"] = u["last"] if u else ""
        m["tools_used"] = dict(u["tools"].most_common(12)) if u else {}
    claude["mcp"] = mcps
    claude["other_mcp_calls"] = {k: v["n"] for k, v in cl.get("mcp", {}).items() if norm_server(k) not in matched}
    claude["plugins_enabled"] = sorted(k for k, v in (settings.get("enabledPlugins") or {}).items() if v)

    # ---- 开关与确定性问题（Claude Code）
    sw, _ = load_json_file(SWITCHES, config=False)
    sw = sw or {"claude": [], "codex": []}
    rows, problems = [], []
    for item in sw.get("claude", []):
        src = env if item["where"] == "env" else settings
        val = src.get(item["key"], MISSING)
        rows.append({"key": item["key"], "where": item["where"],
                     "value": None if val is MISSING else val, "set": val is not MISSING,
                     "default": item["default"], "what": item["what"], "ask": item.get("ask"),
                     "source": item["source"]})
    vt = ver_tuple(cc_version)
    dam = settings.get("disableAutoMode", MISSING)
    if dam is not MISSING and dam != "disable":
        problems.append("disableAutoMode 当前值是 %s，官方文档写的类型是字符串 \"disable\"，这样写可能不生效。" % json.dumps(dam))
    envw = env.get("CLAUDE_CODE_AUTO_COMPACT_WINDOW")
    if isinstance(envw, str) and re.search(r"[kKmM]$", envw) and vt and vt < (2, 1, 304):
        problems.append("环境变量 CLAUDE_CODE_AUTO_COMPACT_WINDOW=%s 带后缀，v2.1.304 之前不认（当前 %s），改成纯数字。" % (envw, cc_version))
    acw = settings.get("autoCompactWindow")
    if envw is not None and acw is not None and str(acw) != str(envw):
        problems.append("autoCompactWindow=%s 和环境变量 CLAUDE_CODE_AUTO_COMPACT_WINDOW=%s 都设了且不一样，生效的是环境变量。" % (acw, envw))
    for label, v in (("autoCompactWindow", acw), ("CLAUDE_CODE_AUTO_COMPACT_WINDOW", envw)):
        try:
            iv = int(str(v))
        except (TypeError, ValueError):
            continue
        if not 100000 <= iv <= 1000000:
            problems.append("%s=%s 超出官方范围 100000–1000000。" % (label, v))
    boc = settings.get("bashOutputMaxChars")
    if isinstance(boc, int) and not 4000 <= boc <= 128000:
        problems.append("bashOutputMaxChars=%s 超出 4000–128000，会被夹到范围内。" % boc)
    notes = []   # 影响常驻上下文的设置：是取舍，不是错误
    if str(env.get("ENABLE_TOOL_SEARCH", "")).lower() == "false":
        notes.append("ENABLE_TOOL_SEARCH=false：工具说明（MCP 的，和一部分内置的）每轮都常驻上下文，不走「用到才加载」。删掉这个环境变量就回到默认。")
    gateway = bool(env.get("ANTHROPIC_BASE_URL")) and "anthropic.com" not in str(env.get("ANTHROPIC_BASE_URL"))
    if gateway and vt and vt < (2, 1, 181) and str(env.get("CLAUDE_CODE_ATTRIBUTION_HEADER")) != "0":
        problems.append("走自定义网关且版本低于 2.1.181：系统提示词开头带每次请求都变的标记，会破坏网关侧缓存。升级，或设 CLAUDE_CODE_ATTRIBUTION_HEADER=0。")
    for tt in [claude.get("tools")] + [t for _ep, t in sorted((claude.get("tools_alt") or {}).items())]:
        if not (tt and not tt["tool_search"] and any(r["server"] for r in tt["items"] if r["load"] == "常驻")
                and str(env.get("ENABLE_TOOL_SEARCH", "")).lower() != "false"):
            continue
        notes.append("工具延迟加载没生效：%s新开的会话里 MCP 工具说明是整份带着的，而 ENABLE_TOOL_SEARCH 并没有被设成 false%s。原因和改法见 skill 目录下的 references/tool-search.md。" % (
            md(tt["ts"]) + " ", "；这个会话是桌面 app 走第三方网关开的（entrypoint=claude-desktop-3p），正是那份文件讲的情况" if tt.get("entrypoint") == "claude-desktop-3p" else ""))
    for m in mcps:
        if m["alwaysLoad"]:
            notes.append("MCP %s 设了 alwaysLoad：它的工具说明每轮常驻，不走延迟加载（近 %d 天调用 %d 次）。" % (m["name"], args.days, m["calls"]))
    claude["switches"], claude["problems"], claude["gateway"], claude["notes"] = rows, problems, gateway, notes

    # ---- /doctor prompt-audit 能不能调
    pa = {"checks": [], "available": None}
    if has_claude:
        ok = True
        if not vt:
            pa["checks"].append("版本未知（没有日志）。先跑 claude --version，要 2.1.283 以上。")
            ok = None
        elif vt < (2, 1, 283):
            pa["checks"].append("版本 %s 低于 2.1.283：先升级 Claude Code。" % cc_version)
            ok = False
        else:
            pa["checks"].append("版本 %s，够（要 2.1.283 以上）。" % cc_version)
        if settings.get("disableBundledSkills") is True or str(env.get("CLAUDE_CODE_DISABLE_BUNDLED_SKILLS")) == "1":
            pa["checks"].append("disableBundledSkills 开着：内置 skill 全关，prompt-audit 用不了。")
            ok = False
        for n in ("claude-api", "doctor"):
            st = overrides.get(n)
            if st and st != "on":
                pa["checks"].append("skillOverrides 里 %s 是 %s：prompt-audit 要靠它，得先改回 on。" % (n, json.dumps(st)))
                ok = False
        if str(env.get("DISABLE_DOCTOR_COMMAND")) == "1":
            pa["checks"].append("DISABLE_DOCTOR_COMMAND=1：/doctor 被隐藏。")
            ok = False
        pa["available"] = ok
    # 调不了时的退路：官方那份说明文件本身。本机的插件市场克隆或插件缓存里常有一份。
    pa["official_url"] = PROMPT_AUDIT_URL
    copies = []
    plug = os.path.join(c_dir, "plugins")
    for pat in (("marketplaces", "*"), ("cache", "*", "*", "*")):
        copies += glob.glob(os.path.join(plug, *pat, "skills", "claude-api", "shared", "prompt-audit.md"))
    copies = [p for p in copies if os.path.isfile(p)]
    if copies:
        best = max(copies, key=os.path.getmtime)
        pa["official_file"] = {"path": best, "date": iso_utc(os.path.getmtime(best))[:10]}
    else:
        pa["official_file"] = None
    claude["prompt_audit"] = pa
    ev["claude"] = claude

    # ---- Codex
    codex = {"present": has_codex, "version": cx.get("version"), "log_files": cx.get("files", 0),
             "log_bytes": cx.get("bytes", 0)}
    if has_codex:
        cfg_p = os.path.join(x_dir, "config.toml")
        cfg, degraded, c_err = load_toml_file(cfg_p)
        track(cfg_p)
        codex["config_error"] = None if c_err in (None, "absent") else c_err
        codex["toml_degraded"] = degraded
        cfg = cfg if isinstance(cfg, dict) else {}
        codex["switches"] = [{"key": i["key"], "value": cfg.get(i["key"]), "set": i["key"] in cfg,
                              "default": i["default"], "what": i["what"], "source": i["source"]}
                             for i in sw.get("codex", [])]
        xp = []
        pct = cfg.get("model_post_turn_compact_threshold_percent")
        if isinstance(pct, (int, float)) and not 0 <= pct <= 100:
            xp.append("model_post_turn_compact_threshold_percent=%s 超出 0–100。" % pct)
        limit = cfg.get("project_doc_max_bytes", 32768)
        over = {}
        for pr in projects:
            total = sum(os.path.getsize(f) for f in pr["codex_files"])
            if isinstance(limit, int) and total > limit:
                key = tuple(sorted(sha256_file(f) for f in pr["codex_files"]))
                if key in over:
                    over[key][1] += 1 + len(pr["same_as"])
                else:
                    over[key] = ["%s 的 AGENTS.md 合计 %d 字节，超过 project_doc_max_bytes=%d。按官方 schema 的说明，超出部分 Codex 读不到。" % (show(pr["cwd"], home), total, limit), len(pr["same_as"])]
        for text, more in over.values():
            xp.append(text + ("（另有 %d 个目录情况相同）" % more if more else ""))
        g = os.path.join(x_dir, "AGENTS.md")
        codex["global_agents_bytes"] = os.path.getsize(g) if os.path.isfile(g) else None
        used_x = {norm_server(k): v for k, v in cx.get("mcp", {}).items()}
        xm, matched = [], set()
        for name, c in (cfg.get("mcp_servers") or {}).items():
            b = mcp_brief(name, c, "config.toml")
            u = used_x.get(norm_server(name))
            matched.add(norm_server(name))
            b["calls"], b["last"] = (u["n"], u["last"]) if u else (0, "")
            b["tools_used"] = dict(u["tools"].most_common(12)) if u else {}
            xm.append(b)
        codex["mcp"] = xm
        codex["other_mcp_calls"] = {k: v["n"] for k, v in cx.get("mcp", {}).items() if norm_server(k) not in matched}
        sk_cfg = (cfg.get("skills") or {}).get("config") if isinstance(cfg.get("skills"), dict) else None
        # 停用条目有两种写法：按 path、按 name。path 先解析成真实路径再比：
        # ~/.codex/skills 是指向别处的软链时，配置里写的常常是软链另一头的路径
        disabled, disabled_real = set(), set()
        for e in sk_cfg or []:
            if isinstance(e, dict) and e.get("enabled") is False:
                if isinstance(e.get("path"), str) and e["path"]:
                    disabled_real.add(os.path.realpath(expand(e["path"], home)))
                if isinstance(e.get("name"), str) and e["name"]:
                    disabled.add(e["name"])
        xs = list_skills(os.path.join(x_dir, "skills"), "codex")
        for s in xs:
            track(s["md"])
            u = sr.get(s["dir"], sr.get(s["name"], new_use()))
            s["reads"], s["last"] = u["n"], u["last"]
            s["enabled"] = not (os.path.realpath(s["md"]) in disabled_real or os.path.realpath(s["path"]) in disabled_real
                                or s["name"] in disabled or s["dir"] in disabled)
            flags = []
            if s["reads"] == 0:
                if RARE_RE.search(s["dir"] + " " + s["desc"]):
                    flags.append("像低频保命项")
                if (now - s["installed_ts"]) / 86400 < args.days:
                    flags.append("装了才 %d 天" % max((now - s["installed_ts"]) / 86400, 0))
            s["flags"] = flags
        codex["skills"] = xs
        codex["skills_shared_with_claude"] = bool(
            has_claude and os.path.isdir(os.path.join(c_dir, "skills"))
            and os.path.realpath(os.path.join(x_dir, "skills")) == os.path.realpath(os.path.join(c_dir, "skills")))
        codex["problems"] = xp
        ad = os.path.join(x_dir, "agents")
        codex["agents"] = sorted(f[:-5] for f in os.listdir(ad) if f.endswith(".toml")) if os.path.isdir(ad) else []
    ev["codex"] = codex

    # ---- Antigravity
    agy = {"present": has_agy, "entries": ag.get("dirs") or [], "log_files": ag.get("files", 0), "log_bytes": ag.get("bytes", 0)}
    if has_agy:
        cfg_dir = os.path.join(g_dir, "config")
        st_a = startup_summary(ag.get("starts") or [], now)
        agy["startup"] = st_a
        # 每个入口（命令行、桌面 app、IDE）各留最近一次带明细的新开会话：它们带的工具和 skill 不一样
        by_entry = {}
        for s_ in sorted(ag.get("starts") or [], key=lambda x: x["ts"]):
            if s_.get("tools") is not None or s_["entrypoint"] not in by_entry:
                by_entry[s_["entrypoint"]] = s_
        agy["by_entry"] = {e: {"ts": s_["ts"], "cwd": s_["cwd"], "tokens": s_["tokens"], "model": s_["model"],
                               "n": sum(1 for x in ag["starts"] if x["entrypoint"] == e),
                               "median": quantile(sorted(x["tokens"] for x in ag["starts"] if x["entrypoint"] == e), 0.5)}
                           for e, s_ in by_entry.items()}
        agy["no_shape"] = ag.get("no_db", 0)
        agy["kind_unknown"] = ag.get("kind_unknown", 0)
        agy["start_no_usage"] = ag.get("start_no_usage", 0)
        agy["partial_shape"] = ag.get("partial_shape", 0)
        agy["wal_pending"] = ag.get("wal_pending", 0)
        agy["context"] = context_summary(ag)
        cks = sorted(c_["before"] for c_ in ag.get("checkpoints") or [])
        agy["compactions"] = {"n": len(cks), "median": quantile(cks, 0.5), "min": cks[0], "max": cks[-1],
                              "by_entry": {e: {"n": len(v), "median": quantile(v, 0.5)} for e, v in sorted(
                                  (e, sorted(c_["before"] for c_ in ag["checkpoints"] if c_["entry"] == e))
                                  for e in set(c_["entry"] for c_ in ag["checkpoints"]))}} if cks else None
        agy["requests_by_model"] = ag.get("req") or {"main": {}, "sub": {}}
        agy["model_from_db"] = ag.get("model_from_db", 0)
        agy["model_unknown"] = ag.get("model_unknown", 0)
        am_a = ag.get("agent_model") or Counter()
        agy["agent_calls"] = {"total": sum(am_a.values()), "no_model": am_a.get("", 0),
                              "by_model": {k: v for k, v in am_a.most_common() if k}}
        runs = sorted(ag.get("sub_runs") or [], key=lambda x: -x["reqs"])
        sizes = sorted(x["reqs"] for x in runs)
        agy["sub_runs"] = {"n": len(runs), "median": quantile(sizes, 0.5), "max": sizes[-1], "threshold": BIG_HANDOFF,
                           "big": [x for x in runs if x["reqs"] >= BIG_HANDOFF][:12]} if runs else None
        agy["subagent_types"] = {k: v["n"] for k, v in sorted(ag.get("agents", {}).items(), key=lambda kv: -kv[1]["n"])}

        # 规则：全局的、被丢掉的、超过上限的
        agy["global_files"] = global_agy
        agy["pointers"] = sorted(set(agy_gpointers + [f for pr in projects for f in pr["agy_pointers"]]))
        dropped = sorted(set(agy_gdropped + [f for pr in projects for f in pr["agy_dropped"]]))
        ap = []
        for f in dropped:
            ap.append("%s 开头没有写 trigger（或写了 Antigravity 不认识的值）：rules/ 目录下的规则文件必须在开头声明 "
                      "trigger: always_on / model_decision / glob / manual，否则整个文件被丢掉、不报错。" % show(f, home))
        all_agy = global_agy + [f for pr in projects for f in pr["agy_files"]]
        # 被 @[标签](路径) 展开进别的规则里的文件，自己不单独算一份规则，大小算在引用它的那个文件头上
        seen_cap = set(os.path.realpath(x) for f in all_agy for x in agy_inlines(f, home))
        for f in all_agy:
            rp = os.path.realpath(f)
            if rp in seen_cap:
                continue
            seen_cap.add(rp)
            try:
                size = agy_rule_size(f, home)
            except OSError:
                continue
            if size > AGY_RULE_CAP:
                ap.append("%s 有 %d 字节（它用 @[标签](路径) 展开进来的正文也算在内），超过 Antigravity 每个规则文件 %d 字节的上限。"
                          "超出的部分被截掉，模型读不到（官方文档写明；实机的会话记录里也看到被截的文件末尾只剩一句 <truncated N bytes>）。" % (show(f, home), size, AGY_RULE_CAP))
        agy["problems"] = ap
        # 自查：按上面的规则算出来的加载清单，和最近一次新开会话里 Antigravity 实际发给模型的规则清单对一遍
        agy["chain_check"] = None
        for s_ in sorted(ag.get("starts") or [], key=lambda x: x["ts"], reverse=True):
            if not s_.get("files") or not s_["cwd"] or not os.path.isdir(s_["cwd"]):
                continue
            inl = set(os.path.realpath(x) for f in global_agy for x in agy_inlines(f, home))
            cf, in_repo = [], True
            for w_ in s_.get("cwds") or [s_["cwd"]]:
                f_, _p, _d, r_ = agy_chain(w_, home)
                cf += f_
                in_repo = in_repo and r_
            inl |= set(os.path.realpath(x) for f in cf for x in agy_inlines(f, home))
            standalone = set(os.path.realpath(os.path.join(g_dir, *x)) for x in (("AGENTS.md",), ("GEMINI.md",), ("config", "AGENTS.md"), ("config", "GEMINI.md")))
            want = set(os.path.realpath(f) for f in global_agy + cf) - inl - standalone
            got = set(os.path.realpath(f["path"]) for f in s_["files"] if f["path"] != "user_global")
            n_glob = sum(1 for f in s_["files"] if f["path"] == "user_global")
            want_glob = sum(1 for x in standalone if os.path.isfile(x))
            agy["chain_check"] = {"ts": s_["ts"], "cwd": s_["cwd"], "in_repo": in_repo,
                                  "only_computed": sorted(want - got), "only_logged": sorted(got - want),
                                  "global_logged": n_glob, "global_computed": want_glob,
                                  "ok": want == got and n_glob == want_glob}
            break

        # skill：全局的、只有命令行读的两个目录、~/.agents/skills、skills.json 点名的、项目里的
        entries, exclude, m_err, m_inherits = agy_manifest(os.path.join(cfg_dir, "skills.json"))
        track(os.path.join(cfg_dir, "skills.json"))
        agy["manifest_error"] = m_err
        agy["exclude"] = exclude
        a_sk = list_skills(os.path.join(g_dir, "antigravity-cli", "skills"), "cli-only")
        a_sk += list_skills(os.path.join(g_dir, "skills"), "cli-only")
        a_sk += list_skills(os.path.join(cfg_dir, "skills"), "global")
        for e_ in entries:
            a_sk += agy_entry_skills(e_, cfg_dir, "manifest")
        # ~/.agents/skills：命令行 1.5.16 起当作全局 skill 目录读（更新日志写明），同名时 ~/.gemini 下的优先
        a_sk += list_skills(os.path.join(home, ".agents", "skills"), "agents-home")
        seen_pk = set()
        for pr in projects:
            for d in agy_dirs(pr["cwd"], home)[0]:
                for x in AGY_DOT:
                    base = os.path.join(d, x, "skills")
                    if os.path.realpath(base) in seen_pk or not os.path.isdir(base) or (d == home and x == ".agents"):
                        continue
                    seen_pk.add(os.path.realpath(base))
                    a_sk += list_skills(base, "project:" + d)
        builtin, builtin_n = set(), 0
        for app in ag.get("dirs") or agy_app_dirs(home):
            bd = os.path.join(g_dir, app, "builtin", "skills")
            if os.path.isdir(bd):
                found = list_skills(bd, "builtin")
                builtin_n = max(builtin_n, len(found))
                for it in found:
                    builtin.update((it["name"], it["dir"]))
        agy["builtin_skills"] = sorted(builtin)
        agy["builtin_skill_count"] = builtin_n
        c_real = os.path.realpath(os.path.join(c_dir, "skills")) if has_claude else None
        latest_listed = None
        for s_ in sorted(ag.get("starts") or [], key=lambda x: x["ts"]):
            if s_.get("skill_paths"):
                latest_listed = s_
        arp = ag.get("skill_read_paths") or {}
        dir_count = Counter(it["dir"] for it in a_sk)
        user_level = {}        # 名字 → 用户级里优先级最高的那一份（a_sk 的顺序就是优先级：命令行专用 > ~/.gemini/config > ~/.agents）
        for it in a_sk:
            track(it["md"])
            # 读过几次：按文件的真实路径归到具体那一份；目录名只此一家的，再用按名字数的那份兜底（会话里走软链等别的路径读的也算）
            u = arp.get(os.path.realpath(it["path"]), new_use())
            if dir_count[it["dir"]] == 1 and ar.get(it["dir"], new_use())["n"] > u["n"]:
                u = ar[it["dir"]]
            it["reads"], it["last"] = u["n"], u["last"]
            it["shared_with_claude"] = bool(c_real and inside(os.path.realpath(it["path"]), c_real))
            flags = []
            if it["dir"] in exclude:
                # 排除名单按目录名匹配（实测：写 SKILL.md 里的 name 不生效）；管不到只有命令行读的那两个目录（官方文档写明，实测也是）
                it["state"] = "on" if it["scope"] == "cli-only" else "excluded"
                if it["scope"] == "cli-only":
                    flags.append("写进了排除名单，但这个目录不受排除名单管，命令行里照样加载")
            elif it["manual_only"]:
                it["state"] = "manual"          # SKILL.md 里写了 disable-model-invocation: true：不进发给模型的清单（实测）
            else:
                it["state"] = "on"
                if it["name"] in exclude and it["name"] != it["dir"]:
                    flags.append("排除名单里写的是它的 name（%s），Antigravity 按目录名（%s）匹配，实际没排除掉" % (it["name"], it["dir"]))
            if it["state"] == "on" and not it["scope"].startswith("project:"):
                win = user_level.get(it["name"])
                if win is None:
                    user_level[it["name"]] = it
                elif win["scope"] == "cli-only" and it["scope"] != "cli-only":
                    # 命令行里同名的那份优先；桌面 app 不读命令行专用目录，那边加载的还是这一份
                    flags.append("命令行里被 %s 里同名的那份盖住，只在桌面 app 里加载" % show(os.path.dirname(win["path"]), home))
                else:
                    it["state"] = "shadowed"    # 同名、优先级低：不进发给模型的清单（官方文档的优先级 + 实测）
                    it["shadowed_by"] = win["path"]
            if it["state"] == "on" and it["scope"].startswith("project:") and it["name"] in user_level:
                flags.append("和全局的一个 skill 同名：在这个项目里用的是项目这份")
            if it["reads"] == 0 and it["state"] == "on":
                pat = ref_patterns(it["dir"])
                refs = [f for f, t in corpus if pat.search(t)]
                if refs:
                    it["referenced_by"] = sorted(set(refs))[:6]
                    flags.append("被点名引用")
                if RARE_RE.search(it["dir"] + " " + it["desc"]):
                    flags.append("像低频保命项")
                age = (now - it["installed_ts"]) / 86400
                if age < args.days:
                    flags.append("装了才 %d 天" % max(age, 0))
            it["flags"] = flags
            if it["state"] == "on" and it["scope"] in ("global", "manifest", "agents-home"):
                it["group"] = ("B" if flags else "A") if it["reads"] == 0 else "E"
        agy["skills"] = a_sk
        agy["broken_skill_links"] = broken_links(os.path.join(cfg_dir, "skills"))
        agy["listing"] = ({"ts": latest_listed["ts"], "cwd": latest_listed["cwd"], "entry": latest_listed["entrypoint"],
                           "count": latest_listed["skill_count"], "chars": latest_listed["parts"].get("skills", 0)}
                          if latest_listed else None)
        # 自查：按上面的规则算「这个会话该看到哪些 skill」，和它实际发给模型的清单（去掉内置的）对一遍
        agy["skills_check"], agy["skills_checks"] = None, []        # 每个入口各查最近的一个会话；skills_check 是其中最新的那个
        for s_ in sorted(ag.get("starts") or [], key=lambda x: x["ts"], reverse=True):
            if not s_.get("skill_paths") or not s_["cwd"] or not os.path.isdir(s_["cwd"]):
                continue
            if any(c_["entry"] == s_["entrypoint"] for c_ in agy["skills_checks"]):
                continue
            cli = s_["entrypoint"] == "antigravity-cli"
            cand = [it for it in a_sk if it["scope"] == "cli-only"] if cli else []
            for w_ in s_.get("cwds") or [s_["cwd"]]:
                for d in agy_dirs(w_, home)[0]:
                    for x in AGY_DOT:
                        if not (d == home and x == ".agents"):
                            cand += list_skills(os.path.join(d, x, "skills"), "project:" + d)
            cand += [it for it in a_sk if it["scope"] in ("global", "manifest")]
            if cli:
                cand += [it for it in a_sk if it["scope"] == "agents-home"]
            want, taken = set(), set()
            for it in cand:
                if it["manual_only"] or (it["dir"] in exclude and it["scope"] != "cli-only") or it["name"] in taken:
                    continue
                taken.add(it["name"])
                want.add(os.path.realpath(it["path"]))
            got = set(os.path.realpath(os.path.dirname(p_)) for p_ in s_["skill_paths"] if "/builtin/skills/" not in p_)
            agy["skills_checks"].append({"ts": s_["ts"], "cwd": s_["cwd"], "entry": s_["entrypoint"], "ok": want == got,
                                         "only_computed": sorted(want - got), "only_logged": sorted(got - want), "n": len(got)})
        if agy["skills_checks"]:
            agy["skills_check"] = agy["skills_checks"][0]
        known_a = set(n for it in a_sk for n in (it["name"], it["dir"])) | builtin
        agy["other_skill_reads"] = {k: v["n"] for k, v in sorted(ar.items(), key=lambda kv: -kv[1]["n"]) if k not in known_a}
        agy["manifest_inherits"] = m_inherits

        # MCP：全局 mcp_config.json，加上各项目的 .agents/mcp_config.json
        a_mcp, mcp_errors = [], []
        srcs, seen_mc = [(os.path.join(cfg_dir, "mcp_config.json"), "global")], set()
        for pr in projects:
            for d in agy_dirs(pr["cwd"], home)[0]:      # 和规则一样，从工作目录往上找到仓库根
                for x in AGY_DOT:
                    mp = os.path.join(d, x, "mcp_config.json")
                    if os.path.realpath(mp) not in seen_mc:
                        seen_mc.add(os.path.realpath(mp))
                        srcs.append((mp, "project:" + d))
        for path, scope in srcs:
            mj, e_ = load_json_file(path)
            if e_ == "absent":
                continue
            track(path)
            if not isinstance(mj, dict):
                mcp_errors.append("%s 解析失败（%s）。" % (show(path, home), e_ or "顶层不是对象"))
                continue
            for name, c_ in (mj.get("mcpServers") or {}).items():
                c_ = c_ if isinstance(c_, dict) else {}
                tl = c_.get("tools") if isinstance(c_.get("tools"), dict) else {}
                on_disk = 0
                for app in ag.get("dirs") or []:
                    td = os.path.join(g_dir, app, "mcp", name)
                    if os.path.isdir(td):
                        on_disk = max(on_disk, len([f for f in os.listdir(td) if f.endswith(".json")]))
                allow = c_.get("enabledTools") if isinstance(c_.get("enabledTools"), list) else None
                deny = c_.get("disabledTools") if isinstance(c_.get("disabledTools"), list) else []
                marked = sorted(k for k, v in tl.items() if isinstance(v, dict) and v.get("eager") is True)
                # 官方文档：先过放行和屏蔽名单，再看 eager。被屏蔽的工具写了 eager 也不会常驻
                eager = [k for k in marked if k not in deny and (allow is None or k in allow)]
                a_mcp.append({"name": name, "scope": scope, "file": path,
                              "transport": "http" if (c_.get("url") or c_.get("serverUrl")) else "stdio",
                              "disabled": c_.get("disabled") is True,
                              "enabled_tools": allow, "disabled_tools": deny,
                              "eager": [] if c_.get("disabled") is True else eager,
                              "eager_blocked": [k for k in marked if k not in eager],
                              "tools_on_disk": on_disk})
        used_a = {k: {"n": v["n"], "last": v["last"], "tools": Counter(v["tools"])} for k, v in ag.get("mcp", {}).items()}
        # 常驻（eager）的 MCP 工具在日志里叫 mcp_<server>_<tool>：按配置里的 server 名（最长的优先）拆回去
        stray = {}
        for raw, v in (ag.get("raw_mcp_tools") or {}).items():
            srv = max((m["name"] for m in a_mcp if raw.startswith("mcp_%s_" % m["name"])), key=len, default=None)
            if srv is None:
                stray[raw] = v["n"]
                continue
            u = used_a.setdefault(srv, {"n": 0, "last": "", "tools": Counter()})
            u["n"] += v["n"]
            u["tools"][raw[len("mcp_%s_" % srv):]] += v["n"]
            u["last"] = max(u["last"], v["last"])
        for m in a_mcp:
            u = used_a.get(m["name"])
            m["calls"], m["last"] = (u["n"], u["last"]) if u else (0, "")
            m["tools_used"] = dict(u["tools"].most_common(12)) if u else {}
        agy["mcp"] = a_mcp
        agy["mcp_errors"] = mcp_errors
        agy["other_mcp_calls"] = dict({k: v["n"] for k, v in used_a.items() if k not in set(m["name"] for m in a_mcp)}, **stray)

        # hook、插件、命令行设置：只报名字和几个不敏感的键
        hk, h_err = load_json_file(os.path.join(cfg_dir, "hooks.json"))
        track(os.path.join(cfg_dir, "hooks.json"))
        agy["hooks"] = [{"name": k, "enabled": v.get("enabled", True) is not False,
                         "events": sorted(e_ for e_ in v if e_ != "enabled")}
                        for k, v in sorted((hk or {}).items()) if isinstance(v, dict)] if isinstance(hk, dict) else []
        cj_a, _e = load_json_file(os.path.join(cfg_dir, "config.json"))
        pl = cj_a.get("plugins") if isinstance(cj_a, dict) and isinstance(cj_a.get("plugins"), dict) else {}
        agy["plugins"] = {k: (v.get("enabled") is not False if isinstance(v, dict) else True) for k, v in sorted(pl.items())}
        cli_s, _e = load_json_file(os.path.join(g_dir, "antigravity-cli", "settings.json"))
        cli_s = cli_s if isinstance(cli_s, dict) else {}
        agy["switches"] = [{"key": i["key"], "where": i.get("where", ""), "value": os.environ.get(i["key"]) if i.get("where") == "env" else None,
                            "set": i.get("where") == "env" and bool(os.environ.get(i["key"])), "default": i["default"], "what": i["what"], "source": i["source"]}
                           for i in sw.get("antigravity", [])]
        agy["env_compact"] = os.environ.get("AGY_CLI_AUTO_COMPACT_OVERRIDE")
        # 公开的设置清单里没有 contextWindow 这个键，但实机的命令行设置里见过：只报它在，不解释、不建议改
        agy["cli_context_window"] = cli_s.get("contextWindow") if isinstance(cli_s.get("contextWindow"), (str, int)) else None
        agy["manifests"] = sorted(set(
            [f for f in (os.path.join(cfg_dir, "rules.json"),) if os.path.isfile(f)]
            + ([os.path.join(cfg_dir, "skills.json")] if agy.get("manifest_inherits") else [])
            + [os.path.join(d, x, n) for pr in projects for d in agy_dirs(pr["cwd"], home)[0] for x in AGY_DOT
               for n in ("rules.json", "skills.json") if os.path.isfile(os.path.join(d, x, n))]))
        legacy, _e = load_json_file(os.path.join(g_dir, "settings.json"))
        agy["legacy_settings"] = sorted(k for k in ("mcpServers", "hooks") if isinstance(legacy, dict) and legacy.get(k))
    ev["antigravity"] = agy

    # ---- 重复规则
    groups = {}
    for pr in projects:
        if has_claude:
            groups["claude@" + pr["cwd"]] = set(os.path.realpath(f) for f in global_claude + pr["claude_files"])
        if has_codex:
            groups["codex@" + pr["cwd"]] = set(os.path.realpath(f) for f in global_codex + pr["codex_files"])
        if has_agy:
            groups["agy@" + pr["cwd"]] = set(os.path.realpath(f) for f in global_agy + pr["agy_files"])
    if not projects:
        if has_claude and global_claude:
            groups["claude@~"] = set(os.path.realpath(f) for f in global_claude)
        if has_codex and global_codex:
            groups["codex@~"] = set(os.path.realpath(f) for f in global_codex)
        if has_agy and global_agy:
            groups["agy@~"] = set(os.path.realpath(f) for f in global_agy)
    all_files = sorted(set().union(*groups.values())) if groups else []
    file_groups = defaultdict(set)
    for gname, fs in groups.items():
        for f in fs:
            file_groups[f].add(gname)
    units = {f: units_of(f) for f in all_files}
    hashes = {f: sha256_file(f) for f in all_files}
    is_global = set(os.path.realpath(f) for f in global_claude + global_codex + global_agy)
    dups = []
    for i, a in enumerate(all_files):
        for b in all_files[i + 1:]:
            ga, gb = file_groups[a], file_groups[b]
            if ga & gb:
                rel = "same_session"
            elif (a in is_global) == (b in is_global) and any(
                    x.split("@", 1)[1] == y.split("@", 1)[1] and x.split("@", 1)[0] != y.split("@", 1)[0]
                    for x in ga for y in gb):
                # 对应的两份：全局对全局，或同一个项目里的 CLAUDE.md 对 AGENTS.md
                rel = "cross_agent"
            else:
                continue              # 不同项目、或一端全局一端项目的，不比
            # 这两个文件在谁的会话里会一起加载（同一会话重复时才有意义）
            who = sorted(set(x.split("@", 1)[0] for x in ga & gb))
            if hashes[a] == hashes[b]:
                if not units[a]:
                    continue          # 两个都只是一行 @import 之类的指针文件，没有规则可重复
                dups.append({"a": a, "b": b, "relation": rel, "in": who, "identical_file": True, "exact": [], "near": []})
                continue
            exact, near = compare_units(units[a], units[b])
            if not exact and not near:
                continue
            dups.append({
                "a": a, "b": b, "relation": rel, "in": who, "identical_file": False,
                "exact": [{"a_line": x[0], "b_line": y[0], "text": scrub(clip(x[1]))} for x, y in exact],
                "near": [{"a_line": x[0], "b_line": y[0], "a_text": scrub(clip(x[1])), "b_text": scrub(clip(y[1])), "ratio": r_}
                         for x, y, r_ in near]})
    ev["duplicates"] = dups
    ev["instruction_files"] = [{"path": f, "bytes": os.path.getsize(f), "rules": len(units[f]), "sha256": hashes[f],
                                "chars": len(read_text(f)),
                                "lines": read_text(f).count("\n") + 1, "missing_imports": missing_imports(f, home),
                                "every_session": f in is_global,
                                "sections": sorted(sections_of(f), key=lambda s: -s["chars"])[:6],
                                "loaded_by": sorted(file_groups[f])} for f in all_files]

    # ---- 日志覆盖
    cov = {}
    for label, r in (("claude", cl), ("codex", cx), ("agy", ag)):
        if r.get("present") and (r.get("earliest") or r.get("older_evidence")):
            first = iso_to_ts(r["earliest"]) if r.get("earliest") else cutoff
            cov[label] = {"earliest_in_window": (r.get("earliest") or "")[:10],
                          "full_window": bool(r.get("older_evidence")),
                          "days_covered": int(min((now - first) / 86400, args.days)),
                          "unreadable_compressed": r.get("unreadable", 0)}
    ev["coverage"] = cov
    ev["backups"] = [{"id": m["id"], "note": m.get("note"), "state": backup_state(m)} for m in all_manifests(home)]

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            f.write(hide_known(json.dumps(ev, ensure_ascii=False, indent=1,
                                          default=lambda o: dict(o) if isinstance(o, Counter) else str(o)), as_json=True))
    print(hide_known(render(ev, home, args.all)))


AGENT_NAMES = {"claude": "Claude Code", "codex": "Codex", "agy": "Antigravity"}


def readers_note(f):
    """规则文件是哪个 agent 在读。Claude Code 读的不标（默认）；只有别的 agent 读的，写明是谁。"""
    who = sorted(set(g.split("@", 1)[0] for g in f.get("loaded_by") or []))
    if not who or "claude" in who:
        return ""
    return "  %s 读的" % "、".join(AGENT_NAMES.get(w, w) for w in who)


def md(ts):
    """日志里的时间是 UTC，报给用户的日期按这台电脑的本地时间。"""
    if not ts:
        return "—"
    t = iso_to_ts(ts)
    return time.strftime("%m-%d", time.localtime(t)) if t else ts[5:10]


def render(ev, home, show_all):
    L = []
    cap = 10 ** 6 if show_all else 25
    c, x = ev["claude"], ev["codex"]
    days = ev["days"]
    L.append("save-my-tokens 扫描（只读，没有改任何文件）")
    L.append("范围：%s   窗口：近 %d 天（%s 起）" % (show(home, home), days, ev["window_start"][:10]))
    L.append("Claude Code：%s   Codex：%s" % (
        ("有，版本 %s，窗口内 %d 个会话文件" % (c["version"] or "未知", c["log_files"])) if c["present"] else "没有",
        ("有，版本 %s，窗口内 %d 个会话文件" % (x["version"] or "未知", x["log_files"])) if x["present"] else "没有"))
    gy = ev.get("antigravity") or {"present": False}
    if gy["present"]:
        L.append("Antigravity：有，窗口内 %d 个会话文件（%s）" % (gy["log_files"], "、".join(
            AGY_ENTRY.get(e, e) for e in gy.get("entries") or []) or "还没有会话记录"))
    for label, name in (("claude", "Claude Code"), ("codex", "Codex"), ("agy", "Antigravity")):
        cv = ev["coverage"].get(label)
        if cv and not cv["full_window"]:
            L.append("注意：%s 的日志最早只到 %s，实际只覆盖 %d 天。下面的「0 次」只代表这 %d 天。" % (name, cv["earliest_in_window"], cv["days_covered"], cv["days_covered"]))
        if cv and cv["unreadable_compressed"]:
            L.append("注意：%s 有 %d 个压缩的会话文件（.jsonl.zst）读不了：要 Python 3.14 以上，或系统里装了 zstd 命令。这部分没数进去，次数偏少。" % (name, cv["unreadable_compressed"]))
    for label, obj in (("Claude Code", c), ("Codex", x), ("Antigravity", gy)):
        if obj.get("present") and not obj.get("log_files"):
            L.append("注意：%s 窗口内没有会话日志，调用次数全部是 0，不能据此判断用没用。" % label)
    if c.get("settings_error"):
        L.append("注意：~/.claude/settings.json 解析失败（%s），开关和 skill 状态读不到。" % c["settings_error"])
    if x.get("config_error"):
        L.append("注意：~/.codex/config.toml 解析失败（%s）。" % x["config_error"])
    if x.get("toml_degraded"):
        L.append("注意：这个 Python 没有 tomllib（3.11 以上才有），config.toml 用简化解析，复杂写法可能读漏；set 改不了 TOML。")

    if c["present"]:
        render_startup(L, c, home, days)
    if gy["present"]:
        render_agy_startup(L, gy, home, days)
    if c["present"] or gy["present"]:
        L.append("")
        L.append("######## 清理：每次请求都带着、可以拿掉的东西 ########")
    if c["present"]:

        sk = c["skills"]
        usr = [s for s in sk if s["scope"] == "user"]
        prj = [s for s in sk if s["scope"] != "user"]
        st_count = Counter(s["state"] for s in usr)
        visible = [s for s in usr if s["state"] in ("on", "name-only")]
        L.append("")
        L.append("== Skill（Claude Code）==")
        L.append("用户级 %d 个（%s）。其中模型每轮能看到 %d 个，描述合计 %d 字符。" % (
            len(usr), "、".join("%s %d" % kv for kv in sorted(st_count.items())) or "无",
            len(visible), sum(s["desc_chars"] for s in visible if s["state"] == "on")))
        if prj:
            L.append("项目级 %d 个（只在各自项目里加载，来自近期用过的 %d 组项目目录）。" % (len(prj), len(ev["projects"])))
        ls = c.get("listing")
        if ls:
            la = ls["latest"]
            L.append("日志实记：最近一次新开会话（%s，%s）发给模型的 skill 清单是 %d 个、%d 字符；窗口内 %d 次新开会话，最少 %d 个、最多 %d 个。" % (
                md(la["ts"]), show(la["cwd"], home) if la["cwd"] else "目录未知", la["count"], la["chars"],
                ls["samples"], ls["min"], ls["max"]))
            L.append("  这个数是 Claude Code 自己记的：内置、插件和当前项目的 skill 也算在里面，字符数里除了描述还有每个 skill 的名字。改完配置后新开一个会话再扫，用它核对。")
        for b in c.get("broken_skill_links") or []:
            L.append("⚠ 软链断了：%s → %s（目标不存在，这个入口已经用不了）" % (show(b["path"], home), b["target"]))
        hidden = [s for s in usr if s["state"] not in ("on", "name-only")]
        if hidden:
            L.append("模型看不见的 %d 个：%s" % (len(hidden), "、".join("%s（%s）" % (s["dir"], "仅手动" if s["state"] == "user-invocable-only" else s["state"]) for s in hidden[:12]) + ("…（完整名单在 json 里）" if len(hidden) > 12 else "")))
        L.append("次数怎么数的：「模型调」是模型用 Skill 工具调用，「手敲」是用户输入 /名字，「Codex 读」是 Codex 按路径读了这个 skill 的 SKILL.md。")

        def where(s):
            if s["scope"] == "user":
                return ""
            w = "项目 " + show(s["scope"].split(":", 1)[1], home)
            return w + ("，另有 %d 个目录有同一份" % len(s["also_in"]) if s["also_in"] else "") + "，"

        def idle_line(s):
            extra = []
            if s["flags"]:
                extra.append("⚠ " + "；".join(s["flags"]))
            if s.get("referenced_by"):
                extra.append("引用它的：" + "、".join(show(p, home) for p in s["referenced_by"][:2]))
            if s.get("last_ever"):
                extra.append("skillUsage 记着最后一次是 " + s["last_ever"])
            if s["symlink"]:
                extra.append("软链 → " + show(s["target"], home))
            return "  - %s [%s%s，描述 %d 字符] %s" % (s["dir"], where(s), s["state"], s["desc_chars"], "  ".join(extra))

        idle = sorted([s for s in visible if s["total"] == 0], key=lambda s: -s["desc_chars"])
        L.append("用户级里近 %d 天 0 次调用、还对模型可见的：%d 个（候选，不是结论）" % (days, len(idle)))
        gs = c.get("skill_groups") or {}
        gcap = cap if show_all else 8
        L.append("模型看得见的 %d 个，按近 %d 天的用法分组（组里的完整名单：slim show --scan <json> --group 字母）：" % (len(visible), days))
        for g, title, advice in SKILL_GROUPS:
            members = sorted([s for s in visible if s.get("group") == g], key=lambda s: (-s["desc_chars"], s["dir"]))
            if not members:
                continue
            L.append("  %s 组 %d 个，描述合计 %d 字符：%s → %s" % (g, len(members), gs.get(g, {}).get("desc_chars", 0), title, advice))
            if g == "E":
                continue                      # 在用的在下面「用过的」里列
            if g in ("A", "B"):
                L.extend("  " + idle_line(s) for s in members[:gcap])
            else:
                L.extend("    - %s [描述 %d 字符]：手敲 %d，模型调 %d，最近 %s" % (
                    s["dir"], s["desc_chars"], s["user_calls"], s["model_calls"], md(s["last"])) for s in members[:gcap])
            if len(members) > gcap:
                L.append("      …还有 %d 个" % (len(members) - gcap))
        idle_p = sorted([s for s in prj if s["total"] == 0 and s["state"] in ("on", "name-only")], key=lambda s: -s["desc_chars"])
        if idle_p:
            L.append("项目级里 0 次调用的：%d 个" % len(idle_p))
            L.extend(idle_line(s) for s in idle_p[:cap])
            if len(idle_p) > cap:
                L.append("  …还有 %d 个，加 --all 看全部" % (len(idle_p) - cap))
        twins = [s for s in prj if s.get("twin")]
        if twins:
            L.append("同名 skill 在用户级和项目级各装了一份（日志分不出用的是哪份，次数是合在一起的）：")
            for s in twins[:cap]:
                L.append("  - %s：%s也有，%s" % (s["dir"], where(s).rstrip("，").replace("项目 ", ""), s["twin"]))

        def busy_line(s):
            note = "  （当前状态 %s）" % s["state"] if s["state"] != "on" else ""
            only = ""
            if s["scope"] == "user" and len(s["cwds"]) == 1 and s["model_calls"] + s["user_calls"] >= 3 and not s["codex_reads"]:
                only = "  只在 %s 用过" % show(list(s["cwds"])[0], home)
            return (note or only), "  - %s%s：模型调 %d，手敲 %d，Codex 读 %d，最近 %s%s%s" % (
                s["dir"], "（项目级）" if s["scope"] != "user" else "", s["model_calls"], s["user_calls"], s["codex_reads"], md(s["last"]), note, only)

        # 和用户级同名的项目级 skill 次数是合在一起的，只列用户级那一行，免得看成两份各用了这么多次
        busy = sorted([s for s in sk if s["total"] > 0 and not s.get("twin")], key=lambda s: -s["total"])
        many = len(busy) > 40      # 用过的很多时只列几个，名单在 json 里；重点留给上面的分组
        top = 10 ** 6 if show_all else (6 if many else 12)
        shown = 0
        L.append("用过的：%d 个（下面列调用最多的，以及状态或用法值得一提的）" % len(busy))
        for i, s in enumerate(busy):
            notable, text = busy_line(s)
            if i < top or (notable and shown < top + (cap if show_all else (2 if many else 6))):
                L.append(text)
                shown += 1
        if len(busy) > shown:
            L.append("  …还有 %d 个，加 --all 看全部" % (len(busy) - shown))
        if c["other_skill_calls"]:
            top = sorted(c["other_skill_calls"].items(), key=lambda kv: -kv[1])[:8]
            L.append("不在上面清单里的 skill 调用（内置、插件带的或已删除的）：" + "、".join("%s %d" % kv for kv in top))
        if not c["skill_usage_source"]:
            L.append("（没有 ~/.claude.json 的 skillUsage 可供交叉核对）")

        L.append("")
        L.append("== MCP（Claude Code）==")
        if not c["mcp"]:
            L.append("没有配置 MCP server。")
        for m in sorted(c["mcp"], key=lambda m: m["calls"]):
            tools = "；用到的工具：" + "、".join("%s %d" % kv for kv in list(m["tools_used"].items())[:6]) if m["tools_used"] else ""
            L.append("  - %s [%s，%s%s]：近 %d 天调用 %d 次，最近 %s%s" % (m["name"], m["scope"].split(":")[0], m["transport"], "，alwaysLoad" if m["alwaysLoad"] else "", days, m["calls"], md(m["last"]), tools))
        if c["other_mcp_calls"]:
            L.append("日志里出现、但不在上面配置里的 MCP（插件带的、别的项目的或已移除的）：" + "、".join("%s %d" % kv for kv in sorted(c["other_mcp_calls"].items(), key=lambda kv: -kv[1])[:8]))
        if c["plugins_enabled"]:
            L.append("启用的插件（它们带的 skill / MCP 归插件管理器管，这里不动）：" + "、".join(c["plugins_enabled"]))
        render_tools(L, c, home, days)

        L.append("")
        L.append("== Subagent（Claude Code）==")
        if not c["agents"]:
            L.append("没有自定义 subagent。")
        for a in sorted(c["agents"], key=lambda a: a["calls"]):
            L.append("  - %s [%s]：近 %d 天调用 %d 次，最近 %s" % (a["name"], a["scope"].split(":")[0], days, a["calls"], md(a["last"])))
        if c["builtin_agent_calls"]:
            L.append("内置或插件 subagent 的调用：" + "、".join("%s %d" % kv for kv in sorted(c["builtin_agent_calls"].items(), key=lambda kv: -kv[1])[:8]))

    if x["present"]:
        L.append("")
        L.append("== Codex ==")
        if x.get("global_agents_bytes") is not None:
            L.append("全局 ~/.codex/AGENTS.md：%d 字节（每个 Codex 会话都加载）。" % x["global_agents_bytes"])
        if x.get("mcp"):
            L.append("MCP：")
            for m in sorted(x["mcp"], key=lambda m: m["calls"]):
                tools = "；用到的工具：" + "、".join("%s %d" % kv for kv in list(m["tools_used"].items())[:6]) if m["tools_used"] else ""
                lim = "，已设 enabled_tools" if m["enabled_tools"] is not None else ""
                L.append("  - %s [%s%s]：近 %d 天调用 %d 次，最近 %s%s" % (m["name"], "启用" if m["enabled"] else "已停用", lim, days, m["calls"], md(m["last"]), tools))
        if x.get("other_mcp_calls"):
            L.append("日志里出现、但不在 config.toml 里的 MCP：" + "、".join("%s %d" % kv for kv in sorted(x["other_mcp_calls"].items(), key=lambda kv: -kv[1])[:8]))
        xs = x.get("skills") or []
        if x.get("skills_shared_with_claude"):
            L.append("~/.codex/skills 就是 ~/.claude/skills（软链）：两端共用同一批 skill 文件。搬动或改名会同时影响两端；只想对一端停用，Claude Code 用 skillOverrides，Codex 用 skills.config。")
        if xs:
            idle = [s for s in xs if s["reads"] == 0 and s["enabled"]]
            L.append("Skill（~/.codex/skills，共 %d 个，停用 %d 个）：近 %d 天没被读过且启用着的 %d 个（候选）" % (len(xs), sum(1 for s in xs if not s["enabled"]), days, len(idle)))
            for s in idle[:cap]:
                L.append("  - %s [描述 %d 字符]%s%s" % (s["dir"], s["desc_chars"], "  ⚠ " + "；".join(s["flags"]) if s["flags"] else "", "  软链 → " + show(s["target"], home) if s["symlink"] else ""))
            read = sorted([s for s in xs if s["reads"]], key=lambda s: -s["reads"])
            top = 10 ** 6 if show_all else 12
            if read:
                L.append("读过的 %d 个，最多的：" % len(read) + "、".join("%s %d" % (s["dir"], s["reads"]) for s in read[:top]))
            L.append("（Codex 的次数是「工具调用里读了这个 SKILL.md」的次数，是推断，不是官方计数。）")
        if x.get("agents"):
            L.append("自定义 agent：%s（v1 不统计 Codex agent 的调用次数）" % "、".join(x["agents"]))

    if gy["present"]:
        render_agy(L, gy, home, days, cap, show_all)

    L.append("")
    L.append("== 规则文件 ==")
    L.append("规则文件（CLAUDE.md、AGENTS.md、%srules/ 下的文件）在会话一开始就整份加载，之后每次请求都带着。越大的越值得先看。" % (
        "GEMINI.md、" if gy["present"] else ""))
    if ev["instruction_files"]:
        L.append("查了这些规则文件（从大到小；内容完全相同的只列一次）：")
        by_hash = {}
        for f in ev["instruction_files"]:
            by_hash.setdefault(f["sha256"], []).append(f)
        rows = [fs for fs in by_hash.values() if fs[0]["rules"]]     # 只有一行 @import 的指针文件不列
        rows.sort(key=lambda fs: -fs[0]["bytes"])
        for i, fs in enumerate(rows[:cap]):
            f = fs[0]
            L.append("  - %s（%d 字符，%d 字节，%d 行，%d 条）%s%s%s" % (
                show(f["path"], home), f.get("chars", 0), f["bytes"], f.get("lines", 0), f["rules"],
                ("  每个会话都加载" if f.get("every_session") else "") + readers_note(f),
                "，另有 %d 份相同" % (len(fs) - 1) if len(fs) > 1 else "",
                "  超过官方建议的 200 行" if f.get("lines", 0) > 200 and os.path.basename(f["path"]).startswith("CLAUDE") else ""))
            secs = [s for s in f.get("sections") or [] if s["chars"] >= 800][:4]
            if f.get("chars", 0) >= 4000 and secs and (i < 5 or f.get("every_session") or show_all):
                L.append("      最大的几节：" + "；".join("「%s」%d 字符（第 %d 行起）" % (s["title"], s["chars"], s["line"]) for s in secs))
        if len(rows) > cap:
            L.append("  …还有 %d 个，加 --all 或看 --json" % (len(rows) - cap))
    mem = c.get("auto_memory") if c["present"] else None
    if mem and mem["count"]:
        L.append("Claude Code 自带的自动记忆：%s，%d 个项目有 MEMORY.md。它的开头 200 行或 25KB 在那个项目的每个会话里都加载，上面开局账单的「规则文件」一行不含它。最大的几份：" % (
            "开着" if mem["enabled"] else "已关", mem["count"]))
        for f in mem["files"][:4]:
            L.append("  - %s（%d 字节，%d 行）%s" % (
                "项目 %s 的 MEMORY.md" % show(f["project"], home) if f.get("project") else show(f["path"], home), f["bytes"], f["lines"],
                                               "  超过 200 行或 25KB，后面的部分开局读不到" if f["over_limit"] else ""))
    elif mem:
        L.append("Claude Code 自带的自动记忆：%s，还没有记下任何 MEMORY.md。" % ("开着" if mem["enabled"] else "已关"))
    L.append("")
    L.append("== 重复规则 ==")
    if ev["instruction_files"]:
        dead = [(f["path"], t) for f in ev["instruction_files"] for t in f.get("missing_imports") or []]
        if dead:
            L.append("写了 @引用、但文件不存在的（候选，先确认是不是引用）：")
            for pth, t in dead[:cap]:
                L.append("  - %s 里的 @%s" % (show(pth, home), t))

    def repo_key(d):   # 同一个仓库的不同 worktree：目录名和文件名都一样
        return tuple((os.path.basename(os.path.dirname(p)), os.path.basename(p)) for p in (d["a"], d["b"])) + (d["relation"],)

    seen_keys, kept, folded = set(), [], Counter()
    for d in ev["duplicates"]:
        k = repo_key(d)
        if k in seen_keys:
            folded[k] += 1
        else:
            seen_keys.add(k)
            kept.append(d)
    same = [d for d in kept if d["relation"] == "same_session"]
    cross = [d for d in kept if d["relation"] == "cross_agent"]
    if not same:
        L.append("同一个会话里会一起加载的文件之间：没发现逐条相同或高度相似的规则。")
    for d in same:
        # 只在 Antigravity 的会话里一起加载的，标出来：Claude Code 的会话不受影响
        who = "" if not d.get("in") or "claude" in d["in"] else "（在 %s 的会话里）" % "、".join(AGENT_NAMES.get(w, w) for w in d["in"])
        L.append("【同一会话重复加载】%s%s × %s%s" % (who, show(d["a"], home), show(d["b"], home), "（另有 %d 个同名目录情况类似）" % folded[repo_key(d)] if folded[repo_key(d)] else ""))
        if d["identical_file"]:
            L.append("  两个文件内容完全相同。")
        for e in d["exact"][:8]:
            L.append("  = 第 %d 行 / 第 %d 行：%s" % (e["a_line"], e["b_line"], e["text"]))
        if len(d["exact"]) > 8:
            L.append("  …逐条相同的共 %d 条" % len(d["exact"]))
        for e in d["near"][:8]:
            L.append("  ≈ 第 %d 行：%s" % (e["a_line"], e["a_text"]))
            L.append("    第 %d 行：%s" % (e["b_line"], e["b_text"]))
    for d in cross:
        L.append("【两个 agent 各一份，不是重复付费】%s × %s" % (show(d["a"], home), show(d["b"], home)))
        if d["identical_file"]:
            L.append("  两个文件内容完全相同%s。" % ("（可以考虑让 CLAUDE.md 只写一行 @AGENTS.md）" if any(
                os.path.basename(p_).startswith("CLAUDE") for p_ in (d["a"], d["b"])) else ""))
            continue
        L.append("  逐条相同 %d 条；相似但有出入 %d 条%s" % (len(d["exact"]), len(d["near"]), "，有出入的是：" if d["near"] else "。"))
        for e in d["near"][:8]:
            L.append("  ≈ 第 %d 行：%s" % (e["a_line"], e["a_text"]))
            L.append("    第 %d 行：%s" % (e["b_line"], e["b_text"]))
    L.append("（脚本只能找逐条相同和措辞相近的。意思相同、写法不同的重复，要读上面这些文件自己判断。）")
    for f in sorted({f for p in ev["projects"] for f in p.get("excluded", [])}):
        L.append("（%s 被 settings.json 的 claudeMdExcludes 排除：Claude Code 不加载它，它 @import 的文件也不算在同一会话里。）" % show(f, home))
    grouped = [p for p in ev["projects"] if p["same_as"]]
    if grouped:
        L.append("（有 %d 组项目目录的规则文件内容完全相同，多半是同一个仓库的 worktree，共 %d 个目录，每组只算一次。）" % (len(grouped), sum(len(p["same_as"]) + 1 for p in grouped)))

    L.append("")
    L.append("######## 配置：不删东西，只改几个设置 ########")
    if c["present"]:
        render_config(L, c, days)
    if gy["present"]:
        render_agy_config(L, gy, days)
    L.append("")
    L.append("== 开关 ==")
    probs = (c.get("problems") or []) + (x.get("problems") or []) + (gy.get("problems") or []) + (gy.get("mcp_errors") or [])
    if probs:
        L.append("确定写错或不生效的：")
        for p in probs:
            L.append("  ! " + p)
    else:
        L.append("没发现写错或不生效的配置。")
    if c.get("notes"):
        L.append("影响常驻上下文的设置（是取舍，不是错误）：")
        for p in c["notes"]:
            L.append("  · " + p)
    if c["present"]:
        walk = [r for r in c["switches"] if r.get("ask")]
        if walk:
            L.append("值得和用户过一遍的几个（每个都是取舍，讲清楚再由他定）：")
            for r in walk:
                L.append("  ? %s，现在是 %s，默认 %s" % (
                    r["key"], json.dumps(r["value"], ensure_ascii=False) if r["set"] else "没设", r["default"]))
                L.append("      " + r["ask"])
    L.append("下面是取舍项，只列事实，不代表建议改：")
    unset = []
    if c["present"]:
        if c.get("gateway"):
            L.append("  （Claude Code 走的是自定义网关。）")
        for r in c["switches"]:
            name = ("env." if r["where"] == "env" else "") + r["key"]
            if r["set"]:
                L.append("  - %s = %s（默认：%s）" % (name, json.dumps(r["value"], ensure_ascii=False), r["default"]))
            else:
                unset.append(name)
    if x["present"]:
        for r in x.get("switches", []):
            if r["set"]:
                L.append("  - codex.%s = %s（默认：%s）" % (r["key"], json.dumps(r["value"], ensure_ascii=False), r["default"]))
            else:
                unset.append("codex." + r["key"])
    if gy["present"]:
        for r in gy.get("switches", []):
            if r["where"] != "env":
                continue            # 其余的（MCP、排除名单、规则的 trigger）现状在 Antigravity 一节里
            if r["set"]:
                L.append("  - 环境变量 %s = %s（当前这个终端里设着，只管 Antigravity 命令行；默认：%s）" % (r["key"], r["value"], r["default"]))
            else:
                unset.append("环境变量 " + r["key"])
        if gy.get("cli_context_window") is not None:
            L.append("  - antigravity 命令行设置里有 contextWindow = %s：公开的设置清单里没有这个键，脚本只报它在，不解释也不建议改。" % json.dumps(gy["cli_context_window"], ensure_ascii=False))
    if unset:
        L.append("  没设、用默认值的：" + "、".join(unset))
    L.append("每个键管什么、默认是什么、出处在哪：%s" % SWITCHES)

    if c["present"]:
        pa = c["prompt_audit"]
        L.append("")
        L.append("== 官方 /doctor prompt-audit（查旧模型写法、失效路径、互相矛盾的规则）==")
        L.append("能不能调：%s" % {True: "能", False: "现在不能", None: "不确定"}[pa["available"]])
        for ck in pa["checks"]:
            L.append("  - " + ck)
        if pa["available"] is not True:
            of = pa.get("official_file")
            L.append("调不了也能做：直接读官方那份说明文件照着做，不用为此改设置。")
            if of:
                L.append("  本机副本：%s（文件日期 %s）" % (show(of["path"], home), of["date"]))
            L.append("  原文：%s" % pa["official_url"])

    if ev["backups"]:
        L.append("")
        L.append("== 之前的备份 ==")
        for b in ev["backups"][-5:]:
            L.append("  - %s [%s] %s" % (b["id"], b["state"], b["note"] or ""))
    return "\n".join(L)


def num(n):
    return "{:,}".format(int(n))


def wan(n):
    """token 数用「万」说：82,300 → 8.2 万。"""
    n = int(n)
    if n >= 100000000:
        return "%.1f 亿" % (n / 100000000.0)
    if n >= 10000:
        return "%.1f 万" % (n / 10000.0)
    return num(n)


def pct(part, whole):
    v = part * 100.0 / max(whole, 1)
    return "不到 0.1%" if 0 < v < 0.05 else "占 %.1f%%" % v


PART_NAMES = (
    ("rules", "规则文件"), ("skills", "skill 清单"), ("mcp_tools", "MCP 工具说明"), ("builtin_tools", "内置工具说明"),
    ("system", "系统提示"), ("hooks", "会话开始时 hook 塞进来的内容"), ("mcp_notes", "MCP 自带的使用说明"),
    ("deferred", "延迟加载的工具名单"), ("agents", "subagent 名单"), ("other", "其他附带信息（环境、沙箱说明等）"),
)
PART_CAN = {
    "rules": "能瘦：见下面「规则文件」", "skills": "能减：见下面「Skill」", "mcp_tools": "能减：先看下面「工具（Claude Code，逐个）」里延迟加载开没开，再逐个工具定去留",
    "builtin_tools": "基本是固定的", "system": "固定的", "hooks": "看 hook 是不是还需要", "mcp_notes": "停掉不用的 MCP 就没了",
    "deferred": "停掉不用的 MCP 会变短", "agents": "删掉不用的 subagent 会变短", "other": "基本是固定的",
}


def render_startup(L, c, home, days):
    st = c.get("startup")
    L.append("")
    L.append("######## 开局：新会话的第一次请求带了多少 token ########")
    if not st:
        L.append("日志里没找到新开会话的记录（Claude Code 版本太旧，或窗口内没有新会话），这一块量不出来。")
        L.append("替代办法：让用户新开一个会话，什么都不说，直接输入 /context，把结果贴过来。")
        return
    if st["n"] < 5:
        # 样本太少时不报中位数和分位数，免得一个数被说三遍
        L.append("实测（Claude Code 自己记在日志里的用量，不是估的）：近 %d 天日志里只有 %d 个新会话，第一次请求的输入在 %s 到 %s token 之间。" % (
            days, st["n"], num(st["min"]), num(st["max"])) if st["min"] != st["max"] else
            "实测（Claude Code 自己记在日志里的用量，不是估的）：近 %d 天日志里只有 %d 个新会话。" % (days, st["n"]))
    else:
        L.append("实测（Claude Code 自己记在日志里的用量，不是估的）：近 %d 天 %d 个新会话，第一次请求的输入中位数 %s token，最少 %s，九成在 %s 以内。" % (
            days, st["n"], num(st["median"]), num(st["min"]), num(st.get("p90", st["max"]))))
    if st.get("recent7") and st["n"] >= 5:
        L.append("最近 7 天：%d 个新会话，中位数 %s token。" % (st["recent7"]["n"], num(st["recent7"]["median"])))
    if len(st["by_cwd"]) > 1:
        L.append("按目录（开局大小跟着项目的规则文件、项目级 skill 和 MCP 变）：")
        for r in st["by_cwd"]:
            L.append("  - %s：%d 个新会话，中位数 %s，最近一次 %s（%s）" % (
                show(r["cwd"], home) if r["cwd"] else "目录未知", r["n"], num(r["median"]), num(r["latest"]), md(r["latest_ts"])))
    la = st.get("focus") or st["latest"]
    parts = la.get("parts") or {}
    total = sum(parts.values())
    L.append("拿最近常用的目录里最近一次新开会话来看（%s，%s，%s）：第一次请求 %s token。" % (
        md(la["ts"]), show(la["cwd"], home) if la["cwd"] else "目录未知", la["model"], num(la["tokens"])))
    if not total:
        L.append("  这个版本的日志没有记这次请求里各部分的大小，分不出明细。")
    else:
        L.append("  这次请求里各部分的大小（字符数，从大到小；占比按字符算，中文和英文折成 token 的比例不同，只用来排先后）：")
        for key, v in sorted(parts.items(), key=lambda kv: -kv[1]):
            if not v:
                continue
            name = dict(PART_NAMES).get(key, key)
            extra = ""
            if key == "skills" and la.get("skill_count"):
                extra = " %d 个" % la["skill_count"]
            elif key == "rules":
                extra = " %d 个" % len(la.get("files") or [])
            elif key == "builtin_tools" and la.get("tools"):
                extra = " %d 个" % la["tools"]["builtin"]["n"]
            elif key == "mcp_tools" and la.get("tools"):
                extra = " %d 个" % sum(v_["n"] for v_ in la["tools"]["mcp"].values())
            elif key == "deferred" and la.get("deferred_n"):
                extra = " %d 个" % la["deferred_n"]
            can = PART_CAN.get(key, "")
            if key == "builtin_tools" and not la.get("deferred_n") and any("ENABLE_TOOL_SEARCH=false" in str(x) for x in c.get("notes") or []):
                # 实测（2.1.321）：这个开关设成 false 时，本来「用到才加载」的那部分内置工具也整份带上
                can = "能减：ENABLE_TOOL_SEARCH 被设成了 false，所有工具的说明都整份带上了；改回默认后一部分工具用到才加载"
            L.append("  %5.1f%%  %8s 字符  %s%s  —— %s" % (v * 100.0 / total, num(v), name, extra, can))
            if key == "rules":
                for f in sorted(la.get("files") or [], key=lambda f: -f["chars"])[:6]:
                    L.append("             · %s 字符  %s" % (num(f["chars"]), show(f["path"], home)))
            if key == "mcp_tools" and la.get("tools"):
                for srv, v_ in sorted(la["tools"]["mcp"].items(), key=lambda kv: -kv[1]["chars"])[:6]:
                    L.append("             · %s 字符  %s（%d 个工具）" % (num(v_["chars"]), srv, v_["n"]))
        if la.get("tools") is None:
            L.append("  （这个版本的日志没记系统提示和工具说明的大小，上面只有其余部分。）")
    L.append("怎么用这一块：先砍排在前面、而且「能瘦」「能减」的。改完后新开一个会话说一句话，再扫一次，对比这里的第一次请求 token。")


AGY_PART_NAMES = (
    ("system", "系统提示（Antigravity 自带的各段说明）"), ("builtin_tools", "内置工具说明"), ("skills", "skill 清单"),
    ("rules", "规则文件"), ("mcp_tools", "MCP 工具说明（常驻的）"), ("mcp_list", "MCP 名单（按需的工具只列名字）"),
    ("agents", "子代理说明"),
)
AGY_PART_CAN = {
    "system": "固定的", "builtin_tools": "基本是固定的", "skills": "能减：见下面「Antigravity」一节的 Skill",
    "rules": "能瘦：见下面「规则文件」", "mcp_tools": "能减：配置里写了 eager 的，去掉就变回只列名字；别的程序带进来的看下面的标注",
    "mcp_list": "停掉不用的 MCP 会变短", "agents": "基本是固定的；自定义子代理多了会变长",
}


def agy_entry(e):
    return AGY_ENTRY.get(e, e) if e else "入口未知"


def render_agy_startup(L, a, home, days):
    st = a.get("startup")
    L.append("")
    L.append("######## 开局（Antigravity）：新会话的第一次请求带了多少 token ########")
    if not st:
        L.append("会话日志里没找到新开会话的记录（窗口内没有新会话，或这个版本的日志位置变了），这一块量不出来。")
        L.append("替代办法：让用户在 Antigravity 命令行里新开一个会话，输入 /context，把结果贴过来。")
        return
    src = "实测（Antigravity 自己记在会话日志里的用量，不是估的）"
    if st["n"] < 5:
        L.append("%s：近 %d 天只有 %d 个新会话，第一次请求的输入在 %s 到 %s token 之间。" % (src, days, st["n"], num(st["min"]), num(st["max"]))
                 if st["min"] != st["max"] else "%s：近 %d 天只有 %d 个新会话。" % (src, days, st["n"]))
    else:
        L.append("%s：近 %d 天 %d 个新会话，第一次请求的输入中位数 %s token，最少 %s，九成在 %s 以内。" % (
            src, days, st["n"], num(st["median"]), num(st["min"]), num(st.get("p90", st["max"]))))
    be = a.get("by_entry") or {}
    if len(be) > 1:
        L.append("按入口（各入口带的工具和 skill 不一样）：")
        for e, v in sorted(be.items(), key=lambda kv: -kv[1]["n"]):
            L.append("  - %s：%d 个新会话，中位数 %s，最近一次 %s（%s）" % (agy_entry(e), v["n"], num(v["median"]), num(v["tokens"]), md(v["ts"])))
    if len(st["by_cwd"]) > 1:
        L.append("按目录（开局大小跟着那个目录的规则文件和项目里的 skill 变）：")
        for r in st["by_cwd"]:
            L.append("  - %s：%d 个新会话，中位数 %s，最近一次 %s（%s）" % (
                show(r["cwd"], home) if r["cwd"] else "目录未知", r["n"], num(r["median"]), num(r["latest"]), md(r["latest_ts"])))
    la = st.get("focus") or st["latest"]
    if not la.get("parts") and (st["latest"].get("parts")):
        la = st["latest"]
    parts = la.get("parts") or {}
    total = sum(parts.values())
    L.append("拿最近常用的目录里最近一次新开会话来看（%s，%s，%s，%s）：第一次请求 %s token。" % (
        md(la["ts"]), show(la["cwd"], home) if la["cwd"] else "目录未知", agy_entry(la.get("entrypoint")), la["model"], num(la["tokens"])))
    if not total:
        L.append("  这个会话的会话库里读不出各部分的大小（库不在了，或这个版本的格式脚本不认识），只有上面的总数。")
        L.append("  替代办法：在 Antigravity 命令行里新开一个会话，输入 /context，把结果贴过来。")
    else:
        L.append("  这个会话每次请求都固定带着的各部分（取自会话库里留着的最后一次请求；字符数，从大到小；"
                 "占比按字符算，中文和英文折成 token 的比例不同，只用来排先后）：")
        tools = la.get("tools") or {"builtin": {"n": 0}, "mcp": {}}
        for key, v in sorted(parts.items(), key=lambda kv: -kv[1]):
            if not v:
                continue
            extra = ""
            if key == "skills" and la.get("skill_count") is not None:
                extra = " %d 个" % la["skill_count"]
            elif key == "rules":
                extra = " %d 份" % len(la.get("files") or [])
            elif key == "builtin_tools":
                extra = " %d 个" % tools["builtin"]["n"]
            elif key == "mcp_tools":
                extra = " %d 个" % sum(v_["n"] for v_ in tools["mcp"].values())
            elif key == "mcp_list":
                extra = " %d 个 server、%d 个按需工具" % (len(la.get("servers") or []), la.get("deferred_n") or 0)
            L.append("  %5.1f%%  %8s 字符  %s%s  —— %s" % (v * 100.0 / total, num(v), dict(AGY_PART_NAMES).get(key, key), extra, AGY_PART_CAN.get(key, "")))
            if key == "rules":
                glob_ = [f for f in la.get("files") or [] if f["path"] == "user_global"]
                if glob_:
                    L.append("             · %s 字符  全局规则 %d 份（~/.gemini 下的 GEMINI.md、AGENTS.md，日志里不分是哪一份）" % (
                        num(sum(f["chars"] for f in glob_)), len(glob_)))
                for f in sorted([f for f in la.get("files") or [] if f["path"] != "user_global"], key=lambda f: -f["chars"])[:6]:
                    L.append("             · %s 字符  %s" % (num(f["chars"]), show(f["path"], home)))
                if la.get("pointers"):
                    L.append("             · 另有 %d 份只给了路径和一句描述、用到才读的规则" % len(la["pointers"]))
            if key == "mcp_tools":
                known_srv = set(m["name"] for m in a.get("mcp") or [])
                for srv, v_ in sorted(tools["mcp"].items(), key=lambda kv: -kv[1]["chars"])[:6]:
                    L.append("             · %s 字符  %s（%d 个工具）%s" % (num(v_["chars"]), srv, v_["n"],
                             "" if srv in known_srv else "  ← 脚本查过的 mcp_config.json 里没有它，来源未知：可能是开这个会话的程序自己带进来的（别的工具通过 agy acp 开的会话会这样），也可能是插件带的"))
    if la.get("partial"):
        L.append("  注意：这个会话的会话库里有几段记录脚本认不出来，上面的明细不完整，缺的部分没有列出来（不是 0）。")
    if a.get("no_shape"):
        L.append("（窗口内有 %d 个新会话的会话库读不出明细，它们只算进了上面的 token 统计。）" % a["no_shape"])
    if a.get("start_no_usage"):
        L.append("（有 %d 个会话的第一条模型回复没有记用量，开局量不出来，没算进上面的统计，也没有拿后面的请求顶替。）" % a["start_no_usage"])
    if a.get("kind_unknown"):
        L.append("（有 %d 个会话在会话摘要库里查不到、日志开头也没有用户输入，分不清是用户开的还是子代理，没算进任何统计。）" % a["kind_unknown"])
    if a.get("wal_pending"):
        L.append("（有 %d 个会话库旁边还有没并入的改动（-wal 文件非空）。脚本只读主库、不碰这些文件，这几个会话的各部分明细可能不是最新一次请求的；token 数取自日志，不受影响。）" % a["wal_pending"])
    L.append("怎么用这一块：先砍排在前面、而且「能瘦」「能减」的。Antigravity 每次请求前都会重新读规则和 skill，改完下一句话就生效；"
             "要对比开局，新开一个会话说一句话，再扫一次。")


def render_agy(L, a, home, days, cap, show_all):
    sk = a.get("skills") or []
    L.append("")
    L.append("== Antigravity ==")
    L.append("和 Claude Code、Codex 不一样的地方：同一层的 AGENTS.md 和 GEMINI.md 两份都加载（不是二选一）；规则里单写 @路径 只是引用，"
             "@[标签](路径) 才会把文件内容展开进来；MCP 工具默认只列名字，用到才读说明。出处见 skill 目录下的 references/antigravity.md。")
    gl = [s for s in sk if s["scope"] in ("global", "manifest", "agents-home")]
    cli = [s for s in sk if s["scope"] == "cli-only"]
    prj = [s for s in sk if s["scope"].startswith("project:")]
    n_ah = sum(1 for s in gl if s["scope"] == "agents-home")
    L.append("Skill：全局 %d 个（~/.gemini/config/skills%s%s），其中已排除 %d 个、只能手动调 %d 个；只有命令行读的目录里 %d 个；项目里 %d 个。" % (
        len(gl), "，含 skills.json 点名的目录" if any(s["scope"] == "manifest" for s in gl) else "",
        "；其中 %d 个在 ~/.agents/skills，命令行 1.5.16 起也当全局 skill 读，和 ~/.gemini 里的同名时让位" % n_ah if n_ah else "",
        sum(1 for s in gl if s["state"] == "excluded"), sum(1 for s in gl if s["state"] == "manual"), len(cli), len(prj)))
    if a.get("manifest_error"):
        L.append("注意：~/.gemini/config/skills.json 解析失败（%s），排除名单读不到。" % a["manifest_error"])
    ls = a.get("listing")
    if ls:
        L.append("日志实记：最近一次新开会话（%s，%s，%s）发给模型的 skill 清单是 %d 个、%d 字符。Antigravity 内置的 skill（这台机器上有 %d 个，不一定都进清单）、当前项目的 skill 也算在里面，"
                 "字符数里除了描述还有每个 skill 的名字和路径。" % (md(ls["ts"]), agy_entry(ls["entry"]), show(ls["cwd"], home) if ls["cwd"] else "目录未知",
                                                 ls["count"], ls["chars"], a.get("builtin_skill_count") or 0))
    for b in a.get("broken_skill_links") or []:
        L.append("⚠ 软链断了：%s → %s（目标不存在，这个入口已经用不了）" % (show(b["path"], home), b["target"]))
    L.append("次数怎么数的：Antigravity 没有专门调 skill 的工具，用一个 skill 就是读它的 SKILL.md。这里数的是近 %d 天有几个会话读过它，是推断，不是官方计数。" % days)

    def line(s):
        extra = []
        if s["flags"]:
            extra.append("⚠ " + "；".join(s["flags"]))
        if s.get("referenced_by"):
            extra.append("引用它的：" + "、".join(show(p, home) for p in s["referenced_by"][:2]))
        if s["symlink"]:
            extra.append("软链 → " + show(s["target"], home))
        return "    - %s [描述 %d 字符] %s" % (s["dir"], s["desc_chars"], "  ".join(extra))

    gcap = cap if show_all else 8
    live = [s for s in gl if s["state"] == "on"]
    idle = [s for s in live if s["reads"] == 0]
    L.append("全局里近 %d 天没有会话读过、还在清单里的：%d 个（候选，不是结论）。完整名单：slim show --agent agy --scan <json> --group 字母" % (days, len(idle)))
    for g, title in (("A", "没读过，也找不到留着的理由 → 可以写进排除名单"), ("B", "没读过，但有理由先留着 → 逐个看 ⚠ 再定，默认保留")):
        members = sorted([s for s in live if s.get("group") == g], key=lambda s: (-s["desc_chars"], s["dir"]))
        if not members:
            continue
        L.append("  %s 组 %d 个，描述合计 %d 字符：%s" % (g, len(members), sum(s["desc_chars"] for s in members), title))
        L.extend(line(s) for s in members[:gcap])
        if len(members) > gcap:
            L.append("      …还有 %d 个" % (len(members) - gcap))
    by_dir = {}
    for s in sk:            # 同名的 skill（全局一份、项目一份）日志里分不开，次数算在一起，只列一次
        if s["reads"]:
            by_dir[s["dir"]] = max(by_dir.get(s["dir"], 0), s["reads"])
    read = sorted(by_dir.items(), key=lambda kv: (-kv[1], kv[0]))
    if read:
        L.append("读过的 %d 个，最多的：" % len(read) + "、".join("%s %d" % kv for kv in read[:(10 ** 6 if show_all else 12)]))
    hidden = [s for s in gl if s["state"] != "on"]
    if hidden:
        why = {"excluded": "已排除", "manual": "仅手动", "shadowed": "被同名的盖住"}
        L.append("模型看不见的 %d 个：%s" % (len(hidden), "、".join("%s（%s）" % (s["dir"], why.get(s["state"], s["state"])) for s in hidden[:12])
                                     + ("…（完整名单在 json 里）" if len(hidden) > 12 else "")))
    for s in cli:
        L.append("  · %s 在 %s：只有命令行读这个目录，桌面 app 不读；排除名单管不到它%s" % (
            s["dir"], show(os.path.dirname(s["path"]), home), "（近 %d 天 %d 个会话读过）" % (days, s["reads"]) if s["reads"] else "，近 %d 天没有会话读过" % days))
    if any(s["shared_with_claude"] for s in gl):
        L.append("其中 %d 个是指向 ~/.claude/skills 的软链：和 Claude Code 共用同一份文件。只想让 Antigravity 不加载，写进排除名单；搬动或删除会同时影响两边。" % sum(1 for s in gl if s["shared_with_claude"]))
    idle_p = [s for s in prj if s["reads"] == 0 and s["state"] == "on"]
    if idle_p:
        L.append("项目里没有会话读过的：%d 个：" % len(idle_p) + "、".join(
            "%s（%s）" % (s["dir"], show(s["scope"].split(":", 1)[1], home)) for s in idle_p[:cap])
                 + ("…（完整名单在 json 里）" if len(idle_p) > cap else "")
                 + "。项目里的 skill 只在那个项目的会话里加载；要让 Antigravity 不加载其中某个，同样写进排除名单（实测管得到）。")
    if a.get("other_skill_reads"):
        L.append("读过、但不在上面清单里的 skill（内置的、插件带的、别的目录的）：" + "、".join("%s %d" % kv for kv in list(a["other_skill_reads"].items())[:8]))

    L.append("MCP（Antigravity）：")
    if not a.get("mcp"):
        L.append("  没有配置 MCP server。")
    for m in sorted(a.get("mcp") or [], key=lambda m: m["calls"]):
        load = "已停用" if m["disabled"] else ("常驻 %d 个（%s），其余按需" % (len(m["eager"]), "、".join(m["eager"][:4])) if m["eager"] else "按需")
        if m.get("eager_blocked") and not m["disabled"]:
            load += "；另有 %d 个写了 eager 但被屏蔽或没放行，不会常驻" % len(m["eager_blocked"])
        lim = ""
        if m["enabled_tools"] is not None:
            lim = "，只放行 %d 个工具" % len(m["enabled_tools"])
        elif m["disabled_tools"]:
            lim = "，屏蔽了 %d 个工具" % len(m["disabled_tools"])
        tools = "；用到的工具：" + "、".join("%s %d" % kv for kv in list(m["tools_used"].items())[:6]) if m["tools_used"] else ""
        L.append("  - %s [%s，%s，%s%s]：%s近 %d 天调用 %d 次，最近 %s%s" % (
            m["name"], "全局" if m["scope"] == "global" else "项目 " + show(m["scope"].split(":", 1)[1], home), m["transport"], load, lim,
            "一共暴露 %d 个工具，" % m["tools_on_disk"] if m["tools_on_disk"] else "", days, m["calls"], md(m["last"]), tools))
    if a.get("mcp"):
        L.append("  怎么读：按需的工具每个只占一个名字，停掉它们省得很少；写了 eager 的工具整份说明每次请求都带着，要省先看它们。"
                 "整个 server 不用了，在 mcp_config.json 里给它加 disabled: true，配置留着。")
    if a.get("other_mcp_calls"):
        L.append("  日志里出现、但不在上面配置里的 MCP（插件带的、入口自己带进来的或已移除的）：" + "、".join(
            "%s %d" % kv for kv in sorted(a["other_mcp_calls"].items(), key=lambda kv: -kv[1])[:8]))
    hooks = [h for h in a.get("hooks") or [] if h["enabled"]]
    if hooks:
        L.append("hook（~/.gemini/config/hooks.json，启用 %d 个）：%s。SessionStart 和 PreInvocation 的 hook 能往上下文里放内容，放了就算进每个会话或每次请求。" % (
            len(hooks), "、".join("%s（%s）" % (h["name"], "、".join(h["events"])) for h in hooks[:8])))
    on = [k for k, v in (a.get("plugins") or {}).items() if v]
    if on:
        L.append("启用的插件（它们带的 skill、规则、MCP 归插件管理，这里不动；要停用 agy plugin disable <名字>）：" + "、".join(on))
    if a.get("legacy_settings"):
        L.append("~/.gemini/settings.json 里还有 %s：这是旧 Gemini CLI 的设置文件。Antigravity 的 MCP 配置在 ~/.gemini/config/mcp_config.json，"
                 "hook 在 ~/.gemini/config/hooks.json（官方文档；1.5.18 的实验里，写在这份旧文件里的 MCP 也确实没有被加载）；改这份旧文件不影响 Antigravity。" % "、".join(a["legacy_settings"]))
    if a.get("pointers"):
        L.append("只给路径和描述、用到才读的规则（trigger: model_decision）：%d 份。" % len(a["pointers"]))
    if a.get("manifests"):
        L.append("注意：有清单文件 %s。清单文件能另外点名要加载或要跳过的规则和 skill，脚本没有展开它们，上面的名单可能不全；以开局部分列的实际加载为准。" % "、".join(show(f, home) for f in a["manifests"][:4]))
    for sc in a.get("skills_checks") or []:
        if sc["ok"]:
            continue
        L.append("注意：脚本算出来的 skill 清单，和 %s 在 %s 新开的那个会话（%s）里 Antigravity 实际发给模型的不一样（以实际发的为准）。"
                 "可能是那之后装过、删过或排除过 skill，也可能是插件、清单文件带进来的，或这个版本的规则和脚本知道的不同。" % (md(sc["ts"]), show(sc["cwd"], home), agy_entry(sc["entry"])))
        if sc["only_logged"]:
            L.append("  实际发给了模型、脚本没算到的 %d 个：%s" % (len(sc["only_logged"]), "、".join(show(f, home) for f in sc["only_logged"][:6])))
        if sc["only_computed"]:
            L.append("  脚本算到了、实际没发给模型的 %d 个：%s" % (len(sc["only_computed"]), "、".join(show(f, home) for f in sc["only_computed"][:6])))
    ck = a.get("chain_check")
    if ck and not ck["ok"]:
        L.append("注意：脚本按规则算出来的规则文件清单，和 %s 在 %s 新开的那个会话里 Antigravity 实际加载的不一样（以实际加载的为准，开局部分列的就是实际加载的）。"
                 "可能是那之后改过规则文件，也可能是这个版本的加载规则和脚本知道的不同。" % (md(ck["ts"]), show(ck["cwd"], home)))
        if ck["only_logged"]:
            L.append("  实际加载了、脚本没算到的：" + "、".join(show(f, home) for f in ck["only_logged"][:6]))
        if ck["only_computed"]:
            L.append("  脚本算到了、实际没加载的：" + "、".join(show(f, home) for f in ck["only_computed"][:6]))
        if ck["global_logged"] != ck["global_computed"]:
            L.append("  全局规则：实际加载 %d 份，现在 ~/.gemini 下有 %d 份。" % (ck["global_logged"], ck["global_computed"]))


def render_agy_config(L, a, days):
    cx = a.get("context")
    L.append("")
    L.append("== Antigravity：会话长到多大、什么时候压缩 ==")
    if cx:
        L.append("实测：近 %d 天主会话 %s 次请求，一共带了 %s token 的上下文（每次请求都把当时的整段历史带一遍）。" % (days, num(cx["requests"]), wan(cx["tokens"])))
        for label, name in (("200k", "20 万"), ("400k", "40 万"), ("500k", "50 万")):
            o = cx["over"][label]
            if o["requests"]:
                L.append("  上下文超过 %s的请求：%s 次（%s），带了 %s token（%s）" % (
                    name, num(o["requests"]), pct(o["requests"], cx["requests"]), wan(o["tokens"]), pct(o["tokens"], cx["tokens"])))
        L.append("  %d 个会话里，最长的那次请求：中位数 %s，九成在 %s 以内，最大 %s。" % (cx["sessions"], wan(cx["peak_median"]), wan(cx["peak_p90"]), wan(cx["peak_max"])))
    else:
        L.append("会话日志里没有用量记录，量不出会话实际长到多大。")
    ck = a.get("compactions")
    if ck:
        L.append("实际发生的压缩：近 %d 天 %d 次（自动的和手动 /compact 的都算），压缩前会话长到 %s 到 %s，中位数 %s。%s" % (
            days, ck["n"], wan(ck["min"]), wan(ck["max"]), wan(ck["median"]),
            "按入口：" + "；".join("%s %d 次、中位数 %s" % (agy_entry(e), v["n"], wan(v["median"])) for e, v in ck["by_entry"].items()) + "。" if len(ck["by_entry"]) > 1 else ""))
    elif cx:
        L.append("近 %d 天没有发生过压缩。" % days)
    L.append("  怎么调：命令行用环境变量 AGY_CLI_AUTO_COMPACT_OVERRIDE（1.5.15 起，可以写 700000、800K、80% 这几种），在 /context 里能看到生效的阈值；"
             "它是终端的环境变量，不在配置文件里，由用户自己设。桌面 app 的官方文档没有给出对应的设置。")
    rw = (cx or {}).get("rewrites") or {"n": 0}
    if rw["n"]:
        L.append("缓存：近 %d 天有 %s 次请求没读到缓存，把 10 万 token 以上的历史整段重算了一遍，合计 %s token。%s" % (
            days, num(rw["n"]), wan(rw["tokens"]), "；".join("%s %s 次" % (why, num(v["n"])) for why, v in sorted(rw["by"].items(), key=lambda kv: -kv[1]["tokens"]))))
    rq = a.get("requests_by_model") or {}
    for kind, name in (("main", "主会话"), ("sub", "子代理")):
        rows = sorted((rq.get(kind) or {}).items(), key=lambda kv: -kv[1]["tokens"])
        if rows:
            L.append("%s用的模型：%s" % (name, "；".join("%s %s 次、%s token" % ("没记模型" if m == "?" else m, num(v["n"]), wan(v["tokens"])) for m, v in rows[:5])))
    if a.get("model_from_db"):
        L.append("  其中 %s 次请求的日志没记模型（桌面 app 多数不记），按那个会话的会话库里最后一次请求用的模型算；会话中途换过模型的会算偏。" % num(a["model_from_db"]))
    ac = a.get("agent_calls") or {}
    if ac.get("total"):
        L.append("派子代理 %s 次：其中 %s 次没指定模型%s。" % (num(ac["total"]), num(ac["no_model"]),
                 "，指定了的：" + "、".join("%s %d" % kv for kv in list(ac["by_model"].items())[:5]) if ac["by_model"] else ""))
    sr = a.get("sub_runs")
    if sr:
        L.append("子代理会话 %d 个，各自发的请求数中位数 %d、最大 %d%s" % (sr["n"], sr["median"], sr["max"],
                 "；其中 %d 个发了 %d 次以上，像是把整件活交了出去：" % (len(sr["big"]), sr["threshold"]) if sr["big"] else "。"))
        for r in sr["big"][:6]:
            L.append("  - %d 次请求  %s  「%s」%s" % (r["reqs"], r["model"] or "模型未知", r["title"] or "无标题", "（%s）" % r["type"] if r["type"] else ""))


def tool_groups(tt):
    g = {}
    for r in tt["items"]:
        d = g.setdefault(r["server"] or "（内置）", {"loaded": 0, "chars": 0, "lazy": 0, "calls": 0})
        if r["load"] == "常驻":
            d["loaded"] += 1
            d["chars"] += r["chars"] or 0
        else:
            d["lazy"] += 1
        d["calls"] += r["calls"]
    return sorted(g.items(), key=lambda kv: (-kv[1]["chars"], -kv[1]["lazy"], kv[0]))


def render_tools(L, c, home, days):
    tt = c.get("tools")
    L.append("")
    L.append("== 工具（Claude Code，逐个）==")
    if not tt:
        L.append("日志里没有记下新开会话时发给模型的工具清单，逐个工具的大小和「常驻还是按需」量不出来。")
        L.append("替代办法：让用户新开一个会话，输入 /context，把 MCP tools 那一栏展开后的列表贴过来。")
        return
    items = tt["items"]
    hot = [r for r in items if r["load"] == "常驻"]
    L.append("拿 %s 在 %s 新开的那个会话来看（Claude Code 记在日志里的工具清单）：整份带着的（常驻）%d 个，共 %s 字符；只列了名字、用到才加载的（按需）%d 个。" % (
        md(tt["ts"]), show(tt["cwd"], home) if tt.get("cwd") else "目录未知", len(hot), num(sum(r["chars"] or 0 for r in hot)), len(items) - len(hot)))
    if tt["tool_search"]:
        L.append("延迟加载：开着。按需的工具每个只占一个名字，屏蔽它们几乎不省；要省，看常驻的。")
    else:
        L.append("延迟加载：没开。所有工具的说明都整份带着%s。先弄清为什么没开（见「开关」一节），它一开，多数 MCP 工具就变成按需。" % (
            "（其中 %d 个 Claude Code 列进了延迟名单，实际仍整份发了出去）" % tt["listed_but_loaded"] if tt.get("listed_but_loaded") else ""))
    for ep, t in sorted((c.get("tools_alt") or {}).items()):
        if t["tool_search"] != tt["tool_search"]:
            L.append("注意：上面说的是入口 %s 的会话。入口 %s 的会话里延迟加载%s，用户平时用哪个入口，就看哪个。" % (
                tt.get("entrypoint") or "未知", ep, "开着" if t["tool_search"] else "没开"))
    L.append("按来源（常驻的从大到小；调用次数是近 %d 天）：" % days)
    for name, d in tool_groups(tt):
        L.append("  - %s：常驻 %d 个 %s 字符，按需 %d 个，调用 %d 次" % (name, d["loaded"], num(d["chars"]), d["lazy"], d["calls"]))
    if tt["deny"]:
        L.append("已经屏蔽的（settings.json 的 permissions.deny 里的工具名）：" + "、".join(tt["deny"]))
    if any(r["denied"] for r in items):
        L.append("上面这份清单是那次会话当时的，其中 %d 个之后已经屏蔽，新会话里不会再有。" % len([r for r in items if r["denied"]]))
    L.append("逐个工具的编号表：slim tools --scan <这次的 json>。连接得晚的 MCP server、会话中途才出现的工具不在这份清单里。")
    for ep, t in sorted((c.get("tools_alt") or {}).items()):
        h = [r for r in t["items"] if r["load"] == "常驻"]
        L.append("别的入口开的会话工具清单不一样：%s（%s，常驻 %d 个 %s 字符，按需 %d 个，延迟加载%s）。看它的编号表：slim tools --scan <json> --entry %s" % (
            ep, md(t["ts"]), len(h), num(sum(r["chars"] or 0 for r in h)), len(t["items"]) - len(h), "开着" if t["tool_search"] else "没开", ep))


def render_config(L, c, days):
    cx = c.get("context")
    cw = c.get("compact_window") or {}
    L.append("")
    L.append("== 自动压缩窗口（会话长到多大就自动压缩）==")
    if cw.get("disabled"):
        cur = "自动压缩被关掉了（autoCompactEnabled=false 或 DISABLE_AUTO_COMPACT=1）"
    elif cw.get("env") is not None:
        cur = "环境变量 CLAUDE_CODE_AUTO_COMPACT_WINDOW=%s" % cw["env"]
    elif cw.get("settings") is not None:
        cur = "autoCompactWindow=%s" % cw["settings"]
    else:
        cur = "没设，Claude Code 按模型自己定"
    if cw.get("per_model"):
        cur += "；另外 /autocompact 给这些模型单独设过：" + "、".join("%s=%s" % kv for kv in cw["per_model"].items())
    L.append("现在的设置：%s。" % cur)
    if cx:
        L.append("实测：近 %d 天主会话 %s 次请求，一共带了 %s token 的上下文（每次请求都把当时的整段历史带一遍）。" % (
            days, num(cx["requests"]), wan(cx["tokens"])))
        for label, name in (("200k", "20 万"), ("400k", "40 万"), ("500k", "50 万")):
            o = cx["over"][label]
            if o["requests"]:
                L.append("  上下文超过 %s的请求：%s 次（%s），带了 %s token（%s）" % (
                    name, num(o["requests"]), pct(o["requests"], cx["requests"]), wan(o["tokens"]), pct(o["tokens"], cx["tokens"])))
        L.append("  %d 个会话里，最长的那次请求：中位数 %s，九成在 %s 以内，最大 %s；超过 40 万的会话 %d 个，超过 50 万的 %d 个。" % (
            cx["sessions"], wan(cx["peak_median"]), wan(cx["peak_p90"]), wan(cx["peak_max"]),
            cx["sessions_over"]["400k"], cx["sessions_over"]["500k"]))
        L.append("  怎么读：窗口设成 40 万或 50 万，上面「超过」的那些请求就不会再带那么长的历史；代价是压缩得更早，压缩后模型手里只有摘要。")
    else:
        L.append("日志里没有用量记录，量不出会话实际长到多大。")
    L.append("")
    L.append("== 缓存：放着不动再回来 ==")
    rw = (cx or {}).get("rewrites") or {"n": 0}
    if rw["n"]:
        L.append("实测：近 %d 天有 %s 次请求没命中缓存，把 10 万 token 以上的历史整段重算了一遍，合计 %s token。" % (days, num(rw["n"]), wan(rw["tokens"])))
        for why, v in sorted(rw["by"].items(), key=lambda kv: -kv[1]["tokens"]):
            L.append("  - %s：%s 次，%s token" % (why, num(v["n"]), wan(v["tokens"])))
        L.append("  怎么读：缓存有时效（订阅用户的主会话 1 小时，其余 5 分钟）。隔久了再回来，第一句话要把整段历史按全价重算。离开前先 /compact，或者回来时新开会话，这一笔就小得多。")
    elif cx:
        L.append("近 %d 天没看到「10 万 token 以上的历史整段重算」的请求。" % days)
    L.append("")
    L.append("== 子代理：交出去什么、用什么模型 ==")
    rq = c.get("requests_by_model") or {}
    for kind, name in (("main", "主会话"), ("sub", "子代理")):
        rows = sorted((rq.get(kind) or {}).items(), key=lambda kv: -kv[1]["tokens"])
        if rows:
            L.append("%s：%s" % (name, "；".join("%s %s 次、%s token" % (m, num(v["n"]), wan(v["tokens"])) for m, v in rows[:5])))
    ac = c.get("agent_calls") or {}
    if ac.get("total"):
        L.append("派子代理 %s 次：其中 %s 次没指定模型（跟主会话用同一个）%s。" % (
            num(ac["total"]), num(ac["no_model"]),
            "，指定了的：" + "、".join("%s %d" % kv for kv in list(ac["by_model"].items())[:5]) if ac["by_model"] else ""))
        L.append("  怎么读：查资料、搜文件、读日志这类活用便宜的模型就够。没指定模型的子代理会用主会话那个最贵的。")
    elif not (rq.get("sub")):
        L.append("近 %d 天没有派过子代理。" % days)
    dg = c.get("delegation")
    if dg:
        L.append("谁派给谁（主会话当时用的模型 → 派工时指定的模型）：")
        for m, v in list(dg["by_main"].items())[:4]:
            L.append("  - %s 派了 %d 次：%s" % (m, v["n"], "、".join("%s %d" % kv for kv in list(v["to"].items())[:5])))
        if dg["measured"]:
            L.append("一次派工有多大，看子代理自己发了多少次请求：对得上日志的 %d 次里，中位数 %d 次，最大 %d 次。" % (
                dg["measured"], dg["median_reqs"], dg["max_reqs"]))
        if dg["big_n"]:
            L.append("其中 %d 次的子代理发了 %d 次以上请求，像是把整件活交了出去（最大的几次）：" % (dg["big_n"], dg["threshold"]))
            for r in dg["big"][:8]:
                L.append("  - %s  %s → %s  %d 次请求  「%s」%s" % (md(r["ts"]), r["main"], r["to"] or "没指定", r["reqs"], r["title"],
                                                             "（%s）" % r["type"] if r["type"] else ""))
            L.append("  怎么读：这些是候选。是用户自己说要整件交给后台做的，还是模型照规则文件自己转出去的，日志分不出来，要问用户。"
                     "整件转出去时，定计划、中途拿主意、下结论的就不是用户选的那个模型了。")
        elif dg["measured"]:
            L.append("没有哪次派工的子代理发到 %d 次请求：分出去的都是小活。" % dg["threshold"])


# ---------------------------------------------------------------- 备份 / 回滚

def store_root(home):
    return os.path.join(home, STORE, "backups")


def manifest_path(home, bid):
    return os.path.join(store_root(home), bid, "manifest.json")


def all_manifests(home):
    root = store_root(home)
    out = []
    if os.path.isdir(root):
        for d in sorted(os.listdir(root)):
            m, _ = load_json_file(os.path.join(root, d, "manifest.json"), config=False)
            if isinstance(m, dict):
                out.append(m)
    return out


def backup_state(m):
    if m.get("rolled_back"):
        return "已回滚"
    return "已封存" if m.get("sealed") else "进行中"


def load_manifest(home, bid):
    m, err = load_json_file(manifest_path(home, bid), config=False)
    if not isinstance(m, dict):
        die("找不到备份 %s（%s）。用 list 看有哪些。" % (bid, err))
    return m


def save_manifest(home, m):
    p = manifest_path(home, m["id"])
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(m, f, ensure_ascii=False, indent=1)
    os.chmod(tmp, 0o600)
    os.replace(tmp, p)


def walk_tree(root):
    for dp, dn, fn in os.walk(root):
        dn.sort()
        for name in sorted(dn + fn):
            if name in IGNORE_NAMES:
                continue
            p = os.path.join(dp, name)
            st = os.lstat(p)
            rel = os.path.relpath(p, root)
            if stat.S_ISLNK(st.st_mode):
                yield rel, "symlink", 0, os.readlink(p)
            elif stat.S_ISDIR(st.st_mode):
                yield rel, "dir", stat.S_IMODE(st.st_mode), ""
            elif stat.S_ISREG(st.st_mode):
                yield rel, "file", stat.S_IMODE(st.st_mode), sha256_file(p)
        # os.walk 默认不跟软链目录，符合预期


def fingerprint(path):
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return {"kind": "absent"}
    if stat.S_ISLNK(st.st_mode):
        return {"kind": "symlink", "target": os.readlink(path)}
    if stat.S_ISDIR(st.st_mode):
        h, n = hashlib.sha256(), 0
        for rel, kind, mode, val in walk_tree(path):
            h.update(("%s\0%s\0%o\0%s\n" % (rel, kind, mode, val)).encode("utf-8", "surrogateescape"))
            n += 1
        return {"kind": "dir", "mode": stat.S_IMODE(st.st_mode), "tree": h.hexdigest(), "count": n}
    if stat.S_ISREG(st.st_mode):
        return {"kind": "file", "mode": stat.S_IMODE(st.st_mode), "sha256": sha256_file(path)}
    return {"kind": "other"}


def inside(p, root):
    # normcase：Windows 上路径不分大小写、/ 和 \ 混用；mac / Linux 上它什么也不做
    p, root = os.path.normcase(p), os.path.normcase(root)
    return p == root or p.startswith(root.rstrip(os.sep) + os.sep)


def forbidden(path):
    b = os.path.basename(path).lower()
    return (b.startswith(".credentials") or b in ("auth.json", ".claude.json", ".env") or b.endswith(".env")
            or "oauth" in b)


def resolve_target(path, roots, home):
    """返回规范化后的路径（父目录解析软链，自身不解析）。不在允许范围内就退出。"""
    parent = os.path.realpath(os.path.dirname(path))
    full = os.path.join(parent, os.path.basename(path))
    if not any(inside(full, r) for r in roots):
        die("%s 不在允许写的范围内（HOME 或 backup 时用 --root 声明的目录）。" % path)
    if inside(full, os.path.join(os.path.realpath(home), STORE)):
        die("不能对备份目录自己做操作。")
    if forbidden(full):
        die("%s 是凭据或运行状态文件，这个工具不碰。" % show(full, home))
    return full


def is_reparse(p):
    """软链，或 Windows 的目录联接等重解析点（Python 3.12 以前 islink 认不出 junction）。"""
    try:
        st = os.lstat(p)
    except OSError:
        return False
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & 0x400)  # FILE_ATTRIBUTE_REPARSE_POINT


def windows_link_inside(p):
    """p 本身或它目录里面有没有软链 / 联接。返回第一个找到的，没有返回 None。"""
    if is_reparse(p):
        return p
    if os.path.isdir(p):
        for dp, dn, fn in os.walk(p):
            for n in dn + fn:
                q = os.path.join(dp, n)
                if is_reparse(q):
                    return q
            dn[:] = [d for d in dn if not is_reparse(os.path.join(dp, d))]
    return None


def entry_for(m, path):
    for i, e in enumerate(m["entries"]):
        if os.path.normcase(e["path"]) == os.path.normcase(path):
            return i, e
    return None, None


def require_open(m):
    if m.get("rolled_back"):
        die("备份 %s 已经回滚过，不能再往里加改动。新开一个 backup。" % m["id"])
    if m.get("sealed"):
        die("备份 %s 已封存。要继续改，新开一个 backup。" % m["id"])


def cmd_backup(args, home):
    rhome = os.path.realpath(home)
    roots = [rhome] + [os.path.realpath(expand(r, home)) for r in (args.root or [])]
    roots += [os.path.realpath(d) for d in (CONF["claude"], CONF["codex"]) if d and not any(inside(os.path.realpath(d), r) for r in roots)]
    paths = []
    for p in args.paths:
        full = resolve_target(expand(p, home), roots, home)
        if full not in paths:
            paths.append(full)
    if is_windows():
        for p in paths:
            q = windows_link_inside(p)
            if q:
                die("%s 是软链或目录联接（或者里面有）。Windows 上备份、回滚这类东西的行为没有验证过，"
                    "回滚可能把联接变成一份普通拷贝，已拒绝。只备份里面的普通文件，或手动改。" % show(q, home))
    # 软链指向的真实文件：在允许范围内就一并备份
    extra, notes = [], []
    for p in paths:
        if os.path.islink(p):
            real = os.path.realpath(p)
            if any(inside(real, r) for r in roots) and os.path.isfile(real) and not forbidden(real):
                if real not in paths and real not in extra:
                    extra.append(real)
                notes.append("%s 是软链，真实文件 %s 也一并备份了；要改内容请改真实文件。" % (show(p, home), show(real, home)))
            else:
                notes.append("%s 是软链，指向 %s，在允许范围之外。这个工具不改它指向的内容。" % (show(p, home), os.readlink(p)))
    paths += extra
    for a in paths:
        for b in paths:
            if a != b and inside(a, b):
                die("%s 在 %s 里面，两个不能同时列。只列外层那个。" % (show(a, home), show(b, home)))

    root = store_root(home)
    os.makedirs(root, mode=0o700, exist_ok=True)
    os.chmod(os.path.join(home, STORE), 0o700)
    os.chmod(root, 0o700)
    base = time.strftime("%Y%m%d-%H%M%S")
    bid, n = base, 1
    while True:
        try:
            os.makedirs(os.path.join(root, bid), mode=0o700)
            break
        except FileExistsError:
            n += 1
            bid = "%s-%d" % (base, n)
    bdir = os.path.join(root, bid)
    entries = []
    for i, p in enumerate(paths):
        fp = fingerprint(p)
        if fp["kind"] == "other":
            die("%s 不是普通文件、目录或软链。" % p)
        dst = os.path.join(bdir, "pre", str(i))
        if fp["kind"] == "file":
            os.makedirs(dst, mode=0o700)
            shutil.copy2(p, os.path.join(dst, "blob"))
        elif fp["kind"] == "dir":
            os.makedirs(dst, mode=0o700)
            shutil.copytree(p, os.path.join(dst, "tree"), symlinks=True)
        entries.append({"path": p, "pre": fp})
    m = {"id": bid, "created": time.strftime("%Y-%m-%d %H:%M:%S"), "note": args.note or "",
         "home": rhome, "roots": roots, "entries": entries, "created_dirs": [], "ops": [],
         "sealed": None, "rolled_back": None, "tool_version": VERSION}
    save_manifest(home, m)
    print("备份 %s 已建好：%s" % (bid, show(bdir, home)))
    for e in entries:
        print("  - %s [%s]" % (show(e["path"], home), {"file": "文件", "dir": "目录", "symlink": "软链", "absent": "现在不存在，回滚时会移走新建的"}[e["pre"]["kind"]]))
    for nline in notes:
        print("注意：" + nline)
    print("备份里是原样拷贝，可能含凭据，目录权限 0700。不要提交或同步出去。")
    print("回滚：python3 %s rollback --backup %s" % (os.path.abspath(__file__), bid))


def struct_get(obj, path):
    cur = obj
    for k in path:
        if isinstance(k, dict):
            if not isinstance(cur, list):
                return MISSING
            hit = [x for x in cur if isinstance(x, dict) and all(x.get(a) == b for a, b in k.items())]
            if not hit:
                return MISSING
            cur = hit[0]
        else:
            if not isinstance(cur, dict) or k not in cur:
                return MISSING
            cur = cur[k]
    return cur


def struct_apply(obj, path, value, delete):
    cur = obj
    for idx, k in enumerate(path[:-1]):
        nxt = path[idx + 1]
        if isinstance(k, dict):
            hit = [x for x in cur if isinstance(x, dict) and all(x.get(a) == b for a, b in k.items())]
            if hit:
                cur = hit[0]
            elif delete:
                return
            else:
                new = dict(k)
                cur.append(new)
                cur = new
        else:
            if k not in cur:
                if delete:
                    return
                cur[k] = [] if isinstance(nxt, dict) else {}
            cur = cur[k]
            want = list if isinstance(nxt, dict) else dict
            if not isinstance(cur, want):
                die("路径 %s 处的现有值类型对不上，没有改。" % json.dumps(path[:idx + 1], ensure_ascii=False))
    if delete:
        cur.pop(path[-1], None)
    else:
        cur[path[-1]] = value


def split_newlines(text, kind):
    """返回 (原文的换行符, 换行统一成 \\n 的文本)。改完再换回去，CRLF 文件不会变成 LF。
    CRLF 和 LF 混用、或有单独的 \\r 的，判断不了该用哪种，拒绝。"""
    crlf = text.count("\r\n")
    if (crlf and crlf != text.count("\n")) or "\r" in text.replace("\r\n", ""):
        die("这个 %s 文件里 CRLF 和 LF 换行混用，脚本改完没法保证其余字节不变，没有改。请手动改，改动仍在备份保护内。" % kind)
    return ("\r\n" if crlf else "\n"), (text.replace("\r\n", "\n") if crlf else text)


def json_edit(text, path, value, delete):
    if any(isinstance(k, dict) for k in path[-1:]):
        die("--path 的最后一项必须是键名。")
    nl, text = split_newlines(text, "JSON")
    try:
        obj = json.loads(text) if text.strip() else {}
    except ValueError as e:
        die("这个 JSON 文件解析不了（%s），没有改。可能带注释，请手动改。" % e)
    if not isinstance(obj, dict):
        die("JSON 顶层不是对象，没有改。")
    old = struct_get(obj, path)
    expected = copy.deepcopy(obj)
    struct_apply(expected, path, value, delete)
    m = re.search(r'\n([ \t]+)"', text)
    indent = m.group(1) if m else "  "
    indent = "\t" if indent.startswith("\t") else len(indent)
    ascii_only = bool(text) and all(ord(ch) < 128 for ch in text)
    tail = "\n" if text.endswith("\n") or not text else ""
    # 整份重写，只有原文本来就是这个格式时，目标键以外的字节才不会变；不是就不改
    if text.strip() and json.dumps(obj, indent=indent, ensure_ascii=ascii_only) + tail != text:
        die("这个 JSON 文件的排版和脚本写出的格式不一样（比如手工排的版），改一个键会连带改动别处，没有改。"
            "请手动改，改动仍在备份保护内。")
    new = json.dumps(expected, indent=indent, ensure_ascii=ascii_only) + tail
    if json.loads(new) != expected:
        die("写出的 JSON 校验没过，没有改。")
    return new.replace("\n", nl), old


def toml_literal(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return repr(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list) and all(not isinstance(i, (dict, list)) for i in v):
        return "[" + ", ".join(toml_literal(i) for i in v) + "]"
    die("TOML 只支持写入标量和标量数组。")


def toml_key(k):
    return k if re.fullmatch(r"[A-Za-z0-9_-]+", k) else json.dumps(k, ensure_ascii=False)


def toml_edit(text, path, value, delete):
    if tomllib is None:
        die("这个 Python 没有 tomllib（要 3.11 以上），改不了 TOML。请手动改，改动仍在备份保护内。")
    sel_at = [i for i, k in enumerate(path) if isinstance(k, dict)]
    if len(sel_at) > 1 or (sel_at and sel_at[0] != len(path) - 2) or isinstance(path[-1], dict):
        die("TOML 的 --path 只支持：表路径 + 键名，或 表路径 + {选择条件} + 键名。")
    table = path[:sel_at[0]] if sel_at else path[:-1]
    sel = path[sel_at[0]] if sel_at else None
    key = path[-1]
    nl, text = split_newlines(text, "TOML")
    try:
        old_obj = tomllib.loads(text)
    except Exception as e:
        die("这个 TOML 文件解析不了（%s），没有改。" % e)
    old = struct_get(old_obj, path)
    expected = copy.deepcopy(old_obj)
    struct_apply(expected, path, value, delete)

    lines = text.split("\n")
    heads = []
    for i, ln in enumerate(lines):
        m = HEADER_RE.match(ln)
        if m and len(m.group(1)) == len(m.group(3)):
            heads.append((i, m.group(1) == "[[", _split_key(m.group(2))))
    bounds = [h[0] for h in heads] + [len(lines)]

    def kv(line):
        try:
            return tomllib.loads(line)
        except Exception:
            return None

    seg = None
    if not table and sel is None:
        seg = (0, bounds[0], None)
    else:
        for n, (i, is_arr, parts) in enumerate(heads):
            if parts != table or is_arr != (sel is not None):
                continue
            start, end = i + 1, bounds[n + 1]
            if sel is not None:
                body = {}
                for ln in lines[start:end]:
                    d = kv(ln)
                    if d:
                        body.update(d)
                if not all(body.get(a) == b for a, b in sel.items()):
                    continue
            seg = (start, end, i)
            break

    newline = "%s = %s" % (toml_key(key), None if delete else toml_literal(value))
    if seg is None:
        if delete:
            return text.replace("\n", nl), old
        head = ".".join(toml_key(p) for p in table)
        block = ["[[%s]]" % head if sel is not None else "[%s]" % head]
        for a, b in (sel or {}).items():
            block.append("%s = %s" % (toml_key(a), toml_literal(b)))
        block.append(newline)
        body = text if text.endswith("\n") or not text else text + "\n"
        new = body + ("\n" if body.strip() else "") + "\n".join(block) + "\n"
    else:
        start, end, _h = seg
        hit = None
        for j in range(start, end):
            d = kv(lines[j])
            if d is not None and list(d.keys()) == [key]:
                hit = j
                break
            if re.match(r"^\s*(%s|%s)\s*=" % (re.escape(key), re.escape(json.dumps(key))), lines[j]) and d is None:
                die("%s 现在的值跨多行，脚本不改这种，请手动改。" % key)
        if delete:
            if hit is None:
                return text.replace("\n", nl), old
            del lines[hit]
        elif hit is not None:
            lines[hit] = re.match(r"^\s*", lines[hit]).group(0) + newline
        else:
            at = start
            if _h is None:  # 顶层：插在顶层键的最后一行后面
                at = start
                for j in range(start, end):
                    if lines[j].strip():
                        at = j + 1
            lines.insert(at, newline)
        new = "\n".join(lines)
    try:
        got = tomllib.loads(new)
    except Exception as e:
        die("改完的 TOML 解析不了（%s），文件没动。请手动改。" % e)
    if got != expected:
        die("改完的 TOML 和预期不一致，文件没动。请手动改。")
    return new.replace("\n", nl), old


def track_makedirs(m, d):
    made = []
    while d and not os.path.isdir(d):
        made.append(d)
        d = os.path.dirname(d)
    for p in reversed(made):
        os.mkdir(p)
        m["created_dirs"].append(p)


def atomic_write(path, text, mode):
    # 先写临时文件再整体替换：任何一步失败，原文件都还是原样，临时文件删掉，不留半截
    tmp = path + ".save-my-tokens-tmp"
    try:
        with open(tmp, "w", encoding="utf-8", newline="") as f:
            f.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except OSError as e:
        try:
            os.remove(tmp)
        except OSError:
            pass
        if isinstance(e, PermissionError):
            die("写 %s 被拒绝（%s）。Windows 上多半是文件正被别的程序占用（Claude Code、Codex、编辑器、杀毒软件），"
                "或者文件是只读的。原文件没动。关掉占用它的程序后再试。" % (path, e))
        die("写 %s 失败（%s），原文件没动。" % (path, e))


def redacted(path, v):
    if v is MISSING:
        return "（无）"
    names = [k for k in path if isinstance(k, str)]
    if any(SECRET_RE.search(k) for k in names):
        return "<已遮掉>"
    # 值本身是一整个对象时（比如删掉整个 env），里面键名像凭据的、env 和 headers 下面的值也要遮
    return clip(json.dumps(mask_secrets(v, hot=any(k in ("env", "headers") for k in names)), ensure_ascii=False), 80)


def check_path(path):
    if not isinstance(path, list) or not path or not all(isinstance(k, (str, dict)) for k in path):
        die("--path 要写成 JSON 数组，元素是键名（字符串）或选择条件（对象）。")


def cmd_set(args, home):
    many = getattr(args, "many", None)
    if many:
        args.many = many
        if args.path or args.value is not None or args.delete:
            die("--many 和 --path / --value / --delete 不能一起用。")
        try:
            with open(args.many, "r", encoding="utf-8-sig") as f:
                items = json.load(f)
        except (OSError, ValueError) as e:
            die("--many 的文件读不了或不是 JSON：%s" % e)
        if not isinstance(items, list) or not items:
            die("--many 的文件要是一个 JSON 数组，每项形如 {\"path\": [...], \"value\": ...} 或 {\"path\": [...], \"delete\": true}。")
        edits = []
        for it in items:
            if not isinstance(it, dict) or ("value" in it) == bool(it.get("delete")):
                die("--many 里每一项要有 path，再加 value 或 \"delete\": true 其中一个。")
            check_path(it.get("path"))
            edits.append((it["path"], it.get("value"), bool(it.get("delete"))))
        return apply_edits(home, args.backup, args.file, edits)
    if not args.path:
        die("要给 --path（改一个键），或 --many（一次改很多个键）。")
    try:
        path = json.loads(args.path)
    except ValueError:
        die("--path 要写成 JSON 数组，例如 '[\"skillOverrides\",\"deploy\"]'。")
    check_path(path)
    if args.delete == (args.value is not None):
        die("--value 和 --delete 二选一。")
    value = None
    if not args.delete:
        try:
            value = json.loads(args.value)
        except ValueError:
            die("--value 要写成 JSON，例如 '\"off\"'、false、350000。")
    apply_edits(home, args.backup, args.file, [(path, value, bool(args.delete))])


SKILL_STATES = {"off": "off", "关掉": "off", "manual": "user-invocable-only", "user-invocable-only": "user-invocable-only",
                "只能手动调": "user-invocable-only", "name": "name-only", "name-only": "name-only", "只留名字": "name-only",
                "on": "on", "保留": "on"}


def group_members(scan_path, group):
    ev, err = load_json_file(scan_path, config=False)
    if not isinstance(ev, dict) or "claude" not in ev:
        die("%s 不是 scan --json 写出的文件（%s）。" % (scan_path, err or "格式不对"))
    return [s for s in ev["claude"].get("skills") or [] if s.get("group") == group.upper()], ev


def agy_scan(scan_path):
    ev, err = load_json_file(scan_path, config=False)
    if not isinstance(ev, dict) or "claude" not in ev:
        die("%s 不是 scan --json 写出的文件（%s）。" % (scan_path, err or "格式不对"))
    a = ev.get("antigravity")
    if not isinstance(a, dict) or not a.get("present"):
        die("这份扫描里没有 Antigravity 的内容（扫描时这台机器上没找到 ~/.gemini/config 和 Antigravity 的会话目录，或者是旧版脚本扫的）。重新 scan --json 一次。")
    return a, ev


def cmd_skills_agy(args, home):
    """Antigravity：把 skill 写进（或拿出）~/.gemini/config/skills.json 顶层的 exclude。只动这一个文件，skill 文件不碰。
    排除名单按 skill 的目录名匹配；它管得到全局的、~/.agents/skills 的、项目里的和内置的，管不到只有命令行读的那两个目录。"""
    state = {"off": "off", "关掉": "off", "on": "on", "保留": "on"}.get(args.state)
    if not state:
        die("Antigravity 的 skill 只有两种状态：off（写进排除名单，模型看不见）和 on（从排除名单里拿掉）。"
            "要「只能手动调」，得在那个 skill 的 SKILL.md 开头写 disable-model-invocation: true，这是改 skill 文件本身，"
            "和别的 agent 共用的 skill 会一起受影响，脚本不代做。")
    g = gemini_dir(home)
    cfg = os.path.join(g, "config")
    mf = os.path.join(cfg, "skills.json")
    known, alias = {}, {}

    def add(base, scope):
        for it in list_skills(base, scope):
            known.setdefault(it["dir"], set()).add(scope)
            if it["name"] != it["dir"]:
                alias.setdefault(it["name"], it["dir"])

    add(os.path.join(cfg, "skills"), "global")
    add(os.path.join(g, "antigravity-cli", "skills"), "cli-only")
    add(os.path.join(g, "skills"), "cli-only")
    add(os.path.join(home, ".agents", "skills"), "agents-home")
    entries, _ex, _err, _inh = agy_manifest(mf)
    for e_ in entries:
        for it in agy_entry_skills(e_, cfg, "manifest"):
            known.setdefault(it["dir"], set()).add("manifest")
            if it["name"] != it["dir"]:
                alias.setdefault(it["name"], it["dir"])
    for app in agy_app_dirs(home):
        add(os.path.join(g, app, "builtin", "skills"), "builtin")
    live = set(known)        # 此刻磁盘上真有的（下面再把扫描里记的项目 skill 并进 known）
    a = None
    if args.scan:
        a, _ev = agy_scan(args.scan)
        for it in a.get("skills") or []:
            known.setdefault(it["dir"], set()).add(it["scope"].split(":")[0])
            if it["name"] != it["dir"]:
                alias.setdefault(it["name"], it["dir"])
    names = []
    for n in args.names or []:
        if n not in known and n in alias:
            print("注意：%s 是 SKILL.md 里写的名字，它的目录名是 %s；排除名单按目录名匹配，这次按 %s 处理。" % (n, alias[n], alias[n]))
            n = alias[n]
        names.append(n)
    cur, err = load_json_file(mf)
    if err != "absent" and not isinstance(cur, dict):
        die("%s 解析不了（%s），没有改。" % (show(mf, home), err or "顶层不是对象"))
    old = (cur or {}).get("exclude")
    if old is None:
        old = []
    if not isinstance(old, list) or not all(isinstance(x, str) for x in old):
        die("%s 里的 exclude 不是一个名字列表，没有改，请手动看一下。" % show(mf, home))
    bad = [n for n in names if n not in known and not (state == "on" and n in old)]
    if bad:
        die("找不到这些 skill：%s。没有改。检查拼写（要写目录名）；项目里的 skill 加 --scan <json> 按扫描到的名单核对。" % "、".join(bad))
    if args.group:
        if a is None:
            die("用 --group 要同时给 --scan <scan --json 写出的文件>。")
        if args.group.upper() not in ("A", "B"):
            die("Antigravity 这边 --group 取 A 或 B。E 组是在用的，不整组改；要改其中某个就点名。")
        members = [it["dir"] for it in a.get("skills") or [] if it.get("group") == args.group.upper()]
        gone = [n for n in members if n not in live]
        if gone:
            die("这份扫描之后配置变过：%s 组里的 %s 现在已经不在原来的位置。没有改。重新 scan --json 一次，再用新的那份。" % (args.group.upper(), "、".join(gone)))
        names += members
    skip = set(args.exclude or [])
    stray = [n for n in skip if n not in names]
    if stray:
        die("--exclude 里的 %s 不在这次要改的名单里（是不是拼错了）。没有改。" % "、".join(sorted(stray)))
    names = [n for i, n in enumerate(names) if n not in skip and n not in names[:i]]
    if not names:
        die("没有要改的 skill：给名字，或给 --scan 加 --group。")
    if state == "off":
        stuck = [n for n in names if known.get(n) and known[n] <= {"cli-only"}]
        if stuck:
            die("这些 skill 只在命令行专用的目录里（~/.gemini/antigravity-cli/skills、~/.gemini/skills）：%s。"
                "排除名单管不到这两个目录（官方文档写明，实测也是），写进去不会生效。没有改。要停用只能把它的目录搬走：slim move。" % "、".join(stuck))
        new = old + [n for n in names if n not in old]
    else:
        new = [x for x in old if x not in names]
    if new == old:
        print("没有变化：这 %d 个 skill %s。" % (len(names), "已经在排除名单里" if state == "off" else "本来就不在排除名单里"))
        return
    apply_edits(home, args.backup, mf, [(["exclude"], new, False)])
    if state == "off":
        print("写进排除名单 %d 个：%s。" % (len(new) - len(old), "、".join(n for n in new if n not in old)))
    else:
        print("从排除名单拿掉 %d 个：%s。" % (len(old) - len(new), "、".join(n for n in old if n not in new)))
    print("Antigravity 每次请求前都会重新读这份名单，正在开着的会话下一句话就生效，不用重启。skill 文件没有动，和别的 agent 共用的不受影响。")


def cmd_skills(args, home):
    """一次改很多个 skill 的状态：整组，或点名的几个。只动 settings.json 的 skillOverrides，skill 文件不碰。"""
    if getattr(args, "agent", "claude") == "agy":
        return cmd_skills_agy(args, home)
    state = SKILL_STATES.get(args.state)
    if not state:
        die("--state 取 off（关掉）、manual（只能手动调）、name（只留名字）、on（保留）之一。")
    names = list(args.names or [])
    # 点名的名字先核对一遍：拼错的名字写进 skillOverrides 不会报错，只会悄悄不生效
    known = None
    if args.scan:
        ev0, err = load_json_file(args.scan, config=False)
        if not isinstance(ev0, dict) or "claude" not in ev0:
            die("%s 不是 scan --json 写出的文件（%s）。" % (args.scan, err or "格式不对"))
        known = set(s["name"] for s in ev0["claude"].get("skills") or [])
    else:
        sd = os.path.join(claude_dir(home), "skills")
        if os.path.isdir(sd):
            known = set(os.listdir(sd))
            cur, _e = load_json_file(os.path.join(claude_dir(home), "settings.json"))
            if isinstance(cur, dict) and isinstance(cur.get("skillOverrides"), dict):
                known |= set(cur["skillOverrides"])
    if known is not None:
        bad = [n for n in names if n not in known]
        if bad:
            die("找不到这些 skill：%s。没有改。检查拼写；项目级、插件里的 skill 加 --scan <json> 按扫描到的名单核对；Claude Code 内置的 skill 用 slim set 改 skillOverrides。" % "、".join(bad))
    if args.group:
        if not args.scan:
            die("用 --group 要同时给 --scan <scan --json 写出的文件>。")
        if args.group.upper() not in ("A", "B", "C", "D"):
            die("--group 取 A、B、C、D 之一。E 组是在用的，不整组改；要改其中某个就点名。")
        members, _ev = group_members(args.scan, args.group)
        names += [s["name"] for s in members]
    skip = set(args.exclude or [])
    stray = [n for n in skip if n not in names]
    if stray:
        die("--exclude 里的 %s 不在这次要改的名单里（是不是拼错了）。没有改。" % "、".join(sorted(stray)))
    names = [n for i, n in enumerate(names) if n not in skip and n not in names[:i]]
    if not names:
        die("没有要改的 skill：给名字，或给 --scan 加 --group。")
    edits = [(["skillOverrides", n], state, False) for n in names]
    apply_edits(home, args.backup, os.path.join(claude_dir(home), "settings.json"), edits,
                summary="%d 个 skill 改成 %s" % (len(names), state))


def cmd_show(args, home):
    """从上次 scan 的 json 里取一组 skill 的完整名单，不用重扫。"""
    if getattr(args, "agent", "claude") == "agy":
        a, ev = agy_scan(args.scan)
        G = args.group.upper()
        title = {"A": "没读过，也找不到留着的理由", "B": "没读过，但有理由先留着", "E": "近期有会话读过"}.get(G)
        if not title:
            die("Antigravity 这边 --group 取 A、B、E 之一。")
        members = sorted([s for s in a.get("skills") or [] if s.get("group") == G], key=lambda s: (-s["desc_chars"], s["dir"]))
        if args.names:
            print(" ".join(s["dir"] for s in members))
            return
        print("Antigravity %s 组 %d 个：%s（近 %d 天）" % (G, len(members), title, ev.get("days", 30)))
        for s in members:
            bits = ["描述 %d 字符" % s["desc_chars"], "%d 个会话读过" % s["reads"]]
            if s["scope"] == "agents-home":
                bits.append("在 ~/.agents/skills")
            if s.get("shared_with_claude"):
                bits.append("和 Claude Code 共用同一份文件")
            if s.get("flags"):
                bits.append("⚠ " + "；".join(s["flags"]))
            if s.get("referenced_by"):
                bits.append("引用它的：" + "、".join(show(p_, home) for p_ in s["referenced_by"][:2]))
            print("  - %s [%s]" % (s["dir"], "，".join(bits)))
        return
    members, ev = group_members(args.scan, args.group)
    title = dict((g, t) for g, t, _a in SKILL_GROUPS).get(args.group.upper())
    if not title:
        die("--group 取 A、B、C、D、E 之一。")
    members.sort(key=lambda s: (-s["desc_chars"], s["dir"]))
    if args.names:
        print(" ".join(s["name"] for s in members))
        return
    print("%s 组 %d 个：%s（近 %d 天）" % (args.group.upper(), len(members), title, ev.get("days", 30)))
    for s in members:
        bits = ["描述 %d 字符" % s["desc_chars"], "手敲 %d" % s["user_calls"], "模型调 %d" % s["model_calls"]]
        if s.get("codex_reads"):
            bits.append("Codex 读 %d" % s["codex_reads"])
        if s.get("flags"):
            bits.append("⚠ " + "；".join(s["flags"]))
        if s.get("referenced_by"):
            bits.append("引用它的：" + "、".join(show(p, home) for p in s["referenced_by"][:2]))
        print("  - %s [%s]" % (s["name"], "，".join(bits)))


def load_tools(scan_path, entry=None):
    ev, err = load_json_file(scan_path, config=False)
    if not isinstance(ev, dict) or "claude" not in ev:
        die("%s 不是 scan --json 写出的文件（%s）。" % (scan_path, err or "格式不对"))
    tt = ev["claude"].get("tools")
    if entry and not (tt and tt.get("entrypoint") == entry):
        alt = ev["claude"].get("tools_alt") or {}
        if entry not in alt:
            die("这份扫描里没有入口 %s 的工具清单。有的是：%s。" % (entry, "、".join(
                ([str(tt.get("entrypoint"))] if tt else []) + sorted(alt)) or "（无）"))
        tt = alt[entry]
    if not tt:
        die("这份扫描里没有逐个工具的清单（日志没记）。请用户新开一个会话输入 /context，把 MCP tools 一栏展开后的列表贴过来，照那份列表做。")
    return tt, ev


def cmd_tools(args, home):
    """从 scan 的 json 里取逐个工具的编号表。编号在同一份 json 里固定，筛选不改变编号。"""
    tt, ev = load_tools(args.scan, args.entry)
    rows = tt["items"]
    if args.server:
        want = set(norm_server(s) for s in args.server)
        rows = [r for r in rows if norm_server(r["server"] or "builtin") in want]
    if args.loaded:
        rows = [r for r in rows if r["load"] == "常驻"]
    print("新开会话时发给模型的工具（%s 的会话%s；延迟加载%s；调用次数是近 %d 天）。%s" % (
        md(tt["ts"]), "，入口 " + tt["entrypoint"] if tt.get("entrypoint") else "", "开着" if tt["tool_search"] else "没开", ev.get("days", 30),
        "「常驻」整份带着，「按需」只占一个名字。" if tt["tool_search"] else "延迟加载没开，所有工具都整份带着。"))
    print("编号  加载  字符  调用  工具名")
    for r in rows:
        print("%3d  %s  %6s  %4d  %s%s" % (r["n"], r["load"], num(r["chars"]) if r["chars"] is not None else "-", r["calls"], r["name"],
                                           "  （之后已屏蔽）" if r.get("denied") else ""))
    if not rows:
        print("（没有符合条件的工具）")
    if tt["deny"]:
        print("已经屏蔽的：" + "、".join(tt["deny"]))


def parse_nums(specs, top):
    out = []
    for spec in specs:
        for part in str(spec).replace("，", ",").split(","):
            part = part.strip()
            if not part:
                continue
            m = re.match(r"^(\d+)(?:-(\d+))?$", part)
            if not m:
                die("编号 %r 看不懂。写成 3、5-8 这样。没有改。" % part)
            a, b = int(m.group(1)), int(m.group(2) or m.group(1))
            if not (1 <= a <= b <= top):
                die("编号 %s 超出范围（这份扫描里是 1 到 %d）。没有改。" % (part, top))
            out.extend(range(a, b + 1))
    return out


def cmd_deny(args, home):
    """屏蔽（或恢复）工具：只动 ~/.claude/settings.json 的 permissions.deny，别的键不碰。
    单个工具写工具名，整个 MCP server 写 mcp__<server>。"""
    names = list(args.names or [])
    tt = None
    if args.scan:
        tt, _ev = load_tools(args.scan, args.entry)
    if args.nums:
        if not tt:
            die("用 --nums 要同时给 --scan <scan --json 写出的文件>：编号是那份扫描里的编号。")
        by_n = {r["n"]: r["name"] for r in tt["items"]}
        names += [by_n[n] for n in parse_nums(args.nums, len(by_n))]
    for srv in args.server or []:
        names.append(srv if srv.startswith("mcp__") else "mcp__" + srv)
    names = [n for i, n in enumerate(names) if n not in names[:i]]
    if not names:
        die("没有要屏蔽的工具：给工具名、--nums 编号，或 --server <名字>。")
    bad = [n for n in names if not BARE_TOOL_RE.match(n)]
    if bad:
        die("这些不是工具名：%s。这里只收完整的工具名（如 NotebookEdit、mcp__lsp__hover）或 mcp__<server>；"
            "Bash(…) 这类权限规则用 slim set 改。没有改。" % "、".join(bad))
    settings_path = os.path.join(claude_dir(home), "settings.json")
    cur, _e = load_json_file(settings_path)
    perms = cur.get("permissions") if isinstance(cur, dict) and isinstance(cur.get("permissions"), dict) else {}
    deny = perms.get("deny") if isinstance(perms.get("deny"), list) else []
    if "deny" in perms and not isinstance(perms.get("deny"), list):
        die("settings.json 的 permissions.deny 不是数组，没有改。")
    if args.remove:
        gone = [n for n in names if n not in deny]
        if gone:
            die("permissions.deny 里没有这些：%s。没有改。" % "、".join(gone))
        new = [d for d in deny if d not in names]
    else:
        if tt:
            known = set(r["name"] for r in tt["items"]) | set("mcp__" + r["server"] for r in tt["items"] if r["server"])
            typo = [n for n in names if n not in known]
            if typo:
                die("这份扫描的工具清单里没有：%s。没有改。拼错的名字写进 permissions.deny 不会报错，只会悄悄不生效；"
                    "确实要屏蔽清单外的工具（连接得晚的 MCP server 的），去掉 --scan 再点名。" % "、".join(typo))
        new = deny + [n for n in names if n not in deny]
    apply_edits(home, args.backup, settings_path, [(["permissions", "deny"], new, False)])
    print("%s %d 个：%s" % ("恢复了" if args.remove else "屏蔽了", len(names), "、".join(names)))
    if not args.remove and tt and tt["tool_search"]:
        lazy = set(r["name"] for r in tt["items"] if r["load"] == "按需")
        n_lazy = len([n for n in names if n in lazy])
        if n_lazy:
            print("其中 %d 个本来就是按需加载的，只占一个名字，屏蔽它们几乎不省上下文。" % n_lazy)


def apply_edits(home, backup_id, file_arg, edits, summary=None):
    """对同一个 JSON / TOML 文件做一批改动，全部成功才写回一次；任何一项被拒，文件不动。"""
    for path, value, delete in edits:
        if path == ["autoCompactWindow"] and not delete and not (isinstance(value, int) and not isinstance(value, bool) and 100000 <= value <= 1000000):
            die("autoCompactWindow 要是 100000 到 1000000 之间的整数，收到的是 %s。没有改。" % json.dumps(value, ensure_ascii=False))
    m = load_manifest(home, backup_id)
    require_open(m)
    full = resolve_target(expand(file_arg, home), m["roots"], home)
    _i, e = entry_for(m, full)
    if e is None:
        die("%s 不在备份 %s 里。先把它加进一个新的 backup 再改。" % (show(full, home), m["id"]))
    if os.path.islink(full):
        die("%s 是软链。要改就改它指向的真实文件（并确保真实文件在备份里）。" % show(full, home))
    if e["pre"]["kind"] not in ("file", "absent"):
        die("%s 不是文件。" % show(full, home))
    exists = os.path.isfile(full)
    text = ""
    if exists:
        try:
            # newline=""：原样读进 CRLF，改完原样写回
            with open(full, "r", encoding="utf-8", newline="") as f:
                text = f.read()
        except UnicodeDecodeError:
            die("%s 不是 UTF-8 编码（可能是 GBK），脚本不改，请手动改。" % show(full, home))
    bom = chr(0xFEFF) if text.startswith(chr(0xFEFF)) else ""   # Windows 记事本可能加 BOM，原样保留
    body = text[len(bom):]
    if not (full.endswith(".toml") or full.endswith(".json")):
        die("set 只改 .json 和 .toml。别的文件请直接编辑，改动仍在备份保护内。")
    edit = toml_edit if full.endswith(".toml") else json_edit
    done = []
    for path, value, delete in edits:
        before = body
        body, old = edit(body, path, value, delete)
        label = ".".join(k if isinstance(k, str) else json.dumps(k, ensure_ascii=False) for k in path)
        if body != before:
            done.append((path, label, old, value, delete))
    if not done:
        print("没有变化：%s 里%s已经是这个值。" % (show(full, home), " " + label + " " if len(edits) == 1 else "这 %d 项" % len(edits)))
        return
    mode = stat.S_IMODE(os.lstat(full).st_mode) if exists else 0o600
    track_makedirs(m, os.path.dirname(full))
    atomic_write(full, bom + body, mode)
    for path, label, old, value, delete in done:
        m["ops"].append({"op": "set", "file": full, "path": path, "delete": bool(delete),
                         "old": redacted(path, old), "new": "（删除）" if delete else redacted(path, value)})
    save_manifest(home, m)
    if len(edits) == 1:
        path, label, old, value, delete = done[0]
        print("已改 %s：%s  %s → %s" % (show(full, home), label, redacted(path, old), "（删除）" if delete else redacted(path, value)))
        return
    same = len(edits) - len(done)
    print("已改 %s：%s%s，一次写回。" % (show(full, home), summary or "%d 项" % len(edits),
                                  "，其中 %d 项本来就是这个值，实际变了 %d 项" % (same, len(done)) if same else ""))
    for path, label, old, value, delete in done[:12]:
        print("  %s  %s → %s" % (label, redacted(path, old), "（删除）" if delete else redacted(path, value)))
    if len(done) > 12:
        print("  …还有 %d 项，完整清单看 slim list" % (len(done) - 12))


def cmd_move(args, home):
    m = load_manifest(home, args.backup)
    require_open(m)
    src = resolve_target(expand(args.src, home), m["roots"], home)
    dst = resolve_target(expand(args.dst, home), m["roots"], home)
    _i, es = entry_for(m, src)
    _j, ed = entry_for(m, dst)
    if es is None or ed is None:
        die("src 和 dst 都要先列进 backup 的 --paths（dst 现在不存在也要列）。dst 要写搬过去之后的完整路径，含最后那一级名字，不是它的上级目录。")
    if not os.path.lexists(src):
        die("%s 不存在。" % show(src, home))
    if os.path.lexists(dst):
        die("%s 已经存在，不覆盖。" % show(dst, home))
    track_makedirs(m, os.path.dirname(dst))
    try:
        os.rename(src, dst)
    except OSError:
        shutil.move(src, dst)
    m["ops"].append({"op": "move", "src": src, "dst": dst})
    save_manifest(home, m)
    print("已搬 %s → %s" % (show(src, home), show(dst, home)))


# ------------------------------------------------------------------ 压缩前后的两个 hook

_HOOK_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "hooks")
# after：压缩完那一刻往模型上下文里放一段提醒。before：压缩前给写摘要的模型加几句要求。
HOOK_SPECS = {
    "after": {"name": "save-my-tokens-compact.py", "src": os.path.join(_HOOK_DIR, "compact-reminder.py"),
              "event": "SessionStart", "matcher": "compact", "label": "压缩后提醒", "other": "压缩后 hook",
              "clash": "两段提醒会一起出现",
              "what": "每次压缩后放进模型上下文，{路径} 换成压缩前完整记录的位置"},
    "before": {"name": "save-my-tokens-precompact.py", "src": os.path.join(_HOOK_DIR, "precompact-instructions.py"),
               "event": "PreCompact", "matcher": None, "label": "压缩前要求", "other": "压缩前 hook",
               "clash": "两边打印的话都会交给写摘要的模型",
               "what": "每次压缩前交给写摘要的模型，附在 Claude Code 自带的摘要要求后面"},
}


def hook_paths(home, spec):
    cd = claude_dir(home)
    return os.path.join(cd, "settings.json"), os.path.join(cd, "hooks", spec["name"])


def hook_command(target):
    if is_windows():
        return '"%s" "%s"' % (sys.executable or "python", target)
    return "python3 " + shlex.quote(target)


def read_settings(path):
    """返回 (bom, 正文, 解析后的对象)。文件不存在时是空对象。"""
    if not os.path.isfile(path):
        return "", "", {}
    try:
        with open(path, "r", encoding="utf-8", newline="") as f:
            text = f.read()
    except UnicodeDecodeError:
        die("%s 不是 UTF-8 编码，脚本不改，请手动改。" % path)
    bom = chr(0xFEFF) if text.startswith(chr(0xFEFF)) else ""
    body = text[len(bom):]
    try:
        obj = json.loads(body) if body.strip() else {}
    except ValueError as e:
        die("%s 解析不了（%s），没有改。可能带注释，请手动改。" % (path, e))
    if not isinstance(obj, dict):
        die("%s 顶层不是对象，没有改。" % path)
    return bom, body, obj


def event_groups(obj, event):
    hooks = obj.get("hooks", {})
    if not isinstance(hooks, dict):
        die("settings.json 里的 hooks 不是对象，没有改。请手动看一下。")
    groups = hooks.get(event, [])
    if not isinstance(groups, list):
        die("settings.json 里的 hooks.%s 不是数组，没有改。请手动看一下。" % event)
    return hooks, groups


def is_ours(h, spec):
    return isinstance(h, dict) and spec["name"] in str(h.get("command", ""))


def hook_report(home, spec):
    settings, target = hook_paths(home, spec)
    _bom, _body, obj = read_settings(settings)
    _hooks, groups = event_groups(obj, spec["event"])
    ours = any(is_ours(h, spec) for g in groups if isinstance(g, dict) for h in g.get("hooks") or [])
    others = []
    for g in groups:
        # 压缩后只看 matcher 带 compact 的那几组；压缩前这个时机下的每一组都算
        if isinstance(g, dict) and (spec["matcher"] is None or spec["matcher"] in str(g.get("matcher", ""))):
            others += [str(h.get("command", "")) for h in g.get("hooks") or [] if isinstance(h, dict) and not is_ours(h, spec)]
    with open(spec["src"], encoding="utf-8") as f:
        shipped = f.read()
    installed = None
    if os.path.isfile(target):
        with open(target, encoding="utf-8", errors="replace") as f:
            installed = f.read()
    return {"settings": settings, "target": target, "registered": ours, "file": installed is not None,
            "current": installed == shipped, "others": others, "shipped": shipped,
            "disabled": obj.get("disableAllHooks") is True}


def hook_status(home, spec):
    r = hook_report(home, spec)
    label = spec["label"]
    if r["registered"] and r["file"]:
        print("%s：已装上%s。" % (label, "，和这个 skill 带的版本一致" if r["current"] else "，但文件和这个 skill 带的版本不一样（重新 install 会换成新版）"))
    elif r["registered"] or r["file"]:
        print("%s：只装了一半（%s）。重新 install 或 remove 都能收拾干净。"
              % (label, "settings.json 里登记了，文件不在" if r["registered"] else "文件在，settings.json 里没登记"))
    else:
        print("%s：没装。" % label)
    for c in r["others"]:
        print("已有别的%s：%s" % (spec["other"], clip(c, 120)))
    if r["disabled"]:
        print("注意：settings.json 里 disableAllHooks 是 true，所有 hook 现在都不跑。")
    print("装或卸之前先备份这两个路径：%s %s" % (show(r["settings"], home), show(r["target"], home)))
    print("\n%s原文（%s）：" % (label, spec["what"]))
    body = re.split(r'print\(f?"""', r["shipped"], maxsplit=1)[-1].rsplit('""")', 1)[0]
    print(body.replace("{p}", "{路径}"))


def cmd_hook(args, home):
    if args.action == "status":
        # 不指定 --which 时两个都列；装和卸一次只动一个，不指定就是压缩后提醒
        for i, w in enumerate([args.which] if args.which else ["after", "before"]):
            if i:
                print()
            hook_status(home, HOOK_SPECS[w])
        return
    spec = HOOK_SPECS[args.which or "after"]
    event = spec["event"]
    r = hook_report(home, spec)
    settings, target = r["settings"], r["target"]
    if not args.backup:
        die("install 和 remove 要给 --backup。先 backup --paths %s %s" % (show(settings, home), show(target, home)))
    m = load_manifest(home, args.backup)
    require_open(m)
    for p in (settings, target):
        full = resolve_target(p, m["roots"], home)
        if entry_for(m, full)[1] is None:
            die("%s 不在备份 %s 里。先 backup --paths %s %s" % (show(full, home), m["id"], show(settings, home), show(target, home)))
    _bom, body, obj = read_settings(settings)
    hooks, groups = event_groups(obj, event)
    if args.action == "install":
        new = copy.deepcopy(groups)
        if not r["registered"]:
            group = {"hooks": [{"type": "command", "command": hook_command(target), "timeout": 5}]}
            if spec["matcher"]:
                group = dict({"matcher": spec["matcher"]}, **group)
            new.append(group)
        edits = [(["hooks", event], new, False)] if new != groups else []
    else:
        new = []
        for g in groups:
            if isinstance(g, dict) and isinstance(g.get("hooks"), list) and any(is_ours(h, spec) for h in g["hooks"]):
                g = dict(g, hooks=[h for h in g["hooks"] if not is_ours(h, spec)])
                if not g["hooks"]:
                    continue
            new.append(g)
        if new == groups:
            edits = []
        elif new:
            edits = [(["hooks", event], new, False)]
        elif set(hooks) == {event}:
            edits = [(["hooks"], None, True)]
        else:
            edits = [(["hooks", event], None, True)]
    tmp = body
    for path, value, delete in edits:   # 先在内存里试改一遍：排版对不上会在这里停下，文件一个都没动
        tmp, _old = json_edit(tmp, path, value, delete)
    if args.action == "install":
        if not r["current"]:
            track_makedirs(m, os.path.dirname(target))
            atomic_write(target, r["shipped"], 0o755)
            m["ops"].append({"op": "write", "file": target})
            save_manifest(home, m)
            print("已写 %s" % show(target, home))
        if edits:
            apply_edits(home, m["id"], settings, edits,
                        summary="hooks.%s 加了一条%s" % (event, " " + spec["matcher"] if spec["matcher"] else ""))
        if r["current"] and not edits:
            print("已经装好，没有变化。")
        for c in r["others"]:
            print("注意：已有别的%s，%s：%s" % (spec["other"], spec["clash"], clip(c, 120)))
        if r["disabled"]:
            print("注意：settings.json 里 disableAllHooks 是 true，装上了也不会跑。")
    else:
        if edits:
            apply_edits(home, m["id"], settings, edits, summary="hooks.%s 去掉%s" % (event, spec["label"]))
        if os.path.isfile(target):
            os.remove(target)
            m = load_manifest(home, m["id"])
            m["ops"].append({"op": "remove", "file": target})
            save_manifest(home, m)
            print("已移走 %s（备份里有原样拷贝）" % show(target, home))
        if not edits and not r["file"]:
            print("本来就没装，没有变化。")
    print("新开的会话里生效。改完记得 seal。")


def describe(pre, cur):
    if pre == cur:
        return "没变"
    if pre["kind"] == "absent":
        return "新建"
    if cur["kind"] == "absent":
        return "已移走"
    return "已改"


def cmd_seal(args, home):
    m = load_manifest(home, args.backup)
    require_open(m)
    post, changed = [], 0
    print("备份 %s 封存，改动结果：" % m["id"])
    for e in m["entries"]:
        cur = fingerprint(e["path"])
        post.append(cur)
        d = describe(e["pre"], cur)
        changed += d != "没变"
        print("  - %s：%s" % (show(e["path"], home), d))
    m["sealed"] = {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "post": post}
    save_manifest(home, m)
    if not changed:
        print("没有任何改动。")
    print("改动在新开的会话里生效；已经开着的会话不会变。")
    if any(inside(e["path"], gemini_dir(home)) for e in m["entries"]):
        print("Antigravity 例外：规则和 skill（含排除名单）它每次请求前都重新读，开着的会话下一句话就生效（官方文档）；MCP 的改动以新开的会话为准。")
    print("回滚：python3 %s rollback --backup %s" % (os.path.abspath(__file__), m["id"]))


def set_aside(path, aside_dir, idx):
    """把现在占着位置的东西挪进备份目录，不删除。"""
    if not os.path.lexists(path):
        return
    dst = os.path.join(aside_dir, str(idx))
    os.makedirs(dst, mode=0o700, exist_ok=True)
    shutil.move(path, os.path.join(dst, os.path.basename(path)))


def restore_one(p, pre, src, aside, i):
    set_aside(p, aside, i)
    if pre["kind"] == "file":
        os.makedirs(os.path.dirname(p), exist_ok=True)
        shutil.copy2(os.path.join(src, "blob"), p)
        os.chmod(p, pre["mode"])
    elif pre["kind"] == "dir":
        os.makedirs(os.path.dirname(p), exist_ok=True)
        shutil.copytree(os.path.join(src, "tree"), p, symlinks=True)
        os.chmod(p, pre["mode"])
    elif pre["kind"] == "symlink":
        os.makedirs(os.path.dirname(p), exist_ok=True)
        os.symlink(pre["target"], p)


def cmd_rollback(args, home):
    manifests = all_manifests(home)
    if args.backup:
        m = load_manifest(home, args.backup)
    else:
        live = [x for x in manifests if not x.get("rolled_back")]
        if not live:
            die("没有可回滚的备份。")
        m = live[-1]
    if m.get("rolled_back"):
        die("备份 %s 已经回滚过（%s）。" % (m["id"], m["rolled_back"]))
    rhome = os.path.realpath(home)
    if m.get("home") != rhome:
        die("这个备份是在 %s 下建的，现在的 HOME 是 %s，不回滚。" % (m.get("home"), rhome))
    bdir = os.path.join(store_root(home), m["id"])
    # 回滚点之后有没有被别人动过
    drift = []
    if m.get("sealed"):
        for e, post in zip(m["entries"], m["sealed"]["post"]):
            cur = fingerprint(e["path"])
            if cur != post and cur != e["pre"]:
                drift.append(e["path"])
    if drift and not args.force:
        print("停：下面这些在这次改动之后又变过，直接还原会冲掉后来的改动：")
        for p in drift:
            print("  - " + show(p, home))
            i, e = entry_for(m, p)
            if e["pre"]["kind"] == "file" and p.endswith((".md", ".markdown", ".txt")) and os.path.isfile(p):
                old = read_text(os.path.join(bdir, "pre", str(i), "blob")).splitlines()
                diff = list(difflib.unified_diff(old, read_text(p).splitlines(), "备份时", "现在", lineterm="", n=1))
                print("    从备份时到现在的全部差异（我们的改动和之后别人的改动都在里面）：")
                for ln in diff[:40]:
                    print("    " + ln)
                if len(diff) > 40:
                    print("    …共 %d 行差异" % len(diff))
        print("配置文件（json / toml）可能含凭据，这里不显示内容。")
        print("先看看后来改了什么。确认要覆盖就加 --force（被替换下来的版本会存进备份目录，不会丢）。")
        sys.exit(3)
    if not m.get("sealed"):
        print("注意：这个备份没有封存（改到一半），无法判断文件之后有没有被别人动过，按原样还原。")
    aside = os.path.join(bdir, "displaced", time.strftime("%Y%m%d-%H%M%S"))
    restored = 0
    for i in reversed(range(len(m["entries"]))):
        e = m["entries"][i]
        p, pre = e["path"], e["pre"]
        if fingerprint(p) == pre:
            continue
        try:
            restore_one(p, pre, os.path.join(bdir, "pre", str(i)), aside, i)
        except PermissionError as err:
            die("还原 %s 时被拒绝（%s）。Windows 上多半是文件正被别的程序占用（Claude Code、Codex、编辑器）。"
                "已经还原到一半，被替换下来的版本在 %s，不会丢。关掉占用它的程序后再跑一次同样的 rollback 接着还原；"
                "如果它说文件「又变过」，那是这次还原到一半造成的，加 --force。"
                % (show(p, home), err, show(aside, home)), 5)
        restored += 1
    for d in sorted(m.get("created_dirs", []), key=len, reverse=True):
        try:
            for junk in IGNORE_NAMES:
                jp = os.path.join(d, junk)
                if os.path.isfile(jp) and os.listdir(d) == [junk]:
                    set_aside(jp, aside, "dirs")
            os.rmdir(d)  # 只删这次自己建的空目录
        except OSError:
            pass
    bad = [e["path"] for e in m["entries"] if fingerprint(e["path"]) != e["pre"]]
    m["rolled_back"] = time.strftime("%Y-%m-%d %H:%M:%S")
    m["rollback_verified"] = not bad
    save_manifest(home, m)
    if bad:
        print("回滚后校验没过，下面这些和备份时不一致：")
        for p in bad:
            print("  - " + show(p, home))
        sys.exit(4)
    print("已回滚备份 %s：还原 %d 项，%d 项本来就没变。逐项校验 sha256 一致。" % (m["id"], restored, len(m["entries"]) - restored))
    if os.path.isdir(aside):
        print("被替换下来的版本存在：%s" % show(aside, home))


def cmd_list(args, home):
    ms = all_manifests(home)
    if not ms:
        print("还没有备份。")
        return
    for m in ms:
        print("%s [%s] %s  %s" % (m["id"], backup_state(m), m["created"], m.get("note") or ""))
        for e in m["entries"]:
            print("    %s" % show(e["path"], home))
        for op in m.get("ops", []):
            if op["op"] == "set":
                print("    · set %s %s：%s → %s" % (show(op["file"], home), json.dumps(op["path"], ensure_ascii=False), op["old"], op["new"]))
            elif op["op"] in ("write", "remove"):
                print("    · %s %s" % ({"write": "写入", "remove": "移走"}[op["op"]], show(op["file"], home)))
            else:
                print("    · move %s → %s" % (show(op["src"], home), show(op["dst"], home)))


def cmd_status(args, home):
    ev, err = load_json_file(args.scan, config=False)
    if not isinstance(ev, dict) or "files" not in ev:
        die("读不了 scan 的 JSON（%s）。先跑 scan --json 文件。" % err)
    covered = []
    for m in all_manifests(home):
        if not m.get("rolled_back"):
            covered += [e["path"] for e in m["entries"]]
    changed = 0
    for p, h in sorted(ev["files"].items()):
        cur = sha256_file(p) if os.path.isfile(p) else None
        if cur == h:
            continue
        changed += 1
        rp = os.path.join(os.path.realpath(os.path.dirname(p)), os.path.basename(p))
        ok = any(inside(rp, c) or inside(os.path.realpath(p), c) for c in covered)
        print("  %s %s（%s）" % ("✓" if ok else "✗", show(p, home), ("已不在原位" if cur is None else "内容变了") + ("，有备份" if ok else "，没有备份覆盖！")))
    if not changed:
        print("自上次扫描以来，扫描过的配置和规则文件都没变。")


def cmd_compare(args, home):
    """改之前和改之后各一份 scan 的 json，对比新开会话第一次请求的实测用量。只读。"""
    evs = []
    for p in (args.before, args.after):
        ev, err = load_json_file(p, config=False)
        if not isinstance(ev, dict) or "claude" not in ev:
            die("读不了 scan 的 JSON（%s：%s）。" % (p, err))
        evs.append(ev)
    agy = getattr(args, "agent", "claude") == "agy"
    who = "Antigravity" if agy else "Claude Code"
    sb, sa = [(e.get("antigravity" if agy else "claude") or {}).get("startup") for e in evs]
    if not sb or not sa:
        die("%s那份扫描里没有新开会话的记录，比不了。新开一个会话说一句话，再 scan --json 一次。" % ("改之前" if not sb else "改之后"))
    a = sa["latest"]
    b = sb["latest"]
    if a["cwd"] != b["cwd"]:
        row = [r for r in sb.get("by_cwd") or [] if r["cwd"] == a["cwd"]]
        if row:
            b = {"ts": row[0]["latest_ts"], "cwd": a["cwd"], "tokens": row[0]["latest"], "parts": row[0]["latest_parts"], "model": None}
    if a["ts"] <= b["ts"]:
        die("改之后那份扫描里，最近一次新开会话还是改之前的那一次（%s）。改动只在新开的会话里生效：新开一个会话说一句话，再 scan --json 一次。" % md(a["ts"]))
    L = ["前后对比：新开一个会话，第一次请求带了多少（%s 自己记在日志里的用量，不是估的）" % who, ""]
    L.append("  改之前  %s token   （%s，%s%s）" % (num(b["tokens"]).rjust(9), md(b["ts"]), show(b["cwd"], home), "，" + b["model"] if b.get("model") else ""))
    L.append("  改之后  %s token   （%s，%s%s）" % (num(a["tokens"]).rjust(9), md(a["ts"]), show(a["cwd"], home), "，" + a["model"] if a.get("model") else ""))
    d = b["tokens"] - a["tokens"]
    if d > 0:
        L.append("  少了    %s token   （现在是原来的 %.0f%%）" % (num(d).rjust(9), 100.0 * a["tokens"] / b["tokens"]))
    elif d < 0:
        L.append("  多了    %s token" % num(-d).rjust(9))
    else:
        L.append("  没变")
    if a["cwd"] != b["cwd"]:
        L.append("  注意：两次不在同一个目录，项目级的规则和 skill 不一样，数字只能粗看。在同一个目录新开会话再比才准。")
    if a.get("model") and b.get("model") and a["model"] != b["model"]:
        L.append("  注意：两次用的模型不一样，同样的内容折出来的 token 数会有出入。")
    pb, pa = b.get("parts") or {}, a.get("parts") or {}
    lack = [n for n, x, pp in (("改之前", b, pb), ("改之后", a, pa)) if not sum(pp.values()) or x.get("partial")]
    if lack:
        L.append("")
        L.append("各部分的大小：%s那次会话读不出完整的明细，分项没法比（不是变成了 0）。上面的 token 数取自日志，不受影响。" % "和".join(lack))
        L.append("")
        L.append("这是各一次新开会话的实测。会话越往后上下文越长，这个数只说明开局。")
        print("\n".join(L))
        return
    L.append("")
    L.append("各部分的大小（字符数）：")
    L.append("  %s  %s  %s" % ("改之前".rjust(8), "改之后".rjust(8), ""))
    for key, name in (AGY_PART_NAMES if agy else PART_NAMES):
        x, y = pb.get(key, 0), pa.get(key, 0)
        if not x and not y:
            continue
        extra = ""
        if key == "skills" and b.get("skill_count") is not None and a.get("skill_count") is not None:
            extra = "（%d 个 → %d 个）" % (b["skill_count"], a["skill_count"])
        elif key == "rules" and b.get("files") is not None and a.get("files") is not None and len(b["files"]) != len(a["files"]):
            extra = "（%d 个文件 → %d 个文件）" % (len(b["files"]), len(a["files"]))
        L.append("  %s  %s  %s%s%s" % (num(x).rjust(10), num(y).rjust(10), name, extra, "" if x != y else "  没变"))
    L.append("")
    L.append("这是各一次新开会话的实测。会话越往后上下文越长，这个数只说明开局。")
    print("\n".join(L))


SELFTEST_FILES = {
    # LF、CRLF 各一份带中文的 settings.json；CRLF 的 config.toml；CRLF 的规则文件；一个 skill 目录
    ".claude/settings.json": '{\n  "env": {\n    "说明": "中文内容 ⚠ → 自检"\n  },\n  "skillOverrides": {\n    "部署": "on"\n  }\n}\n',
    ".claude/settings.local.json": '{\r\n  "env": {\r\n    "说明": "中文内容，CRLF 换行"\r\n  },\r\n  "skillOverrides": {\r\n    "部署": "on"\r\n  }\r\n}\r\n',
    ".codex/config.toml": '# 中文注释\r\nmodel = "gpt"\r\n\r\n[mcp_servers.demo]\r\ncommand = "npx"\r\nnote = "演示"\r\nenabled = true\r\n',
    ".claude/CLAUDE.md": "# 规则\r\n\r\n- 用中文回答\r\n",
    ".claude/skills/演示/SKILL.md": "---\nname: 演示\ndescription: 自检用\n---\n正文\n",
}


def selftest(out=None):
    """在系统临时目录里造一个假 HOME，用本脚本自己的 backup → set → seal → rollback 走一遍，
    校验回滚后每个文件的 sha256 和改前一样。逐步打印，返回是否全部通过。不碰真实 HOME。"""
    import contextlib
    import io
    import tempfile
    out = out or sys.stdout
    saved = dict(CONF)
    CONF.update(claude=None, codex=None)
    results = []

    def step(name, ok, detail=""):
        results.append(bool(ok))
        print("  %s  %s%s" % ("通过" if ok else "失败", name, "：" + detail if detail and not ok else ""), file=out)
        return ok

    def call(fn, home, **kw):
        o, e = io.StringIO(), io.StringIO()
        code = 0
        with contextlib.redirect_stdout(o), contextlib.redirect_stderr(e):
            try:
                fn(argparse.Namespace(**kw), home)
            except SystemExit as x:
                code = x.code if isinstance(x.code, int) else 1
        return code, (o.getvalue() + e.getvalue()).strip()

    def raw(p):
        with open(p, "rb") as f:
            return f.read().decode("utf-8")

    def one_line_changed(a, b, nl):
        la, lb = a.split(nl), b.split(nl)
        if nl == "\r\n" and any("\n" in x or "\r" in x for x in lb):
            return False
        if nl == "\n" and "\r" in b:
            return False
        return len(la) == len(lb) and sum(x != y for x, y in zip(la, lb)) == 1

    print("自检：在临时目录里造假 HOME，走一遍 backup → set → seal → rollback（Python %s，%s）" % (
        sys.version.split()[0], "Windows" if is_windows() else os.name), file=out)
    try:
        tmp = tempfile.mkdtemp(prefix="save-my-tokens-selftest-")
    except OSError as e:
        CONF.update(saved)
        step("在系统临时目录里建目录", False, str(e))
        print("自检没通过。", file=out)
        return False
    try:
        home = os.path.join(tmp, "home")
        for rel, text in SELFTEST_FILES.items():
            p = os.path.join(home, *rel.split("/"))
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as f:
                f.write(text.encode("utf-8"))
        home = os.path.realpath(home)
        P = lambda rel: os.path.join(home, *rel.split("/"))
        before = {rel: sha256_file(P(rel)) for rel in SELFTEST_FILES}
        skill_dir = P(".claude/skills/演示")
        skill_fp = fingerprint(skill_dir)
        targets = [P(".claude/settings.json"), P(".claude/settings.local.json"), P(".codex/config.toml"),
                   P(".claude/CLAUDE.md"), skill_dir]
        code, msg = call(cmd_backup, home, paths=targets, root=None, note="selftest")
        ms = all_manifests(home)
        if not step("backup 建好备份", code == 0 and len(ms) == 1, msg):
            return False
        bid = ms[0]["id"]
        for rel, nl in ((".claude/settings.json", "\n"), (".claude/settings.local.json", "\r\n")):
            pre = raw(P(rel))
            code, msg = call(cmd_set, home, backup=bid, file=P(rel), path='["skillOverrides","部署"]', value='"off"', delete=False)
            post = raw(P(rel)) if code == 0 else pre
            ok = code == 0 and json.loads(post)["skillOverrides"]["部署"] == "off" and one_line_changed(pre, post, nl)
            step("set 改 %s（%s 换行）：只变目标键那一行，换行风格不变" % (rel, "CRLF" if nl == "\r\n" else "LF"), ok, msg or "其余字节变了")
        if tomllib:
            rel = ".codex/config.toml"
            pre = raw(P(rel))
            code, msg = call(cmd_set, home, backup=bid, file=P(rel), path='["mcp_servers","demo","enabled"]', value="false", delete=False)
            post = raw(P(rel)) if code == 0 else pre
            ok = code == 0 and tomllib.loads(post)["mcp_servers"]["demo"]["enabled"] is False and one_line_changed(pre, post, "\r\n")
            step("set 改 %s（CRLF 换行）：只变目标键那一行，换行风格不变" % rel, ok, msg or "其余字节变了")
        else:
            print("  跳过  set 改 config.toml：这个 Python 没有 tomllib，TOML 修改本来就会拒绝", file=out)
        with open(P(".claude/CLAUDE.md"), "ab") as f:
            f.write("- 自检加的一行\r\n".encode("utf-8"))
        with open(os.path.join(skill_dir, "SKILL.md"), "ab") as f:
            f.write("自检加的一行\n".encode("utf-8"))
        code, msg = call(cmd_seal, home, backup=bid)
        step("seal 封存", code == 0, msg)
        changed = [rel for rel in SELFTEST_FILES if sha256_file(P(rel)) != before[rel]]
        step("改动确实落到了文件上", len(changed) == len(SELFTEST_FILES) - (0 if tomllib else 1), "只变了 %s" % changed)
        code, msg = call(cmd_rollback, home, backup=bid, force=False)
        step("rollback 回滚", code == 0, msg)
        bad = [rel for rel in SELFTEST_FILES if not os.path.isfile(P(rel)) or sha256_file(P(rel)) != before[rel]]
        step("回滚后每个文件的 sha256 和改前一致", not bad, "不一致：%s" % bad)
        step("回滚后 skill 目录和改前一致", fingerprint(skill_dir) == skill_fp)
        left = [os.path.join(dp, f) for dp, _d, fn in os.walk(home) for f in fn if f.endswith(".save-my-tokens-tmp")]
        step("没有留下半截的临时文件", not left, "%s" % left)
    except Exception as e:  # 自检本身出意外也算没通过，不往外抛
        step("自检过程", False, "%s: %s" % (type(e).__name__, e))
    finally:
        CONF.update(saved)
        shutil.rmtree(tmp, ignore_errors=True)
        step("清理临时目录", not os.path.exists(tmp), tmp)
    ok = bool(results) and all(results)
    print("自检%s。" % ("全部通过" if ok else "没通过"), file=out)
    return ok


def resolve_home(args):
    """返回 HOME。没显式给 --home 时，按 CLAUDE_CONFIG_DIR / CODEX_HOME 定配置目录。"""
    if args.home:
        return args.home
    home = os.environ.get("HOME")
    if is_windows():
        # 官方文档：Windows 上 ~/.claude 指 %USERPROFILE%\.claude
        up = os.environ.get("USERPROFILE")
        if up:
            if home and os.path.normcase(os.path.abspath(home)) != os.path.normcase(os.path.abspath(up)):
                print("注意：HOME（%s）和 USERPROFILE（%s）不一样，按 USERPROFILE 算；不对就用 --home 指定。" % (home, up), file=sys.stderr)
            home = up
    for key, var in (("claude", "CLAUDE_CONFIG_DIR"), ("codex", "CODEX_HOME")):
        v = os.environ.get(var)
        if not v:
            continue
        if not os.path.isabs(v):
            die("环境变量 %s=%r 不是绝对路径，判断不了它实际指哪个目录。改成绝对路径，或用 --home 指定。" % (var, v))
        CONF[key] = os.path.abspath(v)
        print("注意：按环境变量 %s 读写配置目录 %s。" % (var, CONF[key]), file=sys.stderr)
    if CONF["claude"]:
        print("注意：设了 CLAUDE_CONFIG_DIR 后 .claude.json 放在哪，官方文档没写清，这次不读它（skillUsage 和用户级 MCP 不核对）。", file=sys.stderr)
    elif home:
        s, _ = load_json_file(os.path.join(home, ".claude", "settings.json"))
        if isinstance(s, dict) and isinstance(s.get("env"), dict) and s["env"].get("CLAUDE_CONFIG_DIR"):
            print("注意：~/.claude/settings.json 的 env 里设了 CLAUDE_CONFIG_DIR，但当前环境变量里没有；"
                  "Claude Code 实际用的配置目录可能不是 ~/.claude，这次仍按 ~/.claude 算。", file=sys.stderr)
    return home


def main():
    utf8_console()
    ap = argparse.ArgumentParser(prog="slim.py", description="coding agent 配置体检：取证、备份、回滚。")
    ap.add_argument("--home", help="把哪个目录当 HOME（默认用环境变量 HOME）")
    sub = ap.add_subparsers(dest="cmd")
    s = sub.add_parser("scan", help="只读扫描")
    s.add_argument("--days", type=int, default=30)
    s.add_argument("--project", action="append", help="额外要查的项目目录，可重复")
    s.add_argument("--max-projects", type=int, default=8, help="按近期会话数自动取前几个项目")
    s.add_argument("--json", help="把完整证据写到这个文件")
    s.add_argument("--now", help="把哪个时刻当作现在（ISO 格式，测试用）")
    s.add_argument("--cc-version", help="Claude Code 版本（默认从日志里取）")
    s.add_argument("--all", action="store_true", help="列表不截断")
    b = sub.add_parser("backup", help="改之前先备份")
    b.add_argument("--paths", nargs="+", required=True)
    b.add_argument("--root", action="append", help="HOME 之外允许动的项目目录，可重复")
    b.add_argument("--note")
    t = sub.add_parser("set", help="改 JSON / TOML 的一个键")
    t.add_argument("--backup", required=True)
    t.add_argument("--file", required=True)
    t.add_argument("--path", help="JSON 数组")
    t.add_argument("--value", help="JSON 值")
    t.add_argument("--delete", action="store_true")
    t.add_argument("--many", help="一次改很多个键：一个 JSON 文件，内容是 [{\"path\": [...], \"value\": ...}, ...]")
    sk = sub.add_parser("skills", help="一次改很多个 skill 的状态（只写 skillOverrides，skill 文件不动）")
    sk.add_argument("--backup", required=True)
    sk.add_argument("--state", required=True, help="off 关掉 / manual 只能手动调 / name 只留名字 / on 保留")
    sk.add_argument("names", nargs="*", help="skill 名字")
    sk.add_argument("--scan", help="scan --json 写出的文件，配合 --group 用")
    sk.add_argument("--group", help="整组一起改：A、B、C、D")
    sk.add_argument("--exclude", nargs="*", help="组里要跳过的 skill")
    sk.add_argument("--agent", choices=["claude", "agy"], default="claude",
                    help="改哪个 agent 的：claude（默认，写 skillOverrides）；agy 是 Antigravity（写 ~/.gemini/config/skills.json 的 exclude，只有 off / on）")
    sh = sub.add_parser("show", help="从 scan 的 json 里取一组 skill 的完整名单")
    sh.add_argument("--scan", required=True)
    sh.add_argument("--group", required=True)
    sh.add_argument("--names", action="store_true", help="只打印名字")
    sh.add_argument("--agent", choices=["claude", "agy"], default="claude", help="看哪个 agent 的分组，agy 是 Antigravity")
    tl = sub.add_parser("tools", help="从 scan 的 json 里取逐个工具的编号表")
    tl.add_argument("--scan", required=True)
    tl.add_argument("--server", nargs="*", help="只看这几个 MCP server 的工具；内置工具写 builtin")
    tl.add_argument("--loaded", action="store_true", help="只看常驻的")
    tl.add_argument("--entry", help="看另一个入口的会话的清单（报告里列了有哪些）")
    dn = sub.add_parser("deny", help="屏蔽工具（只写 settings.json 的 permissions.deny）")
    dn.add_argument("--backup", required=True)
    dn.add_argument("names", nargs="*", help="完整的工具名")
    dn.add_argument("--scan", help="scan --json 写出的文件：按它的工具清单核对名字，配合 --nums 用")
    dn.add_argument("--nums", nargs="*", help="slim tools 表里的编号，如 3 5-8")
    dn.add_argument("--entry", help="编号取自哪个入口的表（和 slim tools 用的一致）")
    dn.add_argument("--server", nargs="*", help="整个 MCP server 一起屏蔽")
    dn.add_argument("--remove", action="store_true", help="从 permissions.deny 里拿掉（恢复）")
    mv = sub.add_parser("move", help="搬文件或目录")
    mv.add_argument("--backup", required=True)
    mv.add_argument("--src", required=True)
    mv.add_argument("--dst", required=True)
    se = sub.add_parser("seal", help="改完后封存")
    se.add_argument("--backup", required=True)
    rb = sub.add_parser("rollback", help="还原")
    rb.add_argument("--backup", help="不给就回滚最近一个还没回滚的")
    rb.add_argument("--force", action="store_true")
    sub.add_parser("list", help="列出备份")
    stt = sub.add_parser("status", help="对比上次 scan")
    stt.add_argument("--scan", required=True)
    cp = sub.add_parser("compare", help="两份 scan 的 json 对比开局用量")
    cp.add_argument("--before", required=True)
    cp.add_argument("--after", required=True)
    cp.add_argument("--agent", choices=["claude", "agy"], default="claude", help="比哪个 agent 的开局，agy 是 Antigravity")
    hk = sub.add_parser("hook", help="压缩前后的两个 hook：status 查看 / install 装上 / remove 卸掉")
    hk.add_argument("action", choices=["status", "install", "remove"])
    hk.add_argument("--which", choices=["after", "before"],
                    help="after 是压缩后提醒，before 是压缩前要求。status 不给就两个都列，install 和 remove 不给就是 after")
    hk.add_argument("--backup", help="install 和 remove 要给")
    sub.add_parser("selftest", help="在临时目录里自检 backup → set → seal → rollback，不碰真实配置")
    args = ap.parse_args()
    if args.cmd == "selftest":
        sys.exit(0 if selftest() else 1)
    if is_windows() and args.cmd == "move":
        die("Windows 上不支持 move：目录联接（junction）和软链在 Windows 上搬动、回滚的行为没有验证过，"
            "可能搬走或还原错东西。需要搬的请手动操作，或只用 scan 看报告。")
    home = resolve_home(args)
    if not home or not os.path.isdir(home):
        die("HOME 无效：%r" % home)
    home = os.path.abspath(home)
    if is_windows() and args.cmd == "backup":
        print("Windows：备份前先在这台机器上自检一遍。", file=sys.stderr)
        if not selftest(out=sys.stderr):
            die("自检没通过，这台机器上 backup / set / rollback 不安全，已拒绝。只用 scan 看报告，改动请手动做。")
    fn = {"scan": do_scan, "backup": cmd_backup, "set": cmd_set, "move": cmd_move, "seal": cmd_seal,
          "rollback": cmd_rollback, "list": cmd_list, "status": cmd_status,
          "skills": cmd_skills, "show": cmd_show, "compare": cmd_compare, "hook": cmd_hook,
          "tools": cmd_tools, "deny": cmd_deny}.get(args.cmd)
    if not fn:
        ap.print_help()
        sys.exit(1)
    fn(args, home)


if __name__ == "__main__":
    main()
