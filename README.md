# save-my-tokens

Claude Code 每开一个新会话，第一次请求就要带上内置工具说明、系统提示、skill 清单、规则文件（`CLAUDE.md` / `AGENTS.md`）和 MCP 工具说明。装的东西多了，一句「你好」就是几万 token，而且每个会话都要付一遍。

save-my-tokens 是给 Claude Code 和 Codex 用的配置体检 skill。本机脚本先量出这几万 token 由哪几块组成、装着的东西近 30 天各用了几次；agent 再拿着这份报告和你逐项定去留。你同意的才改，改前备份，一条命令回滚。

## 快速开始

安装到 Claude Code：

```bash
git clone https://github.com/suyuan2022/save-my-tokens ~/.claude/skills/save-my-tokens
```

新开一个 Claude Code 会话，输入 `/save-my-tokens` 即可开始。该 skill 只能手动触发，平时不占上下文。

如果只想先看扫描报告，可以直接跑只读扫描（本机运行，不改任何文件，不调模型、不花模型额度）：

```bash
python3 ~/.claude/skills/save-my-tokens/scripts/slim.py scan
```

退回最近一次改动：

```bash
python3 ~/.claude/skills/save-my-tokens/scripts/slim.py rollback
```

卸载：删除 `~/.claude/skills/save-my-tokens` 目录即可。

## 它怎么工作

整个流程分两步：本机脚本取证，再由 agent 拿着报告和你逐项确认。

### 1. 本机脚本取证

脚本只用 Python 标准库，在本机运行、不调用模型，读取会话日志和配置文件并输出报告：

- **开局 token 构成**：从 Claude Code 会话日志里读取新开会话第一次请求实际带了多少 token，以及系统提示、内置工具说明、skill 清单、规则文件、MCP 工具说明各占多少（实测记录，非估算）。
- **近 30 天使用统计**：统计每个 skill、MCP server、subagent 近 30 天的调用次数。Claude Code 和 Codex 的本机会话日志都读，包括 Codex 压缩过的旧日志（`.jsonl.zst`）。如果某个 skill 在 Claude Code 里没用过但 Codex 在读它，会如实标出。
- **规则文件与配置检查**：
  - 找出规则文件之间的重复，按加载关系分为两种：同一会话里会一起加载的（每次请求多带一遍），和 Claude Code、Codex 各读一份的（不多花钱，但两份可能走样）。
  - 检查超过上限、Codex 读不到的超长 `AGENTS.md`。
  - 检查写错或不生效的开关：类型不对、被环境变量覆盖、超出范围、版本不支持。
- **会话习惯与子代理模型**：统计会话拖到过多长、缓存过期后整段重算了几次、派出的子代理用的是哪个模型，为「自动压缩窗口设多少」这类设置提供依据。
- **官方审查可用性**：检查 Claude Code 官方的 `/doctor prompt-audit` 当前能不能用、不能用卡在哪，以及它背后那份官方说明文件在本机的位置。

### 2. 与 agent 逐项商量

`SKILL.md` 负责让 agent 拿着扫描证据和你一项项核对，你同意的才改：

- **不替你做决定**。「近 30 天 0 次调用」只是候选；发版、回滚这类几个月才用一次的 skill 会被单独标出。
- **不重造官方审查**。旧模型时代的写法、指向不存在文件的规则、互相矛盾的规则，交给 Claude Code 官方的 `/doctor prompt-audit` 来查。即使你关掉了它依赖的内置 skill，agent 也会直接读它背后那份公开的官方说明文件照着做，不动你的开关。
- **不估算「省了多少 token」**。它只报量得出来的数：第一次请求实际用了多少 token、模型能看到几个 skill、调用了几次。改完后新开一个会话，可以再量一次对比。

### 一次实测

作者在一个构造的配置（318 个 skill、大规则文件）上，用真实 Claude Code 2.1.321 测过一遍：第一次请求从 85,854 token 降到清理后的 20,383 token，回滚后回到 85,854 token。这是构造配置上的结果，不代表其他用户实际能省多少。

## 安全保证

- **改前完整备份**：改动前，要动的每个路径原样存入 `~/.save-my-tokens/backups/<时间戳>/`，每次新建目录，不覆盖旧备份。目录权限设为 `0700`（里面可能含凭据）。
- **按键精准修改**：改 `settings.json`、`config.toml` 时通过脚本按键修改（单个键，或一批键一次写回）；改完重新解析并与改前逐项比对，确认只有目标键变了才写回。agent 不需要打开这两个文件的全文。
- **sha256 校验回滚**：回滚后逐项校验 sha256。如果文件在改完之后又被别人动过，回滚会停下来问，不会直接覆盖后来的改动；回滚时被替换下来的版本也会另存一份。
- **不碰的东西**：
  - 不改 `~/.claude.json`（Claude Code 随时在写的状态文件）、凭据文件、插件目录。
  - 不硬删任何东西。
  - 不装 hook，不留后台进程。需要往规则文件里加一句话时（例如子代理的模型分工），先给你看改动，你同意才加。

## 运行要求

- Python 3.9 以上，不需要安装任何第三方包。macOS 自带的 `python3` 就够跑扫描和改 `settings.json`。
- 用脚本改 TOML（Codex 的 `config.toml`）需要 Python 3.11 以上。
- 读 Codex 压缩过的旧日志（`.jsonl.zst`）需要 Python 3.14 以上，或系统里有 `zstd` 命令；两者都没有时，报告会写明有多少个文件没读到。

## Windows 说明

脚本还没有在真实的 Windows 上跑过，因此采取「拿不准就不改」的策略：

- 扫描为只读操作，可以照常用。命令里的 `python3` 换成 `python` 或 `py -3`，路径换成 `%USERPROFILE%\.claude\skills\save-my-tokens`。
- 每次备份前，脚本会先在系统临时目录里造一份假配置，走一遍备份、修改、回滚，核对回滚后每个文件都与改前一致；没通过就拒绝改动，只给报告。想提前检查可以运行 `python scripts\slim.py selftest`，不会碰你的真实配置。
- 搬目录（`move`）在 Windows 上关闭；要备份的路径是软链或目录联接时也会拒绝。
- 带 BOM、CRLF 换行的配置文件改完保持原样；换行混用或非 UTF-8 的文件不改。
- 配置目录通过 `CLAUDE_CONFIG_DIR`、`CODEX_HOME` 改过位置的，脚本会跟着读。
- 在 Windows 上跑出问题欢迎提 issue，附上 `selftest` 的输出。

## 已知限制

- 只在 macOS 上跑过；Windows 的处理方式见上一节。
- 开局的实测只有 Claude Code 有，Codex 没有。各部分大小的明细依赖较新版本 Claude Code 的日志（在 2.1.321、2.1.326 上核过），旧版本只给得出总数。
- Codex 的 skill 使用次数是从「工具调用里读了某个 `SKILL.md`」推断的，不是官方计数。
- 意思相同、措辞不同的重复规则，脚本找不到，要靠 agent 读文件判断。
- 开关清单只收了对着官方文档核对过的二十几个键；键名和默认值会随版本变化，每条都附有出处和核对日期。
- 同名 skill 在用户级和项目级各装一份时，日志分不出实际用的是哪份。

## 目录

```text
SKILL.md                  给 agent 看的流程
scripts/slim.py           扫描、备份、改单个键、回滚
references/switches.json  开关清单：默认值、说明、官方出处、核对日期
references/windows.md     在 Windows 上跑的注意事项
```

## 许可

MIT，见 `LICENSE`。
