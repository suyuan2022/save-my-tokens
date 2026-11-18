# save-my-tokens

给 Claude Code 和 Codex 的配置做体检的 skill。它按你近 30 天的实际用法，和你逐项商量：哪些 skill 和 MCP 可以停、哪些规则写了两遍、哪些开关写错了。改之前备份，一条命令退回原样。

## 安装

Claude Code：

```
git clone https://github.com/suyuan2022/save-my-tokens ~/.claude/skills/save-my-tokens
```

新开一个 Claude Code 会话，输入 `/save-my-tokens`。它只能手动触发，平时不占上下文。

想先看看它会报什么，可以只跑扫描。扫描只读，不改任何文件，不花模型额度：

```
python3 ~/.claude/skills/save-my-tokens/scripts/slim.py scan
```

卸载：删掉 `~/.claude/skills/save-my-tokens` 这个目录。

## 它做什么

一个只用 Python 标准库的脚本负责取证：

- 每个 skill、MCP server、subagent 近 30 天被调用了多少次。读的是本机的会话日志，Claude Code 和 Codex 都读，包括 Codex 压缩过的旧日志。
- 一个 skill 在 Claude Code 里没用过，但 Codex 在读它，会如实标出来。
- 规则文件之间的重复，按加载关系分成两种：同一个会话里会一起加载的（每次请求多带一遍），和 Claude Code、Codex 各读一份的（不多花，但两份可能走样）。
- 写错或不生效的开关：类型不对、被环境变量盖掉、超出范围、版本不支持。
- 官方的 `/doctor prompt-audit` 现在能不能用，不能用是卡在哪，它背后那份官方说明文件在本机哪里。

一份 SKILL.md 负责让 agent 拿着这些证据跟你商量，你同意的才改。

旧模型时代的写法、指向不存在文件的规则、互相矛盾的规则，用 Claude Code 官方的 `/doctor prompt-audit` 来查，这里不另写一套。你关掉了它依赖的内置 skill 也没关系：agent 会直接读它背后那份公开的官方说明文件照着做，不动你的开关。

## 它不做什么

- 不估算「省了多少 token」。它报的是能核对的事实：模型能看到几个 skill、描述一共多少字符、调用了几次。
- 不替你决定。「近 30 天 0 次调用」只是候选；发版、回滚这类几个月才用一次的 skill 会被单独标出来。
- 不往你的配置里加东西：不装 hook，不加规则，不留后台进程。
- 不改 `~/.claude.json`（Claude Code 自己随时在写的状态文件）、凭据文件、插件目录。
- 不硬删任何东西。

## 备份和回滚怎么保证

- 改之前，要动的每个路径原样存进 `~/.save-my-tokens/backups/<时间戳>/`，每次一个新目录，不覆盖旧的。目录权限 0700，因为里面可能有凭据。
- 改 `settings.json`、`config.toml` 通过脚本一次改一个键，改完重新解析，和改前逐项比对，只有目标键变了才写回。agent 不需要打开这两个文件的全文。
- 回滚后逐项校验 sha256。如果文件在改完之后又被别人动过，回滚会停下来问，不会直接盖掉后来的改动。
- 回滚时被替换下来的版本也存一份。

退回最近一次改动：

```
python3 ~/.claude/skills/save-my-tokens/scripts/slim.py rollback
```

## 运行要求

- Python 3.9 以上，不需要装任何包。macOS 自带的 `python3` 就够跑扫描和改 `settings.json`。
- 用脚本改 TOML（Codex 的 `config.toml`）需要 Python 3.11 以上。
- 读 Codex 压缩的旧日志（`.jsonl.zst`）需要 Python 3.14 以上，或系统里有 `zstd` 命令；都没有时报告会写明有多少个文件没读到。

## 已知的限制

- 只在 macOS 上跑过。
- Codex 的 skill 使用次数是从「工具调用里读了某个 SKILL.md」推断的，不是官方计数。
- 意思相同、措辞不同的重复规则，脚本找不到，靠 agent 读文件判断。
- 开关清单只收了对着官方文档核过的二十几个键，键名和默认值会随版本变，每条都带出处和核对日期。
- 同名的 skill 在用户级和项目级各装一份时，日志分不出用的是哪份。

## 目录

```
SKILL.md                  给 agent 看的流程
scripts/slim.py           扫描、备份、改单个键、回滚
references/switches.json  开关清单：默认值、说明、官方出处、核对日期
```

## 许可

MIT，见 `LICENSE`。
