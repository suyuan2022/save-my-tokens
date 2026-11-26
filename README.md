# save-my-tokens

Claude Code 每次开新会话，第一次请求都要带上内置工具说明、系统提示、skill 清单、规则文件（`CLAUDE.md` / `AGENTS.md`）和 MCP 工具说明。装得多了，一句「你好」就是几万 token，每开一个新会话都要重新带上。

save-my-tokens 是给 Claude Code、Codex 和 Antigravity（Google 的 Gemini 编程 agent，命令行叫 `agy`）用的 skill。先跑本机脚本，量出这几万 token 怎么来的、装着的东西近 30 天用了几次；再由 agent 拿着报告逐项和你定去留，同意才改。

## 快速开始

安装到 Claude Code：

```bash
git clone https://github.com/suyuan2022/save-my-tokens ~/.claude/skills/save-my-tokens
```

新开会话输入 `/save-my-tokens`（只能手动触发，平时不占上下文）。一次扫描会把这台机器上的 Claude Code、Codex、Antigravity 都查到，不用分别装。只用 Antigravity 的话，clone 到 `~/.gemini/config/skills/save-my-tokens`，在 Antigravity 里输入 `/save-my-tokens`。只想看报告或回滚，直接跑脚本：

```bash
# 只读扫描（本机运行，不调模型）
python3 ~/.claude/skills/save-my-tokens/scripts/slim.py scan

# 退回最近一次改动
python3 ~/.claude/skills/save-my-tokens/scripts/slim.py rollback
```

卸载直接删 `~/.claude/skills/save-my-tokens`。装过压缩前要求或压缩后提醒的，先照下面「压缩前要求和压缩后提醒」一节把它们卸掉：它们装在 skill 目录外面，删 skill 不会带走。

## 怎么工作

### 1. 本机脚本扫描

- **开局 token**：读 Claude Code 日志，看第一次请求实际带了多少 token 以及这五块各多大（实测，不是估算）。
- **近 30 天用量**：读 Claude Code 和 Codex 日志（含 `.jsonl.zst` 压缩旧日志），统计 skill、MCP server、subagent 调用次数；Claude Code 没用过但 Codex 在读的 skill 会标出。
- **规则与开关**：找规则文件重复（同会话一起加载、每次多带一遍，或 Claude Code 和 Codex 各读一份、不多花钱但可能走样），查超过上限 Codex 读不到的 `AGENTS.md`，以及写错或不生效的开关（类型不对、被环境变量覆盖、超范围、版本不支持）。
- **逐个工具**：新开会话时发给模型的每个工具（内置的、你装的 MCP、桌面 app 自带的），说明是整份常驻还是只列名字按需加载、多大、近 30 天调了几次；延迟加载没生效时指出来。
- **会话与子代理**：统计会话长度、缓存过期整段重算次数、子代理模型，用来定自动压缩窗口等设置；另列出主会话的模型把活派给了谁，哪几次派工大到像是把整件活转包了出去（子代理自己发了上百次请求）。
- **Antigravity**：读它自己的会话日志和会话库，量出新开会话第一次请求带了多少 token（命令行、桌面 app 分开）、规则文件和 skill 清单各多大、哪些 MCP 工具整份常驻、会话实际长到多大才压缩。加载关系按 Antigravity 的规则算：同一层的 `AGENTS.md` 和 `GEMINI.md` 两份都加载，规则文件超过 24,000 字节的部分被截掉，`rules/` 下没写 `trigger` 的文件被丢掉；算出来的清单会和会话里实际加载的对一遍，对不上就写出来。不用的 skill 写进 `~/.gemini/config/skills.json` 的排除名单，skill 文件不动。
- **官方审查**：查 `/doctor prompt-audit` 能不能用、卡在哪，及背后官方说明文件的本机位置。

### 2. agent 按 `SKILL.md` 逐项确认

- 「近 30 天 0 次调用」只是候选，发版、回滚这类几个月才用一次的 skill 单独标出。
- 工具逐个确认：agent 给一张带编号的表（干什么、常驻还是按需、调用次数、建议），你按编号回，同意的才写进 `settings.json` 的 `permissions.deny`，随时拿掉。按需加载的工具只占一个名字，屏蔽它们几乎不省，表里会分开说。
- 整件转包先问是不是你有意交出去的。是模型自己转的，再找出是哪条规则导致的，照模板按你自己的模型和场景改派子代理的规则，给看改动，同意才改。
- 旧模型写法、指向不存在文件或互相矛盾的规则，交给官方 `/doctor prompt-audit`。就算关了它依赖的内置 skill，agent 也直接读背后公开的官方说明文件照做，不动开关。
- 不估「省多少 token」，只报实测数：第一次请求 token、模型可见 skill 数、调用次数。改完新开会话再量一次对比。

### 一次实测

在构造配置（318 个 skill、大规则文件）上，用真实 Claude Code 2.1.321 测过：第一次请求 85,854 → 清理后 20,383 → 回滚后 85,854 token。这是构造配置的结果，不代表实际能省多少。

## 压缩前要求和压缩后提醒（可选）

对话太长时，Claude Code 会把前面的内容压成一份摘要再接着聊，这叫压缩。之后模型手里只有摘要，摘要漏了什么它察觉不到：较早提过、还没做完的事最容易丢，命令、路径、数字也可能不准。

skill 走到配置那一步，会问你要不要装两个 hook 来补这一块，可以只装一个。hook 是写在 `~/.claude/settings.json` 里、由 Claude Code 在固定时刻自动跑的命令。两个各管一头：

- **压缩前要求**在每次压缩开始前跑一次，把约 230 字的三句话附在 Claude Code 自带的摘要要求后面，交给写摘要的模型。自带的要求有两处没管：连续压缩时不要求把上一份摘要里的待办带过来；「待办」只收你明确交代的任务。这三句话补的就是这两处：上一份摘要里还没结的事带过来，写成指针（一句话，加上能在完整记录里搜到原文的原词）；「待办」里加上问了你还没回的问题、没验证的地方、没提交的改动；已经结掉的旧事不带。原文在 `hooks/precompact-instructions.py`。
- **压缩后提醒**在每次压缩完成时跑一次，把约 410 字的提醒放进模型的上下文：回压缩前的完整记录核对细节，遇到指针就拿原词去搜原文，把你提过的要求从头过一遍，逐条确认做完没有。完整记录就是 Claude Code 本来就存在本机的会话日志（`~/.claude/projects/` 下的 `.jsonl`），hook 只告诉模型它在哪。原文在 `hooks/compact-reminder.py`。

装的时候各做两件事：往 `settings.json` 的 `hooks.PreCompact`（压缩前）或 `hooks.SessionStart`（压缩后）加一条，把脚本拷到 `~/.claude/hooks/`（`save-my-tokens-precompact.py`、`save-my-tokens-compact.py`）；卸掉时两样都拿走。每次运行它们只打印那段话，不联网，不写文件，不留后台进程。

### 实测

两项都用同一位用户的真实中文会话测，模型是 Claude Opus 5.5，由另一个模型盲评。细节和局限在 `references/compact-hook.md`。

**压缩前要求**：取 4 次压缩，退回到压缩开始之前，同一个起点各压一次。压缩那一刻真实没做完的事一共 43 件：

| 43 件没做完的事 | 只用自带要求 | 加压缩前要求 |
|---|---|---|
| 摘要里完整保住 | 15 | 24 |
| 只留了一半 | 11 | 8 |
| 丢了 | 17 | 11 |

4 次压缩上它都不比只用自带要求差，不增加请求，摘要也没有变长（按 token 粗估短约 15%）。还丢的事里有几件在更早的压缩里就没了，所以它要从会话的第一次压缩起就装着才起作用。同一批压缩上还试过一版英文写法，完整保住 20 件，不如中文这版，所以装的是中文。摘要短的部分主要在「文件和代码」一节，对接着干活有没有影响没有测。每一路只压了一次，数字不要当定论。

**压缩后提醒**：取 10 次压缩，恢复到压缩刚完成的那一刻，分别在装与不装的情况下接着跑：

| | 不装 | 装 |
|---|---|---|
| 拿用户压缩后真实说的下一句去问，回答的均分（满分 10） | 3.30 | 4.55 |
| 问「还剩什么」，摘要丢掉的 29 件事找回几件 | 2 | 13 |
| 压缩后第一个回答的平均花费 | $0.39 | $0.49 |

代价是压缩后的第一个回答平均多花约四分之一，钱主要花在模型回去翻日志。分数提高了，绝对值仍不高：20 个回答里还有 6 个犯了用户当时纠正过的错，10 次压缩里有 3 次装了反而不如不装。测的那一版比现在的提醒少四处补充（摘要偏向最近的事、不用写文件、做完要看结果并且对不上时以记录为准、遇到指针去搜原文）。

### 不走 skill，直接装或卸

```bash
python3 ~/.claude/skills/save-my-tokens/scripts/slim.py hook status
python3 ~/.claude/skills/save-my-tokens/scripts/slim.py backup --paths ~/.claude/settings.json ~/.claude/hooks/save-my-tokens-precompact.py ~/.claude/hooks/save-my-tokens-compact.py
python3 ~/.claude/skills/save-my-tokens/scripts/slim.py hook install --which before --backup <上一步输出的备份 ID>
python3 ~/.claude/skills/save-my-tokens/scripts/slim.py hook install --which after --backup <备份 ID>
python3 ~/.claude/skills/save-my-tokens/scripts/slim.py seal --backup <备份 ID>
```

`backup` 先把要动的路径原样存一份，输出里有备份 ID；`seal` 是改完后封存，记下改完的样子，之后才能可靠地回滚。只装一个就只跑对应的那条 `install`。改动在新开的会话里生效。

卸掉要新开一个备份（装时那个已经封存，不能再往里加改动）：

```bash
python3 ~/.claude/skills/save-my-tokens/scripts/slim.py backup --paths ~/.claude/settings.json ~/.claude/hooks/save-my-tokens-precompact.py ~/.claude/hooks/save-my-tokens-compact.py
python3 ~/.claude/skills/save-my-tokens/scripts/slim.py hook remove --which before --backup <新的备份 ID>
python3 ~/.claude/skills/save-my-tokens/scripts/slim.py hook remove --which after --backup <新的备份 ID>
python3 ~/.claude/skills/save-my-tokens/scripts/slim.py seal --backup <新的备份 ID>
```

也可以 `rollback --backup <装时的备份 ID>` 退回装之前的样子，但同一次备份里的其他改动（比如关掉的 skill）会一起退回。

## 改动与回滚

- 改前把要动的路径原样存进 `~/.save-my-tokens/backups/<时间戳>/`，每次新建不覆盖旧备份，权限 `0700`（可能含凭据）。
- 改 `settings.json`、`config.toml` 由脚本按键写（单键或批量一次写回），改完重新解析并与改前逐项比对，确认只变了目标键才写回；agent 不读全文。
- 回滚后逐项校验 sha256。文件改完后若被别人动过，回滚会停下来问而不覆盖，被替换的版本另存一份。
- 不碰 `~/.claude.json`（Claude Code 随时在写的状态文件）、凭据和插件目录；不硬删任何东西，不留后台进程；hook 只有压缩前要求和压缩后提醒这两个，你同意才装。往规则文件加内容（如子代理模型分工）前先给看改动，同意才加。

## 运行要求

- Python 3.9+，只用标准库，无需第三方包（macOS 自带 `python3` 够跑扫描和改 `settings.json`）。
- 改 Codex 的 `config.toml` 需 Python 3.11+。
- 读 Codex 的 `.jsonl.zst` 旧日志需 Python 3.14+ 或系统有 `zstd` 命令；都没有时，报告写明漏了多少文件。

## Windows 说明

还没在真实 Windows 上跑过，拿不准就不改：

- 只读扫描照常用；`python3` 换 `python` 或 `py -3`，路径换 `%USERPROFILE%\.claude\skills\save-my-tokens`。
- 每次备份前先在系统临时目录造假配置，走一遍备份、修改、回滚并核对一致；没过就拒绝改动、只出报告。可先跑 `python scripts\slim.py selftest` 检查（不碰真实配置）。
- 搬目录（`move`）在 Windows 关闭；要备份的路径是软链或目录联接也会拒绝。
- 带 BOM、CRLF 换行的文件改完保持原样；换行混用或非 UTF-8 不改。
- 通过 `CLAUDE_CONFIG_DIR`、`CODEX_HOME` 改过的配置目录会跟着读。
- 出问题欢迎提 issue，附上 `selftest` 输出。

## 已知限制

- 只在 macOS 上跑过。
- 开局实测 Claude Code 和 Antigravity 有，Codex 没有。分项明细依赖较新版本 Claude Code 日志（核过 2.1.321、2.1.326），旧版只出总数。
- Codex 和 Antigravity 的 skill 调用次数从「工具调用里读了某个 `SKILL.md`」推断，非官方计数。
- Antigravity 的分项明细读的是它的会话库，这个格式官方没有公开，只在命令行 1.5.17–1.5.18 和同期的桌面 app 上核过；读不出时报告会写明，只给日志里的 token 总数。项目里的 `skills.json`、所有的 `rules.json`，以及插件带进来的内容没有展开（全局 `skills.json` 的 `entries` 和 `inherits` 会展开）。两个压缩 hook 只有 Claude Code 能装。
- 意思相同、措辞不同的重复规则脚本找不到，靠 agent 读文件判断。
- 报告会回显重复规则的原句。配置里键名是凭据的值（`API_KEY`、`*_TOKEN`、自定义请求头这些）、样子像凭据的片段（`KEY=值`、`Bearer …`、常见前缀的密钥、16 个字符以上字母数字混着的词）会遮掉；用大白话写在规则里、又短又不含数字的口令脚本认不出来。
- 开关清单只收了核对过官方文档的三十几个键，键名和默认值随版本变，每条附出处和核对日期。
- 同名 skill 在用户级和项目级各装一份时，日志分不出实际用哪份。
- 桌面 app 走第三方网关时工具延迟加载被关掉的判断和改法，只在 Claude Code 2.1.330 上验证过；改法要写系统目录下的托管设置，需要管理员密码，命令由你自己跑。
- 一次派工是你有意整件交出去的，还是模型自己转的，日志分不出，要 agent 问你。

## 目录与许可

```text
SKILL.md                  给 agent 看的流程
scripts/slim.py           扫描、备份、改单个键、屏蔽工具、回滚
references/switches.json  开关清单：默认值、说明、官方出处、核对日期
references/windows.md     在 Windows 上跑的注意事项
references/antigravity.md Antigravity 的加载规则、能改的地方和命令，每条带出处
references/compact-hook.md 压缩前要求和压缩后提醒的实测
references/tool-search.md 工具延迟加载没生效时的判断和改法
references/subagent-rules.md 派子代理规则的模板和填法
hooks/precompact-instructions.py 压缩前要求的 hook 脚本
hooks/compact-reminder.py 压缩后提醒的 hook 脚本
```

MIT，见 `LICENSE`。
