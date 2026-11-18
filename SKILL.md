---
name: save-my-tokens
description: 给 Claude Code 和 Codex 的配置做一次体检：按近 30 天实际用法，和用户逐项商量停用哪些 skill / MCP、收拾哪些重复规则，改前备份，可回滚。
disable-model-invocation: true
---

# save-my-tokens

这是一次带**证据**的商量：脚本出证据，用户**拍板**，你执行，每一项都能退回原样。成果是用户清楚自己配置里每样东西为什么留着，不是配置变短了多少。

脚本在本文件旁边：`python3 <本目录>/scripts/slim.py`，下面简写成 `slim`。只用 Python 标准库，参数用 `slim <子命令> -h` 查。

用户的电脑是 Windows 时，先读文末「Windows」一节再往下做。

## 1. 扫描

```
slim scan --json <系统临时目录>/save-my-tokens-scan.json
```

只读，不改任何文件，日志多时要跑一两分钟。输出是一份中文报告；`--json` 那份留着，第 4 步要用。

报告开头的「注意」行（日志只覆盖了几天、没有日志、配置解析失败）决定后面的「0 次」能不能信，原样转告用户。

## 2. 先给全貌

用五到八行告诉用户：装了哪一端、模型每轮能看到多少个 skill、各类**候选**各有几个（用户级 skill、项目级 skill、Codex skill、0 调用的 MCP）、同一会话里有没有重复加载的规则、有没有写错的开关、官方 prompt-audit 现在能不能调。然后问他想从哪块开始。整份报告留在你这里，按块取用。

## 3. 逐块商量

每一项都按同一个顺序：摆证据 → 给选项和你的倾向 → 用户拍板 → 记进改动清单。这一步只记不改。同类的可以成组问；带 ⚠ 的逐个讲，不并进成组的问题里。

「0 次调用」是**候选**，不是结论：它只说明这个时间窗里的日志没看到。

### Skill（Claude Code）

对「0 次调用、但还对模型可见」的每个候选，说出报告给的证据（描述多少字符、⚠ 标记、谁引用了它、skillUsage 记的最后一次），再给选项：

| 选项 | 效果 | 适合 |
|---|---|---|
| 保留 | 不动 | 带 ⚠ 的默认选这个 |
| `name-only` | 模型只看到名字，描述不再占位置 | 偶尔用、名字本身说得清的 |
| `user-invocable-only` | 模型看不见，用户敲 `/名字` 才用 | 只会手动触发的 |
| `off` | 模型看不见，`/名字` 也隐藏 | 确定不用的 |

这四个都是往 `~/.claude/settings.json` 的 `skillOverrides` 里写一行，文件原地不动。

报告里「日志实记」那一行是 Claude Code 自己记下的、新开会话时发给模型的 skill 清单（个数和字符数），是实测值。讲效果时用它，并说清一件事：这份清单有预算上限（上下文窗口的 1%），超了 Claude Code 会从最少用的 skill 开始丢掉描述。所以清单已经顶到上限时，停用 skill 的效果是给剩下的 skill 腾出描述的位置，清单不一定变短。

还有一种处理针对用过的 skill：报告在「用过的」里标了「只在某项目用过」的，可以提议**下沉到项目**，把目录搬到 `<项目>/.claude/skills/`，别的项目里模型就不再看到它。

⚠ 标记各自的含义：

- **被点名引用**：别的 skill、规则文件或 hook 里提到了它。停掉之前先看引用者还用不用。
- **像低频保命项**：发版、回滚、迁移、事故这类，本来就几个月用一次。
- **装了才 N 天**：还没到能下结论的时候。
- **软链断了**：入口还在，指向的目录已经不存在，这个 skill 用不了。告诉用户它原本指向哪，由他决定删掉这条软链还是把目标找回来；删由用户自己动手。
- **skillUsage 记着用过，日志里没数到**：两个数据源对不上，按「用过」处理。skillUsage 是 Claude Code 自己记在 `~/.claude.json` 里的每个 skill 的累计次数和最后使用时间，脚本拿它和日志交叉核对。

「Codex 读」大于 0 的 skill，Codex 是直接按路径读文件的：改 `skillOverrides` 不影响它，搬走会让它读不到。软链的 skill 只改 `skillOverrides`，位置留在原处。

「已经 off 但还在被手敲」的，提一句让用户知道。

### Skill（Codex）

没被读过的候选，选项是保留，或在 `~/.codex/config.toml` 的 `skills.config` 里加一条 `enabled = false`（文件不动）。

### MCP

- **Codex**：0 调用的 server 可以设 `mcp_servers.<名字>.enabled = false`。想进一步收窄的，可以用 `enabled_tools` 只放行用到的那几个；报告列了近 30 天用到哪些工具，这个 server 一共暴露多少工具脚本不知道，要问用户。
- **Claude Code**：用户级 MCP 存在 `~/.claude.json`，那是 Claude Code 自己随时在写的状态文件，本工具只读。要移除就把命令给用户自己跑：先 `claude mcp get <名字>` 把配置存下来，再 `claude mcp remove <名字> -s user`。讲清楚这一步不在备份保护里。
- 「设了 alwaysLoad」「ENABLE_TOOL_SEARCH=false」是取舍：告诉用户它意味着工具说明每轮常驻，连同调用次数一起，让他判断值不值。

### 重复规则

报告把重复分成两种，处理方式不同：

- **同一会话重复加载**（比如全局 CLAUDE.md 和项目 CLAUDE.md 里同一条）：每次请求都多带一遍。问用户留哪一处。标 `≈` 的是两处措辞有出入，先问哪份是新的。
- **两个 agent 各一份**（CLAUDE.md 对 AGENTS.md）：Claude Code 和 Codex 各读各的，这不是重复付费。只处理有出入的那几条：问哪份是对的，把另一份同步过去。同一个项目里两份几乎一样时，可以提议让 CLAUDE.md 只写一行 `@AGENTS.md` 再加 Claude 专属的几条。

两个文件算不算「同一会话一起加载」，以报告的标签为准。脚本是按官方规则算的：项目里有 CLAUDE.md 时 Claude Code 只读 CLAUDE.md，没有才读 AGENTS.md；`@路径` 会把那个文件一起带进来；`settings.json` 的 `claudeMdExcludes` 排除掉的文件不加载（报告会注明）；Codex 只读 AGENTS.md。每个项目实际加载哪些文件，在 json 的 `projects[].claude_files` 和 `codex_files` 里。

脚本只找得到逐条相同和措辞相近的。意思相同、写法不同的重复，你去读报告「查了这些规则文件」列出的文件自己找；找到之后先对照上面那份加载清单，确认两个文件确实会一起加载，再提出来。

报告里每个规则文件带行数，CLAUDE.md 超过官方建议的 200 行会标出来。这只是一个事实，删哪些内容不在这里判断，留给下面 prompt-audit 那一步；官方那份说明写明不能只凭长度删内容。

报告还会列出写了 `@路径` 但那个文件不存在的引用，是候选：先打开那一行确认它确实是引用，再问用户是改路径还是删掉。

报告写着「有 N 组项目目录的规则文件内容完全相同」时，同组的其他目录（多半是 worktree）在 json 的 `projects[].same_as` 里。要改其中一个项目的规则文件，先告诉用户同组还有哪些目录，它们不会跟着变。

改规则文件时：只做删除、合并、同步；保留里面的具体事实（命令、路径、数字、项目结构）；每一处改动都要让用户看过 diff。

### 规则写得好不好：交给官方 prompt-audit

旧模型时代的写法、指向不存在的文件或命令、互相矛盾的规则，由 Claude Code 自带的 `/doctor prompt-audit` 查，这里不重做。

- 报告写「能」：其他块都商量完之后调用它（Skill 工具，`doctor`，参数 `prompt-audit`）。它会先出报告、等用户确认才改；在让它动手之前，先把它要改的文件用 `slim backup` 备份。调用失败就请用户自己敲 `/doctor prompt-audit`。
- 报告写「现在不能」或「不确定」（用户关了内置 skill，或版本太旧）：用户的设置保持原样。`/doctor prompt-audit` 背后就是一份官方说明文件，直接读它、照它一步步做，效果相同。报告给了本机副本的路径和文件日期；没有副本，或副本日期早于三个月，读报告里的原文地址。
- 只有 Codex：同样读原文地址照做，对象是 AGENTS.md 和 Codex 的 skill。

照官方文件做时，范围先和用户定（它的 Step 0）：默认从每个会话都加载的全局规则文件开始，要不要扩到全部 skill 由用户决定，因为 skill 多的时候这一步读得多。它的产出是一份报告和一份改动提议；用户同意要改的，和其他改动一样先 `slim backup` 再改。

### 开关

- 「确定写错或不生效的」：逐条讲清楚错在哪，给出改法。
- 取舍项：报告只列事实。用户问到某个键，或者说了他想要的效果，再去 `references/switches.json` 查那个键管什么、默认是什么、出处在哪，讲给他听。条目的核对日期超过三个月时，先打开出处核对再回答。

## 4. 执行

把改动清单完整复述一遍，规则文件的改动在清单里直接写成 diff。用户确认整份清单之后才动手，确认过的 diff 不用再问第二遍：

1. **备份**：`slim backup --paths <这次要动的每个路径>`。要新建的路径（比如 skill 下沉的目的地）也列进去。HOME 之外的项目目录加 `--root <项目目录>`。记下输出的备份 ID。
2. **改**：
   - `settings.json`、`config.toml` 用 `slim set`。这两个文件里常有凭据，全程通过 `slim set` 操作，不打开全文。
   - 搬目录用 `slim move`。
   - Markdown 规则文件直接编辑。
3. **封存**：`slim seal --backup <ID>`。
4. **核对**：`slim status --scan <第 1 步的 json>`。
5. **重扫**：再跑一次 `slim scan`（只读），拿改完之后的数字。

做完的标准：`seal` 列出的每一项和清单对得上，`status` 里没有 ✗。出现 ✗ 表示有文件没备份就被改了，立刻告诉用户是哪个。

最后告诉用户三件事：改了什么（用两次扫描的数字说，比如「模型可见的 skill 从 35 个变成 28 个」）、改动在新开的会话里生效、回滚命令是什么。想看实测的效果：新开一个会话之后再扫一次，「日志实记」那一行就是新会话里模型实际拿到的清单。

`slim set` 的写法（`--path` 是 JSON 数组，`--value` 是 JSON 值）：

```
slim set --backup ID --file ~/.claude/settings.json --path '["skillOverrides","pdf-tools"]' --value '"name-only"'
slim set --backup ID --file ~/.claude/settings.json --path '["skillOverrides","claude-api"]' --delete
slim set --backup ID --file ~/.codex/config.toml --path '["mcp_servers","playwright","enabled"]' --value false
slim set --backup ID --file ~/.codex/config.toml --path '["skills","config",{"path":"/绝对路径/SKILL.md"},"enabled"]' --value false
```

`slim set` 拒绝时会说原因（多行值、内联表、带注释的 JSON、手工排版的 JSON、CRLF 和 LF 混用、文件不是 UTF-8）。这些拒绝是有意的：脚本保证不了目标键以外的字节不变时就不改。那种情况只读目标键附近的几行，手动改，改动仍在备份保护内。

## 5. 回滚

用户想退回：`slim rollback --backup <ID>`，不给 ID 就退最近一次。有多个备份时从新到旧退。

输出以「停：」开头，说明那些文件在我们改完之后又被动过，此时什么都没还原。规则文件的差异脚本会直接打印出来；把文件名和后来多出的改动告诉用户，由他决定要不要加 `--force`。被替换下来的版本会存在备份目录里，用户想留下的后加内容可以在回滚后补回去。

## Windows

这个脚本没有在真实的 Windows 上跑过。所以在 Windows 上，扫描照常用，改动先过本机自检，过不了就只看报告。

- **怎么调用**：`python3` 在 Windows 上常常是一个跳转到应用商店的空壳。依次试 `python`、`py -3`，用第一个能打印版本号的。
- **扫描**：`slim scan` 只读，和其他系统一样用。输出是 UTF-8，按 UTF-8 读。
- **改之前**：`slim backup` 在 Windows 上会先自动自检（约 1 秒，进度打在 stderr）：在系统临时目录里造一份假配置，走一遍备份、改、回滚，核对回滚后每个文件和改前一致。自检没过，`backup` 会拒绝，这台机器上就只用扫描报告，改动告诉用户怎么手动做。想先看一眼可以单独跑 `slim selftest`，它不碰真实配置。
- **备份只列具体文件**，不列目录。Windows 上 skill 目录里常有软链和目录联接（junction），要备份的路径是这类东西、或者里面有，`backup` 会拒绝。
- **`slim move` 不可用**，一定会被拒。skill 要下沉到项目，把步骤告诉用户，由他手动搬。
- **回滚报「被拒绝」**（退出码 5）：文件正被 Claude Code、Codex 或编辑器占用。请用户关掉占用它的程序，再跑一次同样的 `rollback`；这一次如果说文件「又变过」，是上次还原到一半造成的，加 `--force`。
- **`slim set` 的参数是 JSON**，PowerShell 5.1 会吃掉里面的双引号。在 Git Bash 里跑（Claude Code 在 Windows 上的 Bash 工具就是它）；只能用 PowerShell 时写成 `'[\"skillOverrides\",\"x\"]'`。
- **配置不在默认位置**：脚本自己认 `CLAUDE_CONFIG_DIR` 和 `CODEX_HOME` 这两个环境变量，不要再传 `--home`，传了会忽略它们。
- stderr 里「注意：」开头的行（HOME 和 USERPROFILE 不一致、按环境变量换了配置目录、这次不读 `.claude.json`）原样转告用户。

## 边界

- 只读不改：`~/.claude.json`、凭据文件、会话日志、插件目录。
- `~/.save-my-tokens/` 里是原样拷贝，可能含凭据，内容不进对话。
- 没量过的数不报。能说的是事实：可见 skill 的个数、描述字符数、删了几条重复规则。
