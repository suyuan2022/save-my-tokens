# Antigravity（Gemini 反重力，命令行叫 agy）

报告里出现 Antigravity 的章节时，这部分照本文件做。它的加载规则、能改的地方和命令，和 Claude Code、Codex 都不一样。

每条事实后面的方括号是出处：
- `[文档:页名]` 是 `https://antigravity.google/docs/` 下的那一页。
- `[实验]` 是 2026-11-26 用命令行 1.5.18 在隔离目录里实测的（`tests/real_demo_agy.py` 能重跑其中的主流程）。
- `[真机]` 是只读核对一台真机近 30 天的会话记录得到的。

核对日期超过三个月，或用户的版本比 1.5.18 新很多时，先打开出处核对再用。

## 报告里的数是怎么来的

- **开局 token**：会话日志 `~/.gemini/<数据目录>/brain/<会话>/.system_generated/logs/transcript.jsonl` 里第一条模型回复的 `input_tokens + cache_read_tokens`。这是 Antigravity 自己记的用量。`[实验]` agy 通过 ACP 报回来的是一轮里各次请求的合计（新输入、读缓存分开报），和日志里各次请求相加逐项相等；一轮只有一次请求时，它就是开局这个数。
- **各部分的大小**：会话库 `conversations/<会话>.db` 里留着的最后一次请求的全文（Antigravity 只留最后一次）。这个格式官方没有公开，报告写「读不出各部分的大小」时，让用户在命令行里新开会话输入 `/context`，把结果贴过来。
- **入口**：命令行、桌面 app、IDE 各有一个数据目录，报告按入口分开列，因为它们带的工具和 skill 不一样。
- **skill 用了几次**：Antigravity 没有专门调 skill 的工具，用一个 skill 就是读它的 `SKILL.md`。报告数的是近 30 天有几个会话读过它，是推断。跟用户说的时候说「有几个会话读过」。次数按被读文件的真实路径归到具体那一份，同名的两份各算各的。
- **自查**：每次扫描，脚本把自己算出来的规则文件清单、skill 清单，和每个入口最近一个会话里 Antigravity 实际发给模型的对一遍。对不上时报告里有一条「注意：……不一样」，那一块以实际发的为准，并把这条原样告诉用户。
- **量不出来的会明说**：会话的第一条模型回复没记用量、会话在摘要库里查不到又分不清是不是子代理、会话库里有几段认不出来，报告各有一句说明，这些会话不进统计或标成「明细不完整」。转告用户，不要替它补数。
- **模型**：桌面 app 的日志多数不记模型，报告用会话库里最后一次请求的模型补，并写明补了多少次。

开局明细里某个 MCP 标着「来源未知」：脚本查过的 `mcp_config.json`（全局的，和工作目录往上各层的）里都没有它。常见的是开这个会话的程序自己带进来的（别的工具通过 `agy acp` 开的会话就是这样 `[真机]`），也可能是插件带的。先问用户这个会话是用什么开的，再决定去哪里设；这里只报大小。

## 加载规则（跟用户讲和判断重复时用）

**规则文件**

- 全局：`~/.gemini/AGENTS.md`、`~/.gemini/GEMINI.md`、`~/.gemini/config/AGENTS.md`、`~/.gemini/config/GEMINI.md`，存在几个加载几个。`[文档:rules]` `[实验]`
- 项目：从工作目录往上到仓库根（有 `.git` 的那层），每一层的 `AGENTS.md`、`GEMINI.md`、`.agents/AGENTS.md`、`.agents/GEMINI.md`、`.agents/rules/*.md` 都加载。**同一层的 AGENTS.md 和 GEMINI.md 两份都加载**，内容相同就是重复带了两遍。`[文档:customization-discovery]` `[实验]`
- 这些位置的文件 Antigravity 不读：仓库根之上的目录、工作目录下面的子目录、`CLAUDE.md`、`rules/` 的嵌套子目录。`[实验]`
- 工作目录不在任何仓库里时，只读工作目录这一层；把上级目录登记成 Antigravity 的项目也一样。`[文档:customization-discovery]` `[实验]`
- `rules/` 目录下每个文件开头要写 `trigger`：`always_on` 每次整份带着；`model_decision` 只给模型一行路径加描述，相关时才读；`glob` 碰到匹配的文件才带；`manual` 用户 @ 它才带（命令行不支持 @ 规则，所以在命令行里它等于不加载）。没写或写错（比如 `alwaysOn`），整个文件被丢掉、不报错。`[文档:rules]` `[实验]`
- `@[标签](路径)` 把那个文件的正文展开进规则（被展开的文件开头的 frontmatter 会先去掉）；单写 `@路径` 不展开内容，Antigravity 只把它改写成一个规范的绝对路径留在原地（和 Claude Code 相反）。`[文档:rules]` `[实验]`
- 每个规则文件按展开之后的大小算，超过 24,000 字节的部分被截掉。`[文档:rules]` `[真机]` 一个 28,889 字节的文件在请求里只剩 23,762 字节，末尾是一句 `<truncated 5127 bytes>`。
- 全局规则和 `always_on` 规则合用 20,000 token 的预算，超了自动把最大的几份降成只给路径。`[文档:rules]`（没做实验）
- 规则和 skill 每次请求前重新读，改完开着的会话下一句话就生效。`[文档:customization-discovery]`

**Skill**

- 模型每次请求看到一份清单：每个 skill 一行「名字（路径）：描述」。
- 同名的 skill 只留一份。优先级从高到低：命令行专用的两个目录（只在命令行里）、项目里的、`~/.gemini/config/` 的（含它的清单文件点名的）、`~/.agents/skills` 的、内置的。`[文档:customization-discovery]` `[实验]` 报告里让位的那份标着「被同名的盖住」。
- 来源：`~/.gemini/config/skills`（全局）；`~/.agents/skills`（命令行 1.5.16 起也当全局读，和 `~/.gemini` 里的同名时让位）`[文档:changelog]` `[实验]`；`~/.gemini/antigravity-cli/skills` 和 `~/.gemini/skills`（只有命令行读，同名时它们优先）`[文档:customization-discovery]`；项目里各层的 `.agents/skills`；Antigravity 内置的。
- **排除名单**：`~/.gemini/config/skills.json` 顶层的 `exclude`，写 skill 的**目录名**。写 `SKILL.md` 里的 `name` 不生效。`[实验]` 它管得到全局的、`~/.agents/skills` 的、项目里的和内置的 `[实验]`；管不到只有命令行读的那两个目录 `[文档:customization-discovery]` `[实验]`。排除只对 Antigravity 生效，skill 文件不动。
- `SKILL.md` 开头写了 `disable-model-invocation: true` 的 skill 不进这份清单。`[实验]`（官方文档没写）所以 save-my-tokens 自己在 Antigravity 里不占位置；这种 skill 用户输入 `/名字` 仍然调得起来。`[实验]`

**MCP**

- 配置在 `~/.gemini/config/mcp_config.json`，项目里是 `.agents/mcp_config.json`。旧的 `~/.gemini/settings.json` 是 Gemini CLI 的文件，写在里面的 MCP Antigravity 不加载。`[文档:cli/gcli-migration]` `[实验]`
- 默认**按需**：每个工具只在名单里占一个名字，说明文件落在磁盘上，用到才读。`tools.<工具名>.eager: true` 的工具整份说明每次请求都带着；先过 `enabledTools` / `disabledTools`，被屏蔽的工具写了 `eager` 也不常驻。`disabled: true` 的 server 在名单里只剩一个标题。`[文档:mcp]` `[实验]`
- 项目的 `.agents/mcp_config.json` 和规则一样，从工作目录往上找到仓库根。`[文档:customization-discovery]`（没做实验）

**Hook 和压缩**

- hook 的时机只有 SessionStart、PreToolUse、PostToolUse、PreInvocation、PostInvocation、Stop，没有压缩前后。`[文档:hooks]` SKILL.md 里那两个压缩 hook 在 Antigravity 上不装。
- 命令行的自动压缩点用环境变量 `AGY_CLI_AUTO_COMPACT_OVERRIDE` 调（1.5.15 起；写 `700000`、`800K`、`80%` 都行），`/context` 里能看到生效的值。桌面 app 的官方文档没有给出对应的设置。`[文档:changelog]`

## 和用户逐项过

顺序仍按 SKILL.md 第 2 步：先讲开局账单，从大的砍起。

**规则文件**

1. 报告「确定写错或不生效的」里有 Antigravity 的条目时先讲：
   - 没写 `trigger` 被丢掉的文件：问用户这个文件还要不要生效。要，就在开头补上 `trigger`；不要，告诉他它现在本来就没被加载。
   - 超过 24,000 字节的文件：尾部模型读不到。读这个文件，告诉用户被截掉的是哪几节，和他定瘦到上限以内还是拆开。
2. 大文件按节过，四个去向照 SKILL.md。其中「改成按需」在 Antigravity 里的写法：把那一节挪到 `.agents/rules/<名字>.md`（全局的放 `~/.gemini/config/rules/`），开头写 `trigger: model_decision` 和一句 `description`，之后每次请求只带一行路径加描述。
3. 重复规则里标着「在 Antigravity 的会话里」的，是同一个 Antigravity 会话里一起加载的两个文件。同一层的 AGENTS.md 和 GEMINI.md 内容相同时，提议只留一份。
4. AGENTS.md 也是 Codex 读的文件，`~/.gemini/GEMINI.md` 可能是指向别处的软链。动之前先看报告里这个文件还有谁在读，把影响面告诉用户。

**Skill**

- A 组（近 30 天没有会话读过，也找不到留着的理由）：给用户看 `slim show --agent agy --scan J --group A`，他同意后写进排除名单。
- B 组：逐个讲 ⚠ 的理由，默认保留。
- 报告里「排除名单里写的是它的 name……实际没排除掉」的：用户以为停了其实没停，告诉他，他同意后按目录名重新排除。
- 只有命令行读的目录里的 skill，排除名单管不到，要停只能 `slim move` 搬走。
- 项目里的 skill 也能写进排除名单；这份名单按目录名对所有项目生效，同名的都会藏掉，先和用户确认。
- 用户想要「只能手动调」：那是在这个 skill 的 `SKILL.md` 开头加 `disable-model-invocation: true`，改的是 skill 文件本身，Claude Code 也认这个字段，共用的 skill 两边一起变。讲清后由用户决定，改之前把那个文件加进 backup。

**MCP**

- 写了 `eager` 的工具：每次请求都带整份说明。报告的开局明细里有它们一共多少字符，照实说，问用户是否改回按需（功能不变，用之前多读一次说明文件）。
- 近 30 天 0 调用的 server：可以 `disabled: true`，配置留着。它本来是按需的话，省下的只是名单里的几行，照实说。
- 按需的工具逐个屏蔽省得很少，用户没问就不提。

**会话长度和压缩**

报告给了实测：主会话最长到多大、实际发生过几次压缩、压缩前长到多大、有多少次整段重算。只讲事实。用户想让命令行早一点压缩，告诉他 `AGY_CLI_AUTO_COMPACT_OVERRIDE` 这个环境变量，由他自己加进终端的配置文件；脚本不改终端配置。报告里的 `contextWindow` 是公开设置清单里没有的键，只说它在。

**子代理**

报告列了派子代理多少次、多少次没指定模型、哪些子代理会话发了很多次请求。只讲事实。用户想管，自定义子代理的定义里有 `model` 字段（`inherit`、`flash`、`pro`）`[文档:subagents]`，写法读那一页。

## 命令

```
slim backup --paths ~/.gemini/config/skills.json ~/.gemini/config/mcp_config.json [要改的规则文件…]
slim show   --agent agy --scan J --group A
slim skills --agent agy --backup ID --state off --scan J --group A [--exclude 名字…]
slim skills --agent agy --backup ID --state off 目录名…
slim skills --agent agy --backup ID --state on  目录名…                 # 从排除名单拿回来
slim set --backup ID --file ~/.gemini/config/mcp_config.json --path '["mcpServers","名字","disabled"]' --value true
slim set --backup ID --file ~/.gemini/config/mcp_config.json --path '["mcpServers","名字","tools","工具名","eager"]' --delete
slim seal --backup ID
slim compare --agent agy --before 改前.json --after 改后.json
slim rollback --backup ID
```

`skills.json` 还不存在时也照样 backup，脚本会新建它，回滚时删掉。Antigravity 的 skill 只有 off 和 on 两种状态。

看效果：让用户新开一个 Antigravity 会话说一句话，再 `slim scan --json 改后.json`，然后 `slim compare --agent agy`。两次要在同一个目录、同一个入口开，数字才能比。

## 没核实的

碰到下面这些，告诉用户这一条脚本没有把握，以报告开局部分列出的实际加载为准：

- 清单文件：全局 `skills.json` 的 `entries`（含每项的 `include_only`、`exclude`）脚本会展开 `[文档:customization-discovery]`（没做实验）；`inherits`、项目里的 `skills.json`、所有的 `rules.json` 没有展开，报告会提示有这些文件。
- 凭据遮盖：配置里键名是凭据的值（`API_KEY`、`*_TOKEN`、`headers` 下面的这些）、样子像凭据的片段（`KEY=值`、`Bearer …`、常见前缀的密钥）在报告和命令输出里会遮掉。规则文件里换了写法裸写的密钥脚本认不出来；给用户看重复规则的原句之前，自己再看一眼。
- 插件带进来的 skill、规则和 MCP：归插件管，脚本不动。
- SessionStart 的 hook 放进来的内容以一条系统消息进会话 `[实验]`：它算在开局 token 的总数里，但不在「各部分的大小」那张表里，脚本没有单独量它。PreInvocation 的 hook 没试过。
- 桌面 app 读不读 `~/.agents/skills`、IDE 入口的行为：没有样本。
- 会话库的格式只在命令行 1.5.17–1.5.18 和同期的桌面 app 上核过。新版本读不出时报告会写明，不会给估算的数。
