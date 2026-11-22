# 工具延迟加载没生效：桌面 app 走第三方网关

2026-11-22 在一台 Mac 上查到并修好的一个病例，Claude Code 2.1.330。别的版本、别的系统没有验证过；版本不同时先照「判断」一节重新量，再决定用不用这里的改法。

## 是什么情况

Claude 桌面 app 配了第三方推理网关时，它开出来的会话带环境变量 `CLAUDE_CODE_ENTRYPOINT=claude-desktop-3p`，app 还会给会话加上 `CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS=1`。后一个变量把工具延迟加载强制关掉，用户 `settings.json` 里写的 `ENABLE_TOOL_SEARCH=true` 被它盖过。结果：所有 MCP 工具的说明整份带进每一次请求，`ToolSearch` 这个工具不出现。

同一台机器上从终端开的 Claude Code 会话不受影响，所以报告里会看到两个入口的工具清单不一样。

## 判断

三样证据，任意一样就够，越靠前越省事：

1. **扫描报告**：「开关」一节有一行「工具延迟加载没生效……entrypoint=claude-desktop-3p」。
2. **用户贴的 `/context`**：MCP tools 一栏有几万 token，工具一个个整份列着，而用户没有把 `ENABLE_TOOL_SEARCH` 设成 false。
3. **调试日志**（要确认开关到底判成了什么时用）。在用户平时的入口环境里跑一次最便宜的模型：

   ```
   claude -p "hi" --model haiku --debug-file <系统临时目录>/ts-debug.txt
   grep "ToolSearch:optimistic\|Dynamic tool loading" <系统临时目录>/ts-debug.txt
   ```

   - 没生效：`[ToolSearch:optimistic] mode=standard, ENABLE_TOOL_SEARCH=true, result=false`
   - 生效：`[ToolSearch:optimistic] mode=tst, ENABLE_TOOL_SEARCH=true, result=true`，后面还有一行 `Dynamic tool loading: 0/N deferred tools included`（N 是被延迟的工具数）

   这条命令会发一次请求。那次是在桌面 app 会话自己的 Bash 里跑的，环境里已经带着 app 加的那两个变量，用的是 app 自带的 `claude`（在 `~/Library/Application Support/Claude-3p/claude-code/<版本>/` 下面）。你正跑在桌面 app 的会话里时照样做。从终端复现没有实测过：按程序里的判断逻辑，命令前加 `CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS=1` 应该得到同样的结果，用这种办法时告诉用户这是推断。

## 改法

只有一种写法能打开：**托管设置**里把 `ENABLE_TOOL_SEARCH` 写成 `force`。

文件：`/Library/Application Support/ClaudeCode/managed-settings.json`

```json
{"parentSettingsBehavior":"merge","env":{"ENABLE_TOOL_SEARCH":"force"}}
```

- `parentSettingsBehavior: merge` 要带上。不带时这个文件会顶掉 app 自己下发的托管策略，app 日志 `~/Library/Logs/Claude-3p/main.log` 里会有一条警告。
- 这个文件在系统目录，**要 sudo**。它在 `slim backup` 管不到的地方，也是全机所有用户的 Claude Code 都会读的设置。

试过的六种写法：

| 写在哪 | 值 | 结果 |
|---|---|---|
| 托管设置 | `force` | 打开 |
| 托管设置 | `true` | 没打开 |
| 托管设置 | `auto` | 没打开 |
| 用户 `settings.json` 的 `env` | `force` | 没打开 |
| 用户 `settings.json` 的 `env` | `true` | 没打开 |
| 进程环境变量 | `force` | 没打开 |

## 怎么跟用户走这一步

1. 讲清楚这三件事再问他改不改：要 sudo；这是系统级文件，不在备份和回滚里；只在 2.1.330 上验证过。
2. 先看文件在不在：`ls -l "/Library/Application Support/ClaudeCode/"`。已经有这个文件时，读它（只报有哪些键），把上面两个键合并进去，不整份覆盖；公司电脑上这个文件可能是 IT 下发的，那种情况告诉用户去找管理员，不动它。
3. 用户同意后，把命令给他自己跑，密码由他自己输。文件不存在时：

   ```
   sudo mkdir -p "/Library/Application Support/ClaudeCode"
   echo '{"parentSettingsBehavior":"merge","env":{"ENABLE_TOOL_SEARCH":"force"}}' | sudo tee "/Library/Application Support/ClaudeCode/managed-settings.json"
   ```

4. 验证：请用户新开一个会话贴 `/context`，MCP tools 一栏应该从几万 token 掉到几千；或者照「判断」第 3 条再跑一次调试日志，看到 `mode=tst ... result=true`。两样都没变，就是这个版本的行为不同了：把文件移走，告诉用户这条路在他的版本上不通。
5. 退回：`sudo mv "/Library/Application Support/ClaudeCode/managed-settings.json" ~/managed-settings.json.removed`（文件原本不存在时）；原本有文件时，把加进去的两个键删掉。

## 打开之后

被延迟的工具每个只占一个名字。这时再去屏蔽它们几乎不省 token，值得看的是仍然常驻的那些（见 SKILL.md「MCP 和工具」一节的逐个工具表）。那次的实测：MCP 工具说明从 70.8K token 降到常驻 5.3K，另有 20.5K 变成按需加载；这个降幅里既有打开延迟加载，也有同时屏蔽掉的一批工具。
