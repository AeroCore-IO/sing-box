### 结构

```json
{
  "type": "fallback",
  "tag": "fallback",
  
  "outbounds": [
    "proxy-a",
    "proxy-b",
    "proxy-c"
  ],
  "url": "",
  "interval": "3m",
  "interrupt_exist_connections": false
}
```

### 字段

#### outbounds

==必填==

出站标签列表。默认使用第一个出站。当连接失败时，自动切换到列表中的下一个出站。

#### url

用于测试主出站恢复的 URL。为空时使用 `https://www.gstatic.com/generate_204`。

当主出站（第一个）恢复并通过 URL 测试时，将自动切换回主出站。

#### interval

检查主出站恢复的间隔。为空时使用 `3m`。

#### interrupt_exist_connections

当出站发生变更时（如恢复后切回主出站）中断现有连接。

仅影响入站连接，内部连接将始终被中断。