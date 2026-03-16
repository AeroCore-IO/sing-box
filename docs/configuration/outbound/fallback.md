### Structure

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

### Fields

#### outbounds

==Required==

List of outbound tags. The first outbound is used by default. When a connection fails, it automatically switches to the next outbound in the list.

#### url

The URL to test for primary outbound recovery. `https://www.gstatic.com/generate_204` will be used if empty.

When the primary (first) outbound recovers and passes the URL test, the fallback will automatically switch back to it.

#### interval

The test interval for checking primary outbound recovery. `3m` will be used if empty.

#### interrupt_exist_connections

Interrupt existing connections when the outbound has changed (e.g., switching back to primary after recovery).

Only inbound connections are affected by this setting, internal connections will always be interrupted.