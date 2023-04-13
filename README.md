# haproxy-lua-utils

A utility library written in Lua that contains various helper methods and actions that can be easily re-used. The code, as the name suggests, is running inside HAProxy Lua and utilizes some of its Lua API functions.

# Usage

You must include the library in your script, for example:

```
local utils = require("utils")

function is_nil(value)
    return utils.is_nil(value)
end
```

# Hall of fame

Projects that depend on this library include, but not only:

[DNSBL for HAProxy Lua](https://github.com/dobrevit/haproxy-lua-dnsbl)
