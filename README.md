# yara-url
Module for yara that allows matching on URL components


### Example:

```c
import "url"

rule test
{
  meta:
    description = "Using the URL module to match a hostname containing 'google'
  condition:
    url.host(/google/)
}
```

