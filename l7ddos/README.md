# Application-layer DDoS mitigation tools

This is a collection of scripts, useful for L7 (application-level) DDoS mitigation.

It's supposed that your main Tempesta FW configuration file has statement
```
!include /path/to/tempesta_ja5t_block.conf
```


## `most_impactful.py`

Find the most traffic aggressive clients and add them by
[JA5t](https://tempesta-tech.com/knowledge-base/Traffic-Filtering-by-Fingerprints/)
hashes to `tempesta_ja5t_block.conf`.
