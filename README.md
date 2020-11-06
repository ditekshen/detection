# Detection and Hunting Signatures

A set of interrelated network and host detection rules with the aim of improving detection and hunting visibility and context. Where applicable, each Snort rule includes metadata indicating the corresponding Yara and ClamAV rules, and each Yara signature also includes metadata to the corresponding Snort and ClamAV rules, and so on.

## Supported Rules

Currently, Snort, Yara and ClamAV rules are supported. Additional singatures and formats are work in progress.

## Rules

Additional rules and signatures will be added as they complete testing.

| Type            | Snort 2             | Snort 3             | Yara                                                 | ClamAV                                            |
|-----------------|---------------------|---------------------|------------------------------------------------------|---------------------------------------------------|
| ```INDICATOR``` | ```910000-910001``` | ```910000```        | ```INDICATOR_RTF_Ancalog_Exploit_Builder_Document``` | ```INDICATOR.RTF.AncalogExploitBuilderDocument``` |
| ```INDICATOR``` | ```910002-910003``` | ```910001```        | ```INDICATOR_RTF_Equation_BITSAdmin_Downloader```    | ```INDICATOR.RTF.EquationBITSAdminDownloader```   |
| ```MALWARE```   | ```920000-920002``` | ```920000-920002``` | ```MALWARE_Win_RevengeRAT```                         | ```MALWARE.Win.RevengeRAT```                      |
