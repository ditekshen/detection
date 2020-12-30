# Detection and Hunting Signatures

A set of interrelated network and host detection rules with the aim of improving detection and hunting visibility and context. Where applicable, each Snort rule includes metadata indicating the corresponding Yara and ClamAV rules, and each Yara signature also includes metadata to the corresponding Snort and ClamAV rules, and so on.

## Supported Rules

Currently, Snort, Yara and ClamAV rules are supported. Additional singatures and formats are work in progress.

## Scripts

Currently, only scripts available are used to aid in auto-generation of hash-based and certificate-based Yara rules.
