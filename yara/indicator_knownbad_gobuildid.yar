rule INDICATOR_KB_GoBuildID_Zebrocy {
    meta:
        author = "ditekSHen"
        description = "Detects Goland Build IDs in known bad samples"       
    strings:
        $s1 = "Go build ID: \"l6RAKXh3Wg1yzn63nita/b2_Y0DGY05NFWuZ_4gUT/H91sCRktnyyYVzECfvvA/l8f-yII0L_miSjIe-VQu\"" ascii
        $s2 = "Go build ID: \"fiGGvLVFcvIhuJsSaail/jLt9TEPQiusg7IpRkp4H/hlcoXZIfsl1D4521LqEL/yL8dN86mCNc39WqQTgGn\"" ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 8000KB and 1 of them
}

rule INDICATOR_KB_GoBuildID_GoStealer {
    meta:
        author = "ditekSHen"
        description = "Detects Goland Build IDs in known bad samples"       
    strings:
        $s1 = "Go build ID: \"xQV-b1Fr7d576TTTpbXi/gq4FgVQqMcg--9tmY13y/76rKNEUBENlDFDcecmm_/mbw17A_6WrROaNCYDEQF\"" ascii
        $s2 = "Go build ID: \"x4VqrSSsx8iysxVdfB-z/gIF3p7SUxiZsVgTuq7bN/93XHuILGnGYq2L83fRpj/eoY6nTqwk1sdMHTaXzlw\"" ascii
        $s3 = "Go build ID: \"BPRThIYWbHcZQQ4K1y2t/2mO0-FjLC50P0QZuMTgC/9i6TYw_akiEF9ZPN0s3p/s1XoqXr7EyXMDVw5TTP3\"" ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 8000KB and 1 of them
}

rule INDICATOR_KB_GoBuildID_GoldenAxe {
    meta:
        author = "ditekSHen"
        description = "Detects Goland Build IDs in known bad samples"       
    strings:
        $s1 = "Go build ID: \"BrJuyMRdiZ7pC9Cah0is/rbDB__hXWimivbSGiCLi/B35SPLQwHal3ccR2gXNx/hEmVzhJWWatsrKwnENh_\"" ascii
        $s2 = "Go build ID: \"5bgieaBe9PcZCZf23WFp/bCZ0AUHYlqQmX8GJASV6/fGxRLMDDYrTm1jcLMt8j/Wof3n5634bwiwLHFKHTn\"" ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 8000KB and 1 of them
}

rule INDICATOR_KB_GoBuildID_Nemty {
    meta:
        author = "ditekSHen"
        description = "Detects Goland Build IDs in known bad samples"       
    strings:
        $s1 = "Go build ID: \"R6dvaUktgv2SjVXDoMdo/kKgwagwoLRC88DpIXAmx/eipNq7_PQCTCOhZ6Q74q/RHJkCaNdTbd6qgYiA-EC\"" ascii
        $s2 = "Go build ID: \"vsdndTwlj03gbEoDu06S/anJkXGh7N08537M0RMms/VG58d99axcdeD_z1JIko/tfDVbCdWUId-VX90kuT7\"" ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 8000KB and 1 of them
}

rule INDICATOR_KB_GoBuildID_QnapCrypt {
    meta:
        author = "ditekSHen"
        description = "Detects Goland Build IDs in known bad samples"       
    strings:
        $s1 = "Go build ID: \"XcBqbQohm7UevdYNABvs/2RcJz1616naXSRu2xvTX/b6F3Jt1-5WAIexSyzeun/MpHqs5fJA5G2D9gVuUCe\"" ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 8000KB and 1 of them
}

