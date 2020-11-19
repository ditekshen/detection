import "pe"

rule INDICATOR_KB_CERT_56203db039adbd6094b6a142c5e50587 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "e438c77483ecab0ff55cc31f2fd2f835958fad80"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Bccabdacabbdcda" and
            pe.signatures[i].serial == "56:20:3d:b0:39:ad:bd:60:94:b6:a1:42:c5:e5:05:87"
        )
}

rule INDICATOR_KB_CERT_b5f34b7c326c73c392b515eb4c2ec80e {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "9d35805d6311fd2fe6c49427f55f0b4e2836bbc5"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Cdaadbffbaedaabbdedfdbfebf" and
            pe.signatures[i].serial == "b5:f3:4b:7c:32:6c:73:c3:92:b5:15:eb:4c:2e:c8:0e"
        )
}

rule INDICATOR_KB_CERT_0a1dc99e4d5264c45a5090f93242a30a {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "17680b1ebaa74f94272957da11e914a3a545f16f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "K & D KOMPANI d.o.o." and
            pe.signatures[i].serial == "0a:1d:c9:9e:4d:52:64:c4:5a:50:90:f9:32:42:a3:0a"
        )
}

rule INDICATOR_KB_CERT_0d53690631dd186c56be9026eb931ae2 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "c5d1e46a40a8200587d067814adf0bbfa09780f5"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "STA-R TOV" and
            pe.signatures[i].serial == "0d:53:69:06:31:dd:18:6c:56:be:90:26:eb:93:1a:e2"
        )
}

rule INDICATOR_KB_CERT_fd8c468cc1b45c9cfb41cbd8c835cc9e {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "08fc56a14dcdc9e67b9a890b65064b8279176057"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Pivo ZLoun s.r.o." and
            pe.signatures[i].serial == "fd:8c:46:8c:c1:b4:5c:9c:fb:41:cb:d8:c8:35:cc:9e"
        )
}

rule INDICATOR_KB_CERT_32fbf8cfa43dca3f85efabe96dfefa49 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "498d63bf095195828780dba7b985b71ab08e164f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Foxstyle LLC" and
            pe.signatures[i].serial == "32:fb:f8:cf:a4:3d:ca:3f:85:ef:ab:e9:6d:fe:fa:49"
        )
}

rule INDICATOR_KB_CERT_7e0ccda0ef37acef6c2ebe4538627e5c {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "a758d6799e218dd66261dc5e2e21791cbcccd6cb"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Orangetree B.V." and
            pe.signatures[i].serial == "7e:0c:cd:a0:ef:37:ac:ef:6c:2e:be:45:38:62:7e:5c"
        )
}

rule INDICATOR_KB_CERT_0095e5793f2abe0b4ec9be54fd24f76ae5 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "6acdfee2a1ab425b7927d0ffe6afc38c794f1240"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Kommservice LLC" and
            pe.signatures[i].serial == "00:95:e5:79:3f:2a:be:0b:4e:c9:be:54:fd:24:f7:6a:e5"
        )
}

rule INDICATOR_KB_CERT_00c167f04b338b1e8747b92c2197403c43 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "7af7df92fa78df96d83b3c0fd9bee884740572f9"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FORTUNE STAR TRADING, INC." and
            pe.signatures[i].serial == "00:c1:67:f0:4b:33:8b:1e:87:47:b9:2c:21:97:40:3c:43"
        )
}

rule INDICATOR_KB_CERT_00fc7065abf8303fb472b8af85918f5c24 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "b61a6607154d27d64de35e7529cb853dcb47f51f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DIG IN VISION SP Z O O" and
            pe.signatures[i].serial == "00:fc:70:65:ab:f8:30:3f:b4:72:b8:af:85:91:8f:5c:24"
        )
}

rule INDICATOR_KB_CERT_00b61b8e71514059adc604da05c283e514 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "67ee69f380ca62b28cecfbef406970ddd26cd9be"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "APP DIVISION ApS" and
            pe.signatures[i].serial == "00:b6:1b:8e:71:51:40:59:ad:c6:04:da:05:c2:83:e5:14"
        )
}

rule INDICATOR_KB_CERT_51cd5393514f7ace2b407c3dbfb09d8d {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "07a9fd6af84983dbf083c15983097ac9ce761864"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "APPI CZ a.s" and
            pe.signatures[i].serial == "51:cd:53:93:51:4f:7a:ce:2b:40:7c:3d:bf:b0:9d:8d"
        )
}

rule INDICATOR_KB_CERT_030012f134e64347669f3256c7d050c5 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "959caa354b28892608ab1bb9519424c30bebc155"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Futumarket LLC" and
            pe.signatures[i].serial == "03:00:12:f1:34:e6:43:47:66:9f:32:56:c7:d0:50:c5"
        )
}

rule INDICATOR_KB_CERT_00b7f19b13de9bee8a52ff365ced6f67fa {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "61708a3a2bae5343ff764de782d7f344151f2b74"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ALEXIS SECURITY GROUP, LLC" and
            pe.signatures[i].serial == "00:b7:f1:9b:13:de:9b:ee:8a:52:ff:36:5c:ed:6f:67:fa"
        )
}

rule INDICATOR_KB_CERT_4c8def294478b7d59ee95c61fae3d965 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = ""
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DREAM SECURITY USA INC" and
            pe.signatures[i].serial == "4c:8d:ef:29:44:78:b7:d5:9e:e9:5c:61:fa:e3:d9:65"
        )
}

rule INDICATOR_KB_CERT_0a23b660e7322e54d7bd0e5acc890966 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "c1e0c6dc2bc8ea07acb0f8bdb09e6a97ae91e57c"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ARTBUD RADOM SP Z O O" and
            pe.signatures[i].serial == "0a:23:b6:60:e7:32:2e:54:d7:bd:0e:5a:cc:89:09:66"
        )
}

rule INDICATOR_KB_CERT_04332c16724ffeda5868d22af56aea43 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "cba350fe1847a206580657758ad6813a9977c40e"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Bespoke Software Solutions Limited" and
            pe.signatures[i].serial == "04:33:2c:16:72:4f:fe:da:58:68:d2:2a:f5:6a:ea:43"
        )
}

rule INDICATOR_KB_CERT_085b70224253486624fc36fa658a1e32 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "36834eaf0061cc4b89a13e019eccc6e598657922"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Best Fud, OOO" and
            pe.signatures[i].serial == "08:5b:70:22:42:53:48:66:24:fc:36:fa:65:8a:1e:32"
        )
}

rule INDICATOR_KB_CERT_0086e5a9b9e89e5075c475006d0ca03832 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "76f6c507e0bcf7c6b881f117936f5b864a3bd3f8"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BlueMarble GmbH" and
            pe.signatures[i].serial == "00:86:e5:a9:b9:e8:9e:50:75:c4:75:00:6d:0c:a0:38:32"
        )
}

rule INDICATOR_KB_CERT_039668034826df47e6207ec9daed57c3 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "f98bdfa941ebfa2fe773524e0f9bbe9072873c2f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "CHOO FSP, LLC" and
            pe.signatures[i].serial == "03:96:68:03:48:26:df:47:e6:20:7e:c9:da:ed:57:c3"
        )
}

rule INDICATOR_KB_CERT_736dcfd309ea4c3bea23287473ffe071 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "8bfc13bf01e98e5b38f8f648f0f843b63af03f55"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ESTELLA, OOO" and
            pe.signatures[i].serial == "73:6d:cf:d3:09:ea:4c:3b:ea:23:28:74:73:ff:e0:71"
        )
}

rule INDICATOR_KB_CERT_09c89de6f64a7fdf657e69353c5fdd44 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "7ad763dfdaabc1c5a8d1be582ec17d4cdcbd1aeb"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "EXON RENTAL SP Z O O" and
            pe.signatures[i].serial == "09:c8:9d:e6:f6:4a:7f:df:65:7e:69:35:3c:5f:dd:44"
        )
}

rule INDICATOR_KB_CERT_03b630f9645531f8868dae8ac0f8cfe6 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "ab027825daf46c5e686e4d9bc9c55a5d8c5e957d"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Geksan LLC" and
            pe.signatures[i].serial == "03:b6:30:f9:64:55:31:f8:86:8d:ae:8a:c0:f8:cf:e6"
        )
}

rule INDICATOR_KB_CERT_020bc03538fbdc792f39d99a24a81b97 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "0ab2629e4e721a65ad35758d1455c1202aa643d3"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "GLOBAL PARK HORIZON SP Z O O" and
            pe.signatures[i].serial == "02:0b:c0:35:38:fb:dc:79:2f:39:d9:9a:24:a8:1b:97"
        )
}

rule INDICATOR_KB_CERT_4e8d4fc7d9f38aca1169fbf8ef2aaf50 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "7239764d40118fc1574a0af77a34e369971ddf6d"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "INFINITE PROGRAMMING LIMITED" and
            pe.signatures[i].serial == "4e:8d:4f:c7:d9:f3:8a:ca:11:69:fb:f8:ef:2a:af:50"
        )
}

rule INDICATOR_KB_CERT_09830675eb483e265c3153f0a77c3de9 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "1bb5503a2e1043616b915c4fce156c34304505d6"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "James LTH d.o.o." and
            pe.signatures[i].serial == "09:83:06:75:eb:48:3e:26:5c:31:53:f0:a7:7c:3d:e9"
        )
}

rule INDICATOR_KB_CERT_351fe2efdc0ac56a0c822cf8 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "4230bca4b7e4744058a7bb6e355346ff0bbeb26f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Logika OOO" and
            pe.signatures[i].serial == "35:1f:e2:ef:dc:0a:c5:6a:0c:82:2c:f8"
        )
}

rule INDICATOR_KB_CERT_07bb6a9d1c642c5973c16d5353b17ca4 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "9de562e98a5928866ffc581b794edfbc249a2a07"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MADAS d.o.o." and
            pe.signatures[i].serial == "07:bb:6a:9d:1c:64:2c:59:73:c1:6d:53:53:b1:7c:a4"
        )
}

rule INDICATOR_KB_CERT_044e05bb1a01a1cbb50cfb6cd24e5d6b {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "149b7bbe88d4754f2900c88516ce97be605553ff"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MUSTER PLUS SP Z O O" and
            pe.signatures[i].serial == "04:4e:05:bb:1a:01:a1:cb:b5:0c:fb:6c:d2:4e:5d:6b"
        )
}

rule INDICATOR_KB_CERT_0c14b611a44a1bae0e8c7581651845b6 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "c3288c7fbb01214c8f2dc3172c3f5c48f300cb8b"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "NEEDCODE SP Z O O" and
            pe.signatures[i].serial == "0c:14:b6:11:a4:4a:1b:ae:0e:8c:75:81:65:18:45:b6"
        )
}

rule INDICATOR_KB_CERT_0b1926a5e8ae50a0efa504f005f93869 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "2052ed19dcb0e3dfff71d217be27fc5a11c0f0d4"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Nordkod LLC" and
            pe.signatures[i].serial == "0b:19:26:a5:e8:ae:50:a0:ef:a5:04:f0:05:f9:38:69"
        )
}

rule INDICATOR_KB_CERT_0bab6a2aa84b495d9e554a4c42c0126d {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "230614366ddac05c9120a852058c24fa89972535"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "NOSOV SP Z O O" and
            pe.signatures[i].serial == "0b:ab:6a:2a:a8:4b:49:5d:9e:55:4a:4c:42:c0:12:6d"
        )
}

rule INDICATOR_KB_CERT_066226cf6a4d8ae1100961a0c5404ff9 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "8c762918a58ebccb1713720c405088743c0d6d20"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO MEP" and
            pe.signatures[i].serial == "06:62:26:cf:6a:4d:8a:e1:10:09:61:a0:c5:40:4f:f9"
        )
}

rule INDICATOR_KB_CERT_0e96837dbe5f4548547203919b96ac27 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "d6c6a0a4a57af645c9cad90b57c696ad9ad9fcf9"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PLAN CORP PTY LTD" and
            pe.signatures[i].serial == "0e:96:83:7d:be:5f:45:48:54:72:03:91:9b:96:ac:27"
        )
}

rule INDICATOR_KB_CERT_5b320a2f46c99c1ba1357bee {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "5ae8bd51ffa8e82f8f3d8297c4f9caf5e30f425a"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "REGION TOURISM LLC" and
            pe.signatures[i].serial == "5b:32:0a:2f:46:c9:9c:1b:a1:35:7b:ee"
        )
}

rule INDICATOR_KB_CERT_02c5351936abe405ac760228a40387e8 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "1174c2affb0a364c1b7a231168cfdda5989c04c5"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "RESURS-RM OOO" and
            pe.signatures[i].serial == "02:c5:35:19:36:ab:e4:05:ac:76:02:28:a4:03:87:e8"
        )
}

rule INDICATOR_KB_CERT_08d4352185317271c1cec9d05c279af7 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "52fe4ecd6c925e89068fee38f1b9a669a70f8bab"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Retalit LLC" and
            pe.signatures[i].serial == "08:d4:35:21:85:31:72:71:c1:ce:c9:d0:5c:27:9a:f7"
        )
}

rule INDICATOR_KB_CERT_0ed8ade5d73b73dade6943d557ff87e5 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "9bbd8476bf8b62be738437af628d525895a2c9c9"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Rumikon LLC" and
            pe.signatures[i].serial == "0e:d8:ad:e5:d7:3b:73:da:de:69:43:d5:57:ff:87:e5"
        )
}

rule INDICATOR_KB_CERT_0ed1847a2ae5d71def1e833fddd33d38 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "e611a7d4cd6bb8650e1e670567ac99d0bf24b3e8"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SNAB-RESURS, OOO" and
            pe.signatures[i].serial == "0e:d1:84:7a:2a:e5:d7:1d:ef:1e:83:3f:dd:d3:3d:38"
        )
}

rule INDICATOR_KB_CERT_0292c7d574132ba5c0441d1c7ffcb805 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "d0ae777a34d4f8ce6b06755c007d2d92db2a760c"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TES LOGISTIKA d.o.o." and
            pe.signatures[i].serial == "02:92:c7:d5:74:13:2b:a5:c0:44:1d:1c:7f:fc:b8:05"
        )
}

rule INDICATOR_KB_CERT_028d50ae0c554b49148e82db5b1c2699 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "0abdbc13639c704ff325035439ea9d20b08bc48e"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VAS CO PTY LTD" and
            pe.signatures[i].serial == "02:8d:50:ae:0c:55:4b:49:14:8e:82:db:5b:1c:26:99"
        )
}

rule INDICATOR_KB_CERT_0ca41d2d9f5e991f49b162d584b0f386 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "23250aa8e1b8ae49a64d09644db3a9a65f866957"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VB CORPORATE PTY. LTD." and
            pe.signatures[i].serial == "0c:a4:1d:2d:9f:5e:99:1f:49:b1:62:d5:84:b0:f3:86"
        )
}

rule INDICATOR_KB_CERT_1389c8373c00b792207bca20aa40aa40 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "38f65d64ac93f080b229ab83cb72619b0754fa6f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VITA-DE d.o.o." and
            pe.signatures[i].serial == "13:89:c8:37:3c:00:b7:92:20:7b:ca:20:aa:40:aa:40"
        )
}

rule INDICATOR_KB_CERT_a596fd2779e507aa466d159706fe4150 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "104c4183e248d63a6e2ad6766927b070c81afcb6"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ClamAV" and
            pe.signatures[i].serial == "a5:96:fd:27:79:e5:07:aa:46:6d:15:97:06:fe:41:50"
        )
}

rule INDICATOR_KB_CERT_45d76c63929c4620ab706772f5907f82 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "67c4afae16e5e2f98fe26b4597365b3cfed68b58"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "NEON CRAYON LIMITED" and
            pe.signatures[i].serial == "45:d7:6c:63:92:9c:46:20:ab:70:67:72:f5:90:7f:82"
        )
}

rule INDICATOR_KB_CERT_5029daca439511456d9ed8153703f4bc {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "9d5ded35ffd34aa78273f0ebd4d6fa1e5337ac2b"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "THE GREEN PARTNERSHIP LTD" and
            pe.signatures[i].serial == "50:29:da:ca:43:95:11:45:6d:9e:d8:15:37:03:f4:bc"
        )
}

rule INDICATOR_KB_CERT_1c7d3f6e116554809f49ce16ccb62e84 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = ""
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "1549 LIMITED" and
            pe.signatures[i].serial == "1c:7d:3f:6e:11:65:54:80:9f:49:ce:16:cc:b6:2e:84"
        )
}

rule INDICATOR_KB_CERT_75522215406335725687af888dcdc80c {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = ""
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "THEESOLUTIONS LTD" and 
            pe.signatures[i].serial == "75:52:22:15:40:63:35:72:56:87:af:88:8d:cd:c8:0c"
        )
}

rule INDICATOR_KB_CERT_768ddcf9ed8d16a6bc77451ee88dfd90 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = ""
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "THEESOLUTIONS LTD" and 
            pe.signatures[i].serial == "76:8d:dc:f9:ed:8d:16:a6:bc:77:45:1e:e8:8d:fd:90"
        )
}

rule INDICATOR_KB_CERT_59e378994cf1c0022764896d826e6bb8 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "9a17d31e9191644945e920bc1e7e08fbd00b62f4"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SEVA MEDICAL LTD" and
            pe.signatures[i].serial == "59:e3:78:99:4c:f1:c0:02:27:64:89:6d:82:6e:6b:b8"
        )
}

rule INDICATOR_KB_CERT_033ed5eda065d1b8c91dfcf92a6c9bd8 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "c91dcecb3a92a17b063059200b20f5ce251b5a95"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Python Software Foundation" and
            pe.signatures[i].serial == "03:3e:d5:ed:a0:65:d1:b8:c9:1d:fc:f9:2a:6c:9b:d8"
        )
}

rule INDICATOR_KB_CERT_3d2580e89526f7852b570654efd9a8bf {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "c1b4d57a36e0b6853dd38e3034edf7d99a8b73ad"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MIKL LIMITED" and
            pe.signatures[i].serial == "3d:25:80:e8:95:26:f7:85:2b:57:06:54:ef:d9:a8:bf"
        )
}

rule INDICATOR_KB_CERT_5da173eb1ac76340ac058e1ff4bf5e1b {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "acb38d45108c4f0c8894040646137c95e9bb39d8"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ALISA LTD" and
            pe.signatures[i].serial == "5d:a1:73:eb:1a:c7:63:40:ac:05:8e:1f:f4:bf:5e:1b"
        )
}

rule INDICATOR_KB_CERT_378d5543048e583a06a0819f25bd9e85 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "cf933a629598e5e192da2086e6110ad1974f8ec3"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "KITTY'S LTD" and
            pe.signatures[i].serial == "37:8d:55:43:04:8e:58:3a:06:a0:81:9f:25:bd:9e:85"
        )
}

rule INDICATOR_KB_CERT_0c5396dcb2949c70fac48ab08a07338e {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "b6b24aea9e983ed6bda9586a145a7ddd7e220196"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Mozilla Corporation" and
            pe.signatures[i].serial == "0c:53:96:dc:b2:94:9c:70:fa:c4:8a:b0:8a:07:33:8e"
        )
}

rule INDICATOR_KB_CERT_fdb6f4c09a1ad69d4fd2e46bb1f54313 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "4d1bc69003b1b1c3d0b43f6c17f81d13e0846ea7"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FDSMMCME" and
            pe.signatures[i].serial == "fd:b6:f4:c0:9a:1a:d6:9d:4f:d2:e4:6b:b1:f5:43:13"
        )
}

rule INDICATOR_KB_CERT_e5bf5b5c0880db96477c24c18519b9b9 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = ""
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "WATWGHFC" and
            pe.signatures[i].serial == "e5:bf:5b:5c:08:80:db:96:47:7c:24:c1:85:19:b9:b9"
        )
}

rule INDICATOR_KB_CERT_00ede6cfbf9fa18337b0fdb49c1f693020 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "a99b52e0999990c2eb24d1309de7d4e522937080"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "START ARCHITECTURE LTD" and
            pe.signatures[i].serial == "00:ed:e6:cf:bf:9f:a1:83:37:b0:fd:b4:9c:1f:69:30:20"
        )
}

rule INDICATOR_KB_CERT_4f407eb50803845cc43937823e1344c0 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "0c1ffe7df27537a3dccbde6f7a49e38c4971e852"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SLOW COOKED VENTURES LTD" and
            pe.signatures[i].serial == "4f:40:7e:b5:08:03:84:5c:c4:39:37:82:3e:13:44:c0"
        )
}

rule INDICATOR_KB_CERT_20a20dfce424e6bbcc162a5fcc0972ee {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "1d25a769f7ff0694d333648acea3f18b323bc9f1"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TeamViewer GmbH" and
            pe.signatures[i].serial == "20:a2:0d:fc:e4:24:e6:bb:cc:16:2a:5f:cc:09:72:ee"
        )
}

rule INDICATOR_KB_CERT_2bffef48e6a321b418041310fdb9b0d0 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "c40c5157e96369ceb7e26e756f2d1372128cee7b"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "A&D DOMUS LIMITED" and
            pe.signatures[i].serial == "2b:ff:ef:48:e6:a3:21:b4:18:04:13:10:fd:b9:b0:d0"
        )
}

rule INDICATOR_KB_CERT_73b60719ee57974447c68187e49969a2 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "8e50ddad9fee70441d9eb225b3032de4358718dc"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BIT HORIZON LIMITED" and
            pe.signatures[i].serial == "73:b6:07:19:ee:57:97:44:47:c6:81:87:e4:99:69:a2"
        )
}

rule INDICATOR_KB_CERT_2925263b65c7fe1cd47b0851cc6951e3 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "88ef10f0e160b1b4bb8f0777a012f6b30ac88ac8"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "tuning buddy limited" and
            pe.signatures[i].serial == "29:25:26:3b:65:c7:fe:1c:d4:7b:08:51:cc:69:51:e3"
        )
}

rule INDICATOR_KB_CERT_4ff4eda5fa641e70162713426401f438 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "a6277cc8fce0f90a1909e6dac8b02a5115dafb40"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DUHANEY LIMITED" and
            pe.signatures[i].serial == "4f:f4:ed:a5:fa:64:1e:70:16:27:13:42:64:01:f4:38"
        )
}

rule INDICATOR_KB_CERT_04c7cdcc1698e25b493eb4338d5e2f8b {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "60974f5cc654e6f6c0a7332a9733e42f19186fbb"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "3AN LIMITED" and
            pe.signatures[i].serial == "04:c7:cd:cc:16:98:e2:5b:49:3e:b4:33:8d:5e:2f:8b"
        )
}

rule INDICATOR_KB_CERT_4c450eccd61d334e0afb2b2d9bb1d812 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "4c450eccd61d334e0afb2b2d9bb1d812"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ANJELA KEY LIMITED" and
            pe.signatures[i].serial == "4c:45:0e:cc:d6:1d:33:4e:0a:fb:2b:2d:9b:b1:d8:12"
        )
}

rule INDICATOR_KB_CERT_0e1bacb85e77d355ea69ba0b {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "6750c9224540d7606d3c82c7641f49147c1b3fd0"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BULDOK LIMITED" and
            pe.signatures[i].serial == "0e:1b:ac:b8:5e:77:d3:55:ea:69:ba:0b"
        )
}

rule INDICATOR_KB_CERT_5998b4affe2adf592e6528ff800e567c {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "d990d584c856bd28eab641c3c3a0f80c0b71c4d7"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BEAT GOES ON LIMITED" and
            pe.signatures[i].serial == "59:98:b4:af:fe:2a:df:59:2e:65:28:ff:80:0e:56:7c"
        )
}

rule INDICATOR_KB_CERT_00b7e0cf12e4ae50dd643a24285485602f {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "744160f36ba9b0b9277c6a71bf383f1898fd6d89"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "GESO LTD" and
            pe.signatures[i].serial == "00:b7:e0:cf:12:e4:ae:50:dd:64:3a:24:28:54:85:60:2f"
        )
}

rule INDICATOR_KB_CERT_767436921b2698bd18400a24b01341b6 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "871899843b5fd100466e351ca773dac44e936939"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "REBROSE LEISURE LIMITED" and
            pe.signatures[i].serial == "76:74:36:92:1b:26:98:bd:18:40:0a:24:b0:13:41:b6"
        )
}

rule INDICATOR_KB_CERT_26b125e669e77a5e58db378e9816fbc3 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "900aa9e6ff07c6528ecd71400e6404682e812017"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FLOWER DELI LTD" and
            pe.signatures[i].serial == "26:b1:25:e6:69:e7:7a:5e:58:db:37:8e:98:16:fb:c3"
        )
}

rule INDICATOR_KB_CERT_29a248a77d5d4066fe5da75f32102bb5 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "1078c0ab5766a48b0d4e04e57f3ab65b68dd797f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SUN & STARZ LIMITED" and
            pe.signatures[i].serial == "29:a2:48:a7:7d:5d:40:66:fe:5d:a7:5f:32:10:2b:b5"
        )
}

rule INDICATOR_KB_CERT_3a9bdec10e00e780316baaebfe7a772c {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "981b95ffcb259862e7461bc58516d7785de91a8a"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PLAN ALPHA LIMITED" and
            pe.signatures[i].serial == "3a:9b:de:c1:0e:00:e7:80:31:6b:aa:eb:fe:7a:77:2c"
        )
}

rule INDICATOR_KB_CERT_73f9819f3a1a49bac1e220d7f3e0009b {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "bb04986cbd65f0994a544f197fbb26abf91228d9"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Jean Binquet" and
            pe.signatures[i].serial == "73:f9:81:9f:3a:1a:49:ba:c1:e2:20:d7:f3:e0:00:9b"
        )
}

rule INDICATOR_KB_CERT_0989c97804c93ec0004e2843 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "98549ae51b7208bda60b7309b415d887c385864b"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Shanghai Hintsoft Co., Ltd." and
            pe.signatures[i].serial == "09:89:c9:78:04:c9:3e:c0:00:4e:28:43"
        )
}

rule INDICATOR_KB_CERT_6ba32f984444ea464bea41d99a977ea8 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "ae9e65e26275d014a4a8398569af5eeddf7a472c"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "JIN CONSULTANCY LIMITED" and
            pe.signatures[i].serial == "6b:a3:2f:98:44:44:ea:46:4b:ea:41:d9:9a:97:7e:a8"
        )
}

rule INDICATOR_KB_CERT_4f5a9bf75da76b949645475473793a7d {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "f7de21bbdf5effb0f6739d505579907e9f812e6f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "EXEC CONTROL LIMITED" and
            pe.signatures[i].serial == "4f:5a:9b:f7:5d:a7:6b:94:96:45:47:54:73:79:3a:7d"
        )
}

rule INDICATOR_KB_CERT_68b050aa3d2c16f77e14a16dc8d1c1ac {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "c757e09e7dc5859dbd00b0ccfdd006764c557a3d"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SLOW POKE LTD" and
            pe.signatures[i].serial == "68:b0:50:aa:3d:2c:16:f7:7e:14:a1:6d:c8:d1:c1:ac"
        )
}

rule INDICATOR_KB_CERT_0f2b44e398ba76c5f57779c41548607b {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "cef53e9ca954d1383a8ece037925aa4de9268f3f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DIGITAL DR" and
            pe.signatures[i].serial == "0f:2b:44:e3:98:ba:76:c5:f5:77:79:c4:15:48:60:7b"
        )
}

rule INDICATOR_KB_CERT_5ad4ce116b131daf8d784c6fab2ea1f1 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "de2dad893fdd49d7c0d498c0260acfb272588a2b"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ORDARA LTD" and
            pe.signatures[i].serial == "5a:d4:ce:11:6b:13:1d:af:8d:78:4c:6f:ab:2e:a1:f1"
        )
}

rule INDICATOR_KB_CERT_48ce01ac7e137f4313cc5723af817da0 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "8f594f2e0665ffd656160aac235d8c490059a9cc"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ET HOMES LTD" and
            pe.signatures[i].serial == "48:ce:01:ac:7e:13:7f:43:13:cc:57:23:af:81:7d:a0"
        )
}

rule INDICATOR_KB_CERT_c7e62986c36246c64b8c9f2348141570 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "f779e06266802b395ef6d3dbfeb1cc6a0a2cfc47"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "LLC Mail.Ru" and
            pe.signatures[i].serial == "c7:e6:29:86:c3:62:46:c6:4b:8c:9f:23:48:14:15:70"
        )
}

rule INDICATOR_KB_CERT_731d40ae3f3a1fb2bc3d8395 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "b3df816a17a25557316d181ddb9f46254d6d8ca0"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "win.rar GmbH" and
            pe.signatures[i].serial == "73:1d:40:ae:3f:3a:1f:b2:bc:3d:83:95"
        )
}

rule INDICATOR_KB_CERT_00ee663737d82df09c7038a6a6693a8323 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "dc934afe82adbab8583e393568f81ab32c79aeea"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "KREACIJA d.o.o." and
            pe.signatures[i].serial == "00:ee:66:37:37:d8:2d:f0:9c:70:38:a6:a6:69:3a:83:23"
        )
}

rule INDICATOR_KB_CERT_3d568325dec56abf48e72317675cacb7 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "e5b21024907c9115dafccc3d4f66982c7d5641bc"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Virtual Byte F-B-I" and
            pe.signatures[i].serial == "3d:56:83:25:de:c5:6a:bf:48:e7:23:17:67:5c:ac:b7"
        )
}

rule INDICATOR_KB_CERT_0232466dc95b40ec9d21d9329abfcd5d {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "fb845245cfbb0ee97e76c775348caa31d74bec4c"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Martin Prikryl" and
            pe.signatures[i].serial == "02:32:46:6d:c9:5b:40:ec:9d:21:d9:32:9a:bf:cd:5d"
        )
}

rule INDICATOR_KB_CERT_3533080b377f80c0ea826b2492bf767b {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "2afcc4cdee842d80bf7b6406fb503957c8a09b4d"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE5\\xA8\\x9C\\xE8\\xBF\\xAA\\xD0\\x91\\xE8\\xBF\\xAA\\xD0\\x91\\xE5\\xA8\\x9C\\xE5\\x93\\xA6\\xE5\\xB0\\xBA\\xE5\\x8B\\x92\\xE5\\x8B\\x92\\xD0\\x91\\xE8\\xBF\\xAA\\xD0\\x91\\xE5\\xB0\\xBA\\xE5\\xB0\\xBA\\xE8\\xBF\\xAA\\xE5\\x93\\xA6\\xE8\\xBF\\xAA\\xE5\\x8B\\x92\\xD0\\x91\\xE5\\x8B\\x92\\xE5\\x93\\xA6\\xE5\\x8B\\x92\\xE5\\x93\\xA6\\xD0\\x91" and
            pe.signatures[i].serial == "35:33:08:0b:37:7f:80:c0:ea:82:6b:24:92:bf:76:7b"
        )
}

rule INDICATOR_KB_CERT_00b0ecd32f95f8761b8a6d5710c7f34590 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "2e25e7e8abc238b05de5e2a482e51ed324fbaa76"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE6\\x96\\xAF\\xD0\\xA8\\xD0\\xA8\\xE5\\xBC\\x97\\xE6\\xAF\\x94\\xE5\\xBC\\x97\\xD0\\xA8\\xE6\\xAF\\x94\\xD0\\xA8\\xE5\\xBC\\x97\\xD0\\xA8\\xE5\\xB0\\x94\\xE5\\xBC\\x97\\xE5\\xBC\\x97\\xD0\\xA8\\xE5\\xB0\\x94\\xD0\\xA8\\xE6\\x96\\xAF\\xE5\\xB0\\x94\\xE5\\xBC\\x97" and
            pe.signatures[i].serial == "00:b0:ec:d3:2f:95:f8:76:1b:8a:6d:57:10:c7:f3:45:90"
        )
}

rule INDICATOR_KB_CERT_3a727248e1940c5bf91a466b29c3b9cd {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "eeeb3a616bb50138f84fc0561d883b47ac1d3d3d"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE5\\x90\\x89\\xE5\\x90\\x89\\xD0\\x98\\xE5\\x90\\x89\\xD0\\x98\\xE4\\xB8\\x9D\\xE4\\xB8\\x9D" and
            pe.signatures[i].serial == "3a:72:72:48:e1:94:0c:5b:f9:1a:46:6b:29:c3:b9:cd"
        )
}

rule INDICATOR_KB_CERT_00ce40906451925405d0f6c130db461f71 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "af79bbdb4fa0724f907343e9b1945ffffb34e9b3"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE8\\x89\\xBE\\xE6\\x9D\\xB0\\xE8\\x89\\xBE\\xD0\\xA5\\xE7\\xBB\\xB4\\xE6\\x9D\\xB0\\xE6\\x96\\xAF\\xE6\\x96\\xAF\\xE7\\xBB\\xB4\\xE6\\x9D\\xB0\\xE6\\x9D\\xB0\\xD0\\xA5\\xE6\\x96\\xAF\\xD0\\xA5\\xD0\\xA5\\xE6\\x96\\xAF\\xE6\\x9D\\xB0\\xE6\\x9D\\xB0\\xE8\\x89\\xBE\\xE6\\x9D\\xB0\\xE6\\x9D\\xB0\\xE8\\x89\\xBE\\xE6\\x9D\\xB0\\xE6\\x96\\xAF\\xE6\\x9D\\xB0" and
            pe.signatures[i].serial == "00:ce:40:90:64:51:92:54:05:d0:f6:c1:30:db:46:1f:71"
        )
}

rule INDICATOR_KB_CERT_00e130d3537e0b7a4dda47b4d6f95f9481 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "89f9786c8cb147b1dd7aa0eb871f51210550c6f4"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE4\\xBC\\x8A\\xE6\\x96\\xAF\\xE8\\x89\\xBE\\xE4\\xBC\\x8A\\xE8\\x89\\xBE\\xE8\\x89\\xBE\\xE5\\x90\\xBE\\xE5\\x90\\xBE\\xE5\\x8B\\x92\\xE5\\x8B\\x92\\xE5\\x8B\\x92\\xE5\\x8B\\x92" and
            pe.signatures[i].serial == "00:e1:30:d3:53:7e:0b:7a:4d:da:47:b4:d6:f9:5f:94:81"
        )
}

rule INDICATOR_KB_CERT_4bec555c48aada75e83c09c9ad22dc7c {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "a2be2ab16e3020ddbff1ff37dbfe2d736be7a0d5"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xD0\\x92\\xE5\\xB1\\x81\\xE5\\xB0\\x94\\xE5\\x90\\xBE\\xD0\\x92\\xE5\\x90\\x89\\xE5\\xB0\\x94\\xE5\\x90\\xBE\\xD0\\x92\\xE4\\xB8\\x9D\\xE5\\xB1\\x81" and
            pe.signatures[i].serial == "4b:ec:55:5c:48:aa:da:75:e8:3c:09:c9:ad:22:dc:7c"
        )
}

rule INDICATOR_KB_CERT_009356e0361bcf983ab14276c332f814e7 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "f8bc145719666175a2bb3fcc62e0f3b2deccb030"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE8\\x89\\xBE\\xE5\\x90\\x89\\xE4\\xB8\\x9D\\xE6\\x9D\\xB0\\xE8\\x89\\xBE\\xE4\\xB8\\x9D\\xE6\\x9D\\xB0\\xE8\\x89\\xBE\\xE6\\x9D\\xB0\\xE4\\xB8\\x9D\\xE4\\xBC\\x8A\\xE6\\x9D\\xB0\\xE5\\x90\\x89\\xE4\\xBC\\x8A" and
            pe.signatures[i].serial == "00:93:56:e0:36:1b:cf:98:3a:b1:42:76:c3:32:f8:14:e7"
        )
}

rule INDICATOR_KB_CERT_00e5d20477e850c9f35c5c47123ef34271 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "d11431836db24dcc3a17de8027ab284a035f2e4f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE8\\x89\\xBE\\xD0\\x92\\xE5\\xBE\\xB7\\xE8\\x89\\xBE\\xE5\\x8B\\x92\\xD0\\x92\\xE8\\xB4\\x9D\\xE8\\x89\\xBE\\xE5\\xBE\\xB7\\xD0\\x92\\xE8\\x89\\xBE\\xD0\\x92\\xD0\\x92\\xE8\\x89\\xBE\\xD0\\x92\\xE8\\xB4\\x9D\\xE5\\x8B\\x92\\xD0\\x92\\xE5\\xBE\\xB7\\xE8\\xB4\\x9D\\xD0\\x92\\xD0\\x92\\xE8\\x89\\xBE\\xD0\\x92" and
            pe.signatures[i].serial == "00:e5:d2:04:77:e8:50:c9:f3:5c:5c:47:12:3e:f3:42:71"
        )
}

rule INDICATOR_KB_CERT_00c865d49345f1ed9a84bea40743cdf1d7 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "d5e8afa85c6bf68d31af4a04668c3391e48b24b7"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE5\\xB0\\x94\\xE5\\x93\\xA6\\xD0\\x93\\xE8\\x89\\xBE\\xE5\\xB1\\x81\\xE5\\xB1\\x81\\xE5\\x93\\xA6\\xE5\\xB1\\x81\\xE5\\x93\\xA6\\xE7\\xBB\\xB4\\xE5\\x93\\xA6\\xE8\\x89\\xBE\\xE5\\xB0\\x94\\xE8\\x89\\xBE" and
            pe.signatures[i].serial == "00:c8:65:d4:93:45:f1:ed:9a:84:be:a4:07:43:cd:f1:d7"
        )
}

rule INDICATOR_KB_CERT_29f2093e925b7fe70a9ba7b909415251 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "f9fc647988e667ec92bdf1043ea1077da8f92ccc"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xD0\\x99\\xE4\\xB8\\x9D\\xE4\\xBC\\x8A\\xE5\\x85\\x8B\\xD0\\x99\\xE8\\x89\\xBE\\xE8\\x89\\xBE\\xE5\\x85\\x8B\\xD0\\x99\\xE8\\x89\\xBE\\xE5\\x85\\x8B\\xD0\\x9D\\xD0\\x9D\\xE8\\x89\\xBE\\xE8\\x89\\xBE\\xE5\\x85\\x8B\\xE4\\xB8\\x9D\\xD0\\x99\\xE8\\x89\\xBE\\xE5\\x85\\x8B\\xD0\\x9D\\xD0\\x9D\\xE5\\x85\\x8B\\xD0\\x9D\\xD0\\x9D\\xD0\\x9D\\xE8\\x89\\xBE\\xE4\\xB8\\x9D\\xE4\\xBC\\x8A" and
            pe.signatures[i].serial == "29:f2:09:3e:92:5b:7f:e7:0a:9b:a7:b9:09:41:52:51"
        )
}

rule INDICATOR_KB_CERT_0889e4181e71b16c4a810bee38a78419 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "bce3c17815ec9f720ba9c59126ae239c9caf856d"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE5\\x8B\\x92\\xE5\\xBC\\x97\\xE4\\xBC\\x8A\\xE4\\xBC\\x8A\\xE5\\x90\\xBE\\xE4\\xBC\\x8A\\xE5\\x90\\xBE" and
            pe.signatures[i].serial == "08:89:e4:18:1e:71:b1:6c:4a:81:0b:ee:38:a7:84:19"
        )
}

rule INDICATOR_KB_CERT_00c1afabdaa1321f815cdbb9467728bc08 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "e9c5fb9a7d3aba4b49c41b45249ed20c870f5c9e"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xD0\\x92\\xD0\\x93\\xE5\\x84\\xBF\\xD0\\x93\\xE5\\x8B\\x92\\xD0\\x92\\xE5\\x8B\\x92\\xD0\\x93\\xD0\\x93\\xE5\\x84\\xBF\\xE8\\x89\\xBE\\xD0\\x92\\xD0\\x93\\xE5\\x8B\\x92\\xE5\\x8B\\x92\\xD0\\x92\\xD0\\x93\\xE8\\x89\\xBE\\xE9\\xA9\\xAC\\xD0\\x93\\xE8\\x89\\xBE\\xE9\\xA9\\xAC\\xD0\\x93" and
            pe.signatures[i].serial == "00:c1:af:ab:da:a1:32:1f:81:5c:db:b9:46:77:28:bc:08"
        )
}

rule INDICATOR_KB_CERT_371381a66fb96a07077860ae4a6721e1 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "c4419f095ae93d93e145d678ed31459506423d6a"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE7\\xBB\\xB4\\xD0\\xA9\\xE5\\x90\\xBE\\xE7\\xBB\\xB4\\xD0\\xA9\\xD0\\xA9\\xE7\\xBB\\xB4\\xE5\\x90\\xBE\\xE5\\x90\\xBE\\xE5\\xA8\\x9C\\xE5\\x90\\xBE\\xE5\\x90\\xBE\\xD0\\xA9\\xE5\\xA8\\x9C\\xE5\\x90\\xBE\\xD0\\xA9\\xE5\\xA8\\x9C\\xE6\\x9D\\xB0\\xE5\\xA8\\x9C\\xE5\\x90\\xBE\\xE5\\xA8\\x9C\\xE5\\xA8\\x9C\\xD0\\xA9" and
            pe.signatures[i].serial == "37:13:81:a6:6f:b9:6a:07:07:78:60:ae:4a:67:21:e1"
        )
}