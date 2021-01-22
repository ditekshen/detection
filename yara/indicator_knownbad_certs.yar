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

rule INDICATOR_KB_CERT_0deb004e56d7fcec1caa8f2928d4e768 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "21dacc55b6e0b3b0e761be03ed6edd713489b6ce"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "LLC Mail.Ru" and
            pe.signatures[i].serial == "0d:eb:00:4e:56:d7:fc:ec:1c:aa:8f:29:28:d4:e7:68"
        )
}

rule INDICATOR_KB_CERT_7bd36898217b4cc6b6427dd7c361e43d {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "c55df31aa16adb1013612ceb1dcf587afb7832c3"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Aeafefcafbafbaf" and
            pe.signatures[i].serial == "7b:d3:68:98:21:7b:4c:c6:b6:42:7d:d7:c3:61:e4:3d"
        )
}

rule INDICATOR_KB_CERT_02d17fbf4869f23fea43c7863902df93 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "d336ff8d8ccb771943a70bb4ba11239fb71beca5"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Microsoft Windows" and
            pe.signatures[i].serial == "02:d1:7f:bf:48:69:f2:3f:ea:43:c7:86:39:02:df:93"
        )
}

rule INDICATOR_KB_CERT_1e74cfe7de8c5f57840a61034414ca9f {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "2dfa711a12aed0ace72e538c57136fa021412f95951c319dcb331a3e529cf86e"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Insta Software Solution Inc." and
            pe.signatures[i].serial == "1e:74:cf:e7:de:8c:5f:57:84:0a:61:03:44:14:ca:9f"
        )
}

rule INDICATOR_KB_CERT_009272607cfc982b782a5d36c4b78f5e7b {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "2514c615fe54d511555bc5b57909874e48a438918a54cea4a0b3fbc401afa127"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Rada SP Z o o" and
            pe.signatures[i].serial == "00:92:72:60:7c:fc:98:2b:78:2a:5d:36:c4:b7:8f:5e:7b"
        )
}

rule INDICATOR_KB_CERT_7b91468122273aa32b7cfc80c331ea13 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "409f32dc91542546e7c7f85f687fe3f1acffdd853657c8aa8c1c985027f5271d"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO KBI" and
            pe.signatures[i].serial == "7b:91:46:81:22:27:3a:a3:2b:7c:fc:80:c3:31:ea:13"
        )
}

rule INDICATOR_KB_CERT_0082cb93593b658100cdd7a00c874287f2 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "d168d7cf7add6001df83af1fc603a459e11395a9077579abcdfd708ad7b7271f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Sportsonline24 B.V." and
            pe.signatures[i].serial == "00:82:cb:93:59:3b:65:81:00:cd:d7:a0:0c:87:42:87:f2"
        )
}

rule INDICATOR_KB_CERT_00df683d46d8c3832489672cc4e82d3d5d {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "8b63c5ea8d9e4797d77574f35d1c2fdff650511264b12ce2818c46b19929095b"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Osatokio Oy" and
            pe.signatures[i].serial == "00:df:68:3d:46:d8:c3:83:24:89:67:2c:c4:e8:2d:3d:5d"
        )
}

rule INDICATOR_KB_CERT_105440f57e9d04419f5a3e72195110e6 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "e95c7b4f2e5f64b388e968d0763da67014eb3aeb8c04bd44333ca3e151aa78c2"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "CRYPTOLAYER SRL" and
            pe.signatures[i].serial == "10:54:40:f5:7e:9d:04:41:9f:5a:3e:72:19:51:10:e6"
        )
}

rule INDICATOR_KB_CERT_c01e41ff29078e6626a640c5a19a8d80 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "cca4a461592e6adff4e0a4458ebe29ee4de5f04c638dbd3b7ee30f3519cfd7e5"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BurnAware" and
            pe.signatures[i].serial == "c0:1e:41:ff:29:07:8e:66:26:a6:40:c5:a1:9a:8d:80"
        )
}

rule INDICATOR_KB_CERT_00fa3dcac19b884b44ef4f81541184d6b0 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "6557117e37296d7fdcac23f20b57e3d52cabdb8e5aa24d3b78536379d57845be"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Unicom Ltd" and
            pe.signatures[i].serial == "00:fa:3d:ca:c1:9b:88:4b:44:ef:4f:81:54:11:84:d6:b0"
        )
}

rule INDICATOR_KB_CERT_70e1ebd170db8102d8c28e58392e5632 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "90d67006be03f2254e1da76d4ea7dc24372c4f30b652857890f9d9a391e9279c"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Equal Cash Technologies Limited" and
            pe.signatures[i].serial == "70:e1:eb:d1:70:db:81:02:d8:c2:8e:58:39:2e:56:32"
        )
}

rule INDICATOR_KB_CERT_6cfa5050c819c4acbb8fa75979688dff {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "e7241394097402bf9e32c87cada4ba5e0d1e9923f028683713c2f339f6f59fa9"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Elite Web Development Ltd." and
            pe.signatures[i].serial == "6c:fa:50:50:c8:19:c4:ac:bb:8f:a7:59:79:68:8d:ff"
        )
}

rule INDICATOR_KB_CERT_00b8164f7143e1a313003ab0c834562f1f {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "263c636c5de68f0cd2adf31b7aebc18a5e00fc47a5e2124e2a5613b9a0247c1e"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Ekitai Data Inc." and
            pe.signatures[i].serial == "00:b8:16:4f:71:43:e1:a3:13:00:3a:b0:c8:34:56:2f:1f"
        )
}

rule INDICATOR_KB_CERT_e3c7cc0950152e9ceead4304d01f6c89 {
    meta:
         author = "ditekSHen"
         description = "Detects executables signed with stolen, revoked or invalid certificate"
         thumbprint = "82975e3e21e8fd37bb723de6fdb6e18df9d0e55f0067cc77dd571a52025c6724"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DNS KOMPLEKT" and
            pe.signatures[i].serial == "e3:c7:cc:09:50:15:2e:9c:ee:ad:43:04:d0:1f:6c:89"
        )
}

rule INDICATOR_KB_CERT_6a241ffe96a6349df608d22c02942268 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "f97f4b9953124091a5053712b2c22b845b587cb2655156dcafed202fa7ceeeb1"    
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "HELP, d.o.o." and
            pe.signatures[i].serial == "6a:24:1f:fe:96:a6:34:9d:f6:08:d2:2c:02:94:22:68"
        )
}

rule INDICATOR_KB_CERT_00c04f5d17af872cb2c37e3367fe761d0d {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "7f52ece50576fcc7d66e028ecec89d3faedeeedb953935e215aac4215c9f4d63"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DES SP Z O O" and
            (
                pe.signatures[i].serial == "00:c0:4f:5d:17:af:87:2c:b2:c3:7e:33:67:fe:76:1d:0d" or
                pe.signatures[i].serial == "c0:4f:5d:17:af:87:2c:b2:c3:7e:33:67:fe:76:1d:0d"    
            )
        )
}

rule INDICATOR_KB_CERT_5c7e78f53c31d6aa5b45de14b47eb5c4 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "f91d436c1c7084b83007f032ef48fecda382ff8b81320212adb81e462976ad5a"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Cubic Information Systems, UAB" and
            pe.signatures[i].serial == "5c:7e:78:f5:3c:31:d6:aa:5b:45:de:14:b4:7e:b5:c4"
        )
}

rule INDICATOR_KB_CERT_7156ec47ef01ab8359ef4304e5af1a05 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "59fe580974e2f813c2a00b4be01acd46c94fdea89a3049433cd5ba5a2d96666d"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BOREC, OOO" and
            pe.signatures[i].serial == "71:56:ec:47:ef:01:ab:83:59:ef:43:04:e5:af:1a:05"
        )
}

rule INDICATOR_KB_CERT_00b2e730b0526f36faf7d093d48d6d9997 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "10dd41eb9225b615e6e4f1dce6690bd2c8d055f07d4238db902f3263e62a04a9"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Bamboo Connect s.r.o." and
            pe.signatures[i].serial == "00:b2:e7:30:b0:52:6f:36:fa:f7:d0:93:d4:8d:6d:99:97"
        )
}

rule INDICATOR_KB_CERT_2c90eaf4de3afc03ba924c719435c2a3 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "6b916111ffbd6736afa569d7d940ada544daf3b18213a0da3025b20973a577dc"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "AntiFIX s.r.o." and
            pe.signatures[i].serial == "2c:90:ea:f4:de:3a:fc:03:ba:92:4c:71:94:35:c2:a3"
        )
}

rule INDICATOR_KB_CERT_00bdc81bc76090dae0eee2e1eb744a4f9a {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "a3b0a1cd3998688f294838758688f96adee7d5aa98ec43709b8868d6914e96c1"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ALM4U GmbH" and
            pe.signatures[i].serial == "00:bd:c8:1b:c7:60:90:da:e0:ee:e2:e1:eb:74:4a:4f:9a"
        )
}

rule INDICATOR_KB_CERT_00e38259cf24cc702ce441b683ad578911 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "16304d4840d34a641f58fe7c94a7927e1ba4b3936638164525bedc5a406529f8"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Akhirah Technologies Inc." and
            pe.signatures[i].serial == "00:e3:82:59:cf:24:cc:70:2c:e4:41:b6:83:ad:57:89:11"
        )
}

rule INDICATOR_KB_CERT_4929ab561c812af93ddb9758b545f546 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "0946bf998f8a463a1c167637537f3eba35205b748efc444a2e7f935dc8dd6dc7"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Everything Wow s.r.o." and
            pe.signatures[i].serial == "49:29:ab:56:1c:81:2a:f9:3d:db:97:58:b5:45:f5:46"
        )
}

rule INDICATOR_KB_CERT_00b649a966410f62999c939384af553919 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "a0c6cd25e1990c0d03b6ec1ad5a140f2c8014a8c2f1f4f227ee2597df91a8b6c"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "F.A.T. SARL" and
            pe.signatures[i].serial == "00:b6:49:a9:66:41:0f:62:99:9c:93:93:84:af:55:39:19"
        )
}

rule INDICATOR_KB_CERT_22367dbefd0a325c3893af52547b14fa {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "b5cb5b256e47a30504392c37991e4efc4ce838fde4ad8df47456d30b417e6d5c"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "F.lux Software LLC" and
            pe.signatures[i].serial == "22:36:7d:be:fd:0a:32:5c:38:93:af:52:54:7b:14:fa"
        )
}

rule INDICATOR_KB_CERT_00e04a344b397f752a45b128a594a3d6b5 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "d73229f3b7c2025a5a56e6e189be8a9120f1b3b0d8a78b7f62eff5c8d2293330"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Highweb Ireland Operations Limited" and
            pe.signatures[i].serial == "00:e0:4a:34:4b:39:7f:75:2a:45:b1:28:a5:94:a3:d6:b5"
        )
}

rule INDICATOR_KB_CERT_00a7989f8be0c82d35a19e7b3dd4be30e5 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "3e93aadb509b542c065801f04cffb34956f84ee8c322d65c7ae8e23d27fe5fbf"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Instamix Limited" and
            pe.signatures[i].serial == "00:a7:98:9f:8b:e0:c8:2d:35:a1:9e:7b:3d:d4:be:30:e5"
        )
}

rule INDICATOR_KB_CERT_39f56251df2088223cc03494084e6081 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "66f32cf78b8f685a2c6f5bf361c9b0f9a9678de11a8e7931e2205d0ef65af05c"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Inter Med Pty. Ltd." and
            pe.signatures[i].serial == "39:f5:62:51:df:20:88:22:3c:c0:34:94:08:4e:60:81"
        )
}

rule INDICATOR_KB_CERT_009cfbb4c69008821aaacecde97ee149ab {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "6c7e917a2cc2b2228d6d4a0556bda6b2db9f06691749d2715af9a6a283ec987b"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Kivaliz Prest s.r.l." and
            pe.signatures[i].serial == "00:9c:fb:b4:c6:90:08:82:1a:aa:ce:cd:e9:7e:e1:49:ab"
        )
}

rule INDICATOR_KB_CERT_008cff807edaf368a60e4106906d8df319 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "c97d809c73f376cdf8062329b357b16c9da9d14261895cd52400f845a2d6bdb1"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "KRAFT BOKS OOO" and
            pe.signatures[i].serial == "00:8c:ff:80:7e:da:f3:68:a6:0e:41:06:90:6d:8d:f3:19"
        )
}

rule INDICATOR_KB_CERT_2924785fd7990b2d510675176dae2bed {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "adbc44fda783b5fa817f66147d911fb81a0e2032a1c1527d1b3adbe55f9d682d"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Neoopt LLC" and
            pe.signatures[i].serial == "29:24:78:5f:d7:99:0b:2d:51:06:75:17:6d:ae:2b:ed"
        )
}

rule INDICATOR_KB_CERT_f2c4b99487ed33396d77029b477494bc {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "f38abffd259919d68969b8b2d265afac503a53dd"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Bedaabaefadfdfedcbbbebaaef" and
            pe.signatures[i].serial == "f2:c4:b9:94:87:ed:33:39:6d:77:02:9b:47:74:94:bc"
        )
}

rule INDICATOR_KB_CERT_c54cccff8acceb9654b6f585e2442ef7 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "416c79fccc5f42260cd227fd831b001aca14bf0d"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Eadbebdebcc" and
            pe.signatures[i].serial == "c5:4c:cc:ff:8a:cc:eb:96:54:b6:f5:85:e2:44:2e:f7"
        )
}

rule INDICATOR_KB_CERT_690910dc89d7857c3500fb74bed2b08d {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "dfeb986812ba9f2af6d4ff94c5d1128fa50787951c07b4088f099a5701f1a1a4"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OLIMP STROI" and
            pe.signatures[i].serial == "69:09:10:dc:89:d7:85:7c:35:00:fb:74:be:d2:b0:8d"
        )
}

rule INDICATOR_KB_CERT_0af9b523180f34a24fcfd11b74e7d6cd {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "c8aec622951068734d754dc2efd7032f9ac572e26081ac38b8ceb333ccc165c9"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ORBIS LTD" and
            pe.signatures[i].serial == "0a:f9:b5:23:18:0f:34:a2:4f:cf:d1:1b:74:e7:d6:cd"
        )
}

rule INDICATOR_KB_CERT_00f4d2def53bccb0dd2b7d54e4853a2fc5 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "d5431403ba7b026666e72c675aac6c46720583a60320c5c2c0f74331fe845c35"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PETROYL GROUP, TOV" and
            pe.signatures[i].serial == "00:f4:d2:de:f5:3b:cc:b0:dd:2b:7d:54:e4:85:3a:2f:c5"
        )
}

rule INDICATOR_KB_CERT_56d576a062491ea0a5877ced418203a1 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "b22e022f030cf1e760a7df84d22e78087f3ea2ed262a4b76c8b133871c58213b"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Silvo LLC" and
            pe.signatures[i].serial == "56:d5:76:a0:62:49:1e:a0:a5:87:7c:ed:41:82:03:a1"
        )
}

rule INDICATOR_KB_CERT_4152169f22454ed604d03555b7afb175 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "a1561cacd844fcb62e9e0a8ee93620b3b7d4c3f4bd6f3d6168129136471a7fdb"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SMACKTECH SOFTWARE LIMITED" and
            pe.signatures[i].serial == "41:52:16:9f:22:45:4e:d6:04:d0:35:55:b7:af:b1:75"
        )
}

rule INDICATOR_KB_CERT_41d05676e0d31908be4dead3486aeae3 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "e6e597527853ee64b45d48897e3ca4331f6cc08a88cc57ff2045923e65461598"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Rov SP Z O O" and
            pe.signatures[i].serial == "41:d0:56:76:e0:d3:19:08:be:4d:ea:d3:48:6a:ea:e3"
        )
}

rule INDICATOR_KB_CERT_13c7b92282aae782bfb00baf879935f4 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "c253cce2094c0a4ec403518d4fbf18c650e5434759bc690758cb3658b75c8baa"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "THE WIZARD GIFT CORPORATION" and
            pe.signatures[i].serial == "13:c7:b9:22:82:aa:e7:82:bf:b0:0b:af:87:99:35:f4"
        )
}

rule INDICATOR_KB_CERT_00d627f1000d12485995514bfbdefc55d9 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "5fac3a6484e93f62686e12de3611f7a5251009d541f65e8fe17decc780148052"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "THREE D CORPORATION PTY LTD" and
            pe.signatures[i].serial == "00:d6:27:f1:00:0d:12:48:59:95:51:4b:fb:de:fc:55:d9"
        )
}

rule INDICATOR_KB_CERT_62205361a758b00572d417cba014f007 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "83e851e8c50f9d7299363181f2275edc194037be8cb6710762d2099e0b3f31c6"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "UNITEKH-S, OOO" and
            pe.signatures[i].serial == "62:20:53:61:a7:58:b0:05:72:d4:17:cb:a0:14:f0:07"
        )
}

rule INDICATOR_KB_CERT_566ac16a57b132d3f64dced14de790ee {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "2e44464a5907ac46981bebd8eed86d8deec9a4cfafdf1652c8ba68551d4443ff"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Unirad LLC" and
            pe.signatures[i].serial == "56:6a:c1:6a:57:b1:32:d3:f6:4d:ce:d1:4d:e7:90:ee"
        )
}

rule INDICATOR_KB_CERT_661ba8f3c9d1b348413484e9a49502f7 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "4ca944c9b69f72be3e95f385bdbc70fc7cff4c3ebb76a365bf0ab0126b277b2d"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Unique Digital Services Ltd." and
            pe.signatures[i].serial == "66:1b:a8:f3:c9:d1:b3:48:41:34:84:e9:a4:95:02:f7"
        )
}

rule INDICATOR_KB_CERT_0092d9b92f8cf7a1ba8b2c025be730c300 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "b891c96bd8548c60fa86b753f0c4a4ccc7ab51256b4ee984b5187c62470f9396"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "UPLagga Systems s.r.o." and
            pe.signatures[i].serial == "00:92:d9:b9:2f:8c:f7:a1:ba:8b:2c:02:5b:e7:30:c3:00"
        )
}

rule INDICATOR_KB_CERT_00e5ad42c509a7c24605530d35832c091e {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "17b1f6ffc569acd2cf803c4ac24a7f9828d8d14f6b057e65efdb5c93cc729351"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VESNA, OOO" and
            pe.signatures[i].serial == "00:e5:ad:42:c5:09:a7:c2:46:05:53:0d:35:83:2c:09:1e"
        )
}

rule INDICATOR_KB_CERT_3e57584db26a2c2ebc24ae3e1954fff6 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "4ecbada12a11a5ad5fe6a72a8baaf9d67dc07556a42f6e9a9b6765e334099f4e"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Zaryad LLC" and
            pe.signatures[i].serial == "3e:57:58:4d:b2:6a:2c:2e:bc:24:ae:3e:19:54:ff:f6"
        )
}

rule INDICATOR_KB_CERT_13794371c052ec0559e9b492abb25c26 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "dd3ab539932e81db45cf262d44868e1f0f88a7b0baf682fb89d1a3fcfba3980b"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Carmel group LLC" and
            pe.signatures[i].serial == "13:79:43:71:c0:52:ec:05:59:e9:b4:92:ab:b2:5c:26"
        )
}

rule INDICATOR_KB_CERT_51aead5a9ab2d841b449fa82de3a8a00 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "155edd03d034d6958af61bc6a7181ef8f840feae68a236be3ff73ce7553651b0"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Corsair Software Solution Inc." and
            pe.signatures[i].serial == "51:ae:ad:5a:9a:b2:d8:41:b4:49:fa:82:de:3a:8a:00"
        )
}

rule INDICATOR_KB_CERT_bce1d49ff444d032ba3dda6394a311e9 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "e9a9ef5dfca4d2e720e86443c6d491175f0e329ab109141e6e2ee4f0e33f2e38"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DECIPHER MEDIA LLC" and
            pe.signatures[i].serial == "bc:e1:d4:9f:f4:44:d0:32:ba:3d:da:63:94:a3:11:e9"
        )
}

rule INDICATOR_KB_CERT_00dadf44e4046372313ee97b8e394c4079 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "80986ae0d4f8c8fabf6c4a91550c90224e26205a4ca61c00ff6736dd94817e65"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Digital Capital Management Ireland Limited" and
            pe.signatures[i].serial == "00:da:df:44:e4:04:63:72:31:3e:e9:7b:8e:39:4c:40:79"
        )
}

rule INDICATOR_KB_CERT_00f8c2e08438bb0e9adc955e4b493e5821 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "459ef82eb5756e85922a4687d66bd6a0195834f955ede35ae6c3039d97b00b5f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DocsGen Software Solutions Inc." and
            pe.signatures[i].serial == "00:f8:c2:e0:84:38:bb:0e:9a:dc:95:5e:4b:49:3e:58:21"
        )
}

rule INDICATOR_KB_CERT_00d2caf7908aaebfa1a8f3e2136fece024 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "82baf9b781d458a29469e5370bc9752ebef10f3f8ea506ca6dd04ea5d5f70334"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FANATOR, OOO" and
            pe.signatures[i].serial == "00:d2:ca:f7:90:8a:ae:bf:a1:a8:f3:e2:13:6f:ec:e0:24"
        )
}

rule INDICATOR_KB_CERT_003223b4616c2687c04865bee8321726a8 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "321218e292c2c489bbc7171526e1b4e02ef68ce23105eee87832f875b871ed9f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FORTUNE STAR TRADING, INC." and
            pe.signatures[i].serial == "32:23:b4:61:6c:26:87:c0:48:65:be:e8:32:17:26:a8"
        )
}

rule INDICATOR_KB_CERT_0fa13ae98e17ae23fcfe7ae873d0c120 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "be226576c113cd14bcdb67e46aab235d9257cd77b826b0d22a9aa0985bad5f35"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "KLAKSON, LLC" and
            pe.signatures[i].serial == "0f:a1:3a:e9:8e:17:ae:23:fc:fe:7a:e8:73:d0:c1:20"
        )
}

rule INDICATOR_KB_CERT_3696883055975d571199c6b5d48f3cd5 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "933749369d61bebd5f2c63ff98625973c41098462d9732cffaffe7e02823bc3a"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Korist Networks Incorporated" and
            pe.signatures[i].serial == "36:96:88:30:55:97:5d:57:11:99:c6:b5:d4:8f:3c:d5"
        )
}

rule INDICATOR_KB_CERT_00aff762e907f0644e76ed8a7485fb12a1 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "7b0c55ae9f8f5d82edbc3741ea633ae272bbb2207da8e88694e06d966d86bc63"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Lets Start SP Z O O" and
            pe.signatures[i].serial == "00:af:f7:62:e9:07:f0:64:4e:76:ed:8a:74:85:fb:12:a1"
        )
}

rule INDICATOR_KB_CERT_5b440a47e8ce3dd202271e5c7a666c78 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "07e4cbdd52027e38b86727e88b33a0a1d49fe18f5aee4101353dd371d7a28da5"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Master Networking s.r.o." and
            pe.signatures[i].serial == "5b:44:0a:47:e8:ce:3d:d2:02:27:1e:5c:7a:66:6c:78"
        )
}

rule INDICATOR_KB_CERT_00fe41941464b9992a69b7317418ae8eb7 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "ef4da71810fb92e942446ee1d9b5f38fea49628e0d8335a485f328fcef7f1a20"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Milsean Software Limited" and
            pe.signatures[i].serial == "00:fe:41:94:14:64:b9:99:2a:69:b7:31:74:18:ae:8e:b7"
        )
}

rule INDICATOR_KB_CERT_29128a56e7b3bfb230742591ac8b4718 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "f9fcc798e1fccee123034fe9da9a28283de48ba7ae20f0c55ce0d36ae4625133"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Programavimo paslaugos, MB" and
            pe.signatures[i].serial == "29:12:8a:56:e7:b3:bf:b2:30:74:25:91:ac:8b:47:18"
        )
}

rule INDICATOR_KB_CERT_00c2bb11cfc5e80bf4e8db2ed0aa7e50c5 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "f1044e01ff30d14a3f6c89effae9dbcd2b43658a3f7885c109f6e22af1a8da4b"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Rooth Media Enterprises Limited" and
            pe.signatures[i].serial == "00:c2:bb:11:cf:c5:e8:0b:f4:e8:db:2e:d0:aa:7e:50:c5"
        )
}

rule INDICATOR_KB_CERT_040cc2255db4e48da1b4f242f5edfa73 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "1270a79829806834146ef50a8036cfcc1067e0822e400f81073413a60aa9ed54"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Softland SRL" and
            pe.signatures[i].serial == "04:0c:c2:25:5d:b4:e4:8d:a1:b4:f2:42:f5:ed:fa:73"
        )
}

rule INDICATOR_KB_CERT_3bcaed3ef678f2f9bf38d09e149b8d70 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "45d598691e79be3c47e1883d4b0e149c13a76932ea630be429b0cfccf3217bc2"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "StarY Media Inc." and
            pe.signatures[i].serial == "3b:ca:ed:3e:f6:78:f2:f9:bf:38:d0:9e:14:9b:8d:70"
        )
}

rule INDICATOR_KB_CERT_091736d368a5980ebeb433a0ecb49fbb {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "b1c1dc94f0c775deeb46a0a019597c4ac27ab2810e3b3241bdc284d2fccf3eb5"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ELEKSIR, OOO" and
            pe.signatures[i].serial == "09:17:36:d3:68:a5:98:0e:be:b4:33:a0:ec:b4:9f:bb"
        )
}

rule INDICATOR_KB_CERT_00e48cb3314977d77dedcd4c77dd144c50 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "025bce0f36ec5bac08853966270ed2f5e28765d9c398044462a28c67d74d71e1"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BESPOKE SOFTWARE SOLUTIONS LIMITED" and
            pe.signatures[i].serial == "00:e4:8c:b3:31:49:77:d7:7d:ed:cd:4c:77:dd:14:4c:50"
        )
}

rule INDICATOR_KB_CERT_1e72a72351aecf884df9cdb77a16fd84 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "f945bbea1c2e2dd4ed17f5a98ea7c0f0add6bfc3d07353727b40ce48a7d5e48f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Buket and Co." and
            pe.signatures[i].serial == "1e:72:a7:23:51:ae:cf:88:4d:f9:cd:b7:7a:16:fd:84"
        )
}

rule INDICATOR_KB_CERT_00b383658885e271129a43d19de40c1fc6 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "ef234051b4b83086b675ff58aca85678544c14da39dbdf4d4fa9d5f16e654e2f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Elekon" and
            pe.signatures[i].serial == "00:b3:83:65:88:85:e2:71:12:9a:43:d1:9d:e4:0c:1f:c6"
        )
}

rule INDICATOR_KB_CERT_00ca7d54577243934f665fd1d443855a3d {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "2ea2c7625c1a42fff63f0b17cfc4fd0c0f76d7eb45a86b18ec9a630d3d8ad913"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FABO SP Z O O" and
            pe.signatures[i].serial == "00:ca:7d:54:57:72:43:93:4f:66:5f:d1:d4:43:85:5a:3d"
        )
}

rule INDICATOR_KB_CERT_7709d2df39e9a4f7db2f3cbc29b49743 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "04349ba0f4d74f46387cee8a13ee72ab875032b4396d6903a6e9e7f047426de8"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Grina LLC" and
            pe.signatures[i].serial == "77:09:d2:df:39:e9:a4:f7:db:2f:3c:bc:29:b4:97:43"
        )
}

rule INDICATOR_KB_CERT_186d49fac34ce99775b8e7ffbf50679d {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "812a80556775d658450362e1b3650872b91deba44fef28f17c9364add5aa398e"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Hairis LLC" and
            pe.signatures[i].serial == "18:6d:49:fa:c3:4c:e9:97:75:b8:e7:ff:bf:50:67:9d"
        )
}

rule INDICATOR_KB_CERT_0097df46acb26b7c81a13cc467b47688c8 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "54c4929195fafddfd333871471a015fa68092f44e2f262f2bbf4ee980b41b809"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Information Civilized System Oy" and
            pe.signatures[i].serial == "00:97:df:46:ac:b2:6b:7c:81:a1:3c:c4:67:b4:76:88:c8"
        )
}

rule INDICATOR_KB_CERT_2a52acb34bd075ac9f58771d2a4bbfba {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "c839065a159bec7e63bfdcb1794889829853c07f7a931666f4eb84103302c1c9"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Katarzyna Galganek mim e coc" and
            pe.signatures[i].serial == "2a:52:ac:b3:4b:d0:75:ac:9f:58:77:1d:2a:4b:bf:ba"
        )
}

rule INDICATOR_KB_CERT_5a9d897077a22afe7ad4c4a01df6c418 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "50fa9d22557354a078767cb61f93de9abe491e3a8cb69c280796c7c20eabd5b9"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Klarens LLC" and
            pe.signatures[i].serial == "5a:9d:89:70:77:a2:2a:fe:7a:d4:c4:a0:1d:f6:c4:18"
        )
}

rule INDICATOR_KB_CERT_00d7c432e8d4edef515bfb9d1c214ff0f5 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "6256d3ca79330f7bd912a88e59f9a4f3bdebdcd6b9c55cda4e733e26583b3d61"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "LLC \"MILKY PUT\"" and
            pe.signatures[i].serial == "00:d7:c4:32:e8:d4:ed:ef:51:5b:fb:9d:1c:21:4f:f0:f5"
        )
}

rule INDICATOR_KB_CERT_0085e1af2be0f380e5a5d11513ddf45fc6 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "e9849101535b47ff2a67e4897113c06f024d33f575baa5b426352f15116b98b4"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Makke Digital Works" and
            pe.signatures[i].serial == "00:85:e1:af:2b:e0:f3:80:e5:a5:d1:15:13:dd:f4:5f:c6"
        )
}

rule INDICATOR_KB_CERT_02aa497d39320fc979ad96160d90d410 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "33e8e72a75d6f424c5a10d2b771254c07a7d9c138e5fea703117fe60951427ae"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MATCHLESS GIFTS, INC." and
            pe.signatures[i].serial == "02:aa:49:7d:39:32:0f:c9:79:ad:96:16:0d:90:d4:10"
        )
}

rule INDICATOR_KB_CERT_d0b094274c761f367a8eaea08e1d9c8f {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "e94a9d81c4a67ef953fdb27aad6ec8fa347e6903b140d21468066bdca8925bc5"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Nsasoft US LLC" and
            pe.signatures[i].serial == "d0:b0:94:27:4c:76:1f:36:7a:8e:ae:a0:8e:1d:9c:8f"
        )
}

rule INDICATOR_KB_CERT_00d59a05955a4a421500f9561ce983aac4 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "7f56555ac8479d4e130a89e787b7ff2f47005cc02776cf7a30a58611748c4c2e"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Olymp LLC" and
            pe.signatures[i].serial == "00:d5:9a:05:95:5a:4a:42:15:00:f9:56:1c:e9:83:aa:c4"
        )
}

rule INDICATOR_KB_CERT_35590ebe4a02dc23317d8ce47a947a9b {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "d9b60a67cf3c8964be1e691d22b97932d40437bfead97a84c1350a2c57914f28"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Largos" and
            pe.signatures[i].serial == "35:59:0e:be:4a:02:dc:23:31:7d:8c:e4:7a:94:7a:9b"
        )
}

rule INDICATOR_KB_CERT_1f23f001458716d435cca1a55d660ec5 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "934d9357b6fb96f7fb8c461dd86824b3eed5f44a65c10383fe0be742c8c9b60e"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Ringen" and
            pe.signatures[i].serial == "1f:23:f0:01:45:87:16:d4:35:cc:a1:a5:5d:66:0e:c5"
        )
}

rule INDICATOR_KB_CERT_00c2fc83d458e653837fcfc132c9b03062 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "82294a7efa5208eb2344db420b9aeff317337a073c1a6b41b39dda549a94557e"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Vertical" and
            pe.signatures[i].serial == "00:c2:fc:83:d4:58:e6:53:83:7f:cf:c1:32:c9:b0:30:62"
        )
}

rule INDICATOR_KB_CERT_fcb3d3519e66e5b6d90b8b595f558e81 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "8bf6e51dfe209a2ca87da4c6b61d1e9a92e336e1a83372d7a568132af3ad0196"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Pegasun" and
            pe.signatures[i].serial == "fc:b3:d3:51:9e:66:e5:b6:d9:0b:8b:59:5f:55:8e:81"
        )
}

rule INDICATOR_KB_CERT_4b03cabe6a0481f17a2dbeb9aefad425 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "2e86cb95aa7e4c1f396e236b41bb184787274bb286909b60790b98f713b58777"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "RASSVET, OOO" and
            pe.signatures[i].serial == "4b:03:ca:be:6a:04:81:f1:7a:2d:be:b9:ae:fa:d4:25"
        )
}

rule INDICATOR_KB_CERT_539015999e304a5952985a994f9c3a53 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "7731825aea38cfc77ba039a74417dd211abef2e16094072d8c2384af1093f575"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Service lab LLC" and
            pe.signatures[i].serial == "53:90:15:99:9e:30:4a:59:52:98:5a:99:4f:9c:3a:53"
        )
}

rule INDICATOR_KB_CERT_016836311fc39fbb8e6f308bb03cc2b3 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "cab373e2d4672beacf4ca9c9baf75a2182a106cca5ea32f2fc2295848771a979"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SERVICE STREAM LIMITED" and
            pe.signatures[i].serial == "01:68:36:31:1f:c3:9f:bb:8e:6f:30:8b:b0:3c:c2:b3"
        )
}

rule INDICATOR_KB_CERT_009bd81a9adaf71f1ff081c1f4a05d7fd7 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "885b9f1306850a87598e5230fcae71282042b74e8a14cabb0a904c559b506acb"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SMART TOYS AND GAMES" and
            pe.signatures[i].serial == "00:9b:d8:1a:9a:da:f7:1f:1f:f0:81:c1:f4:a0:5d:7f:d7"
        )
}

rule INDICATOR_KB_CERT_082023879112289bf351d297cc8efcfc {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "0eb3382177f26e122e44ddd74df262a45ebe8261029bc21b411958a07b06278a"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "STA-R TOV" and
            pe.signatures[i].serial == "08:20:23:87:91:12:28:9b:f3:51:d2:97:cc:8e:fc:fc"
        )
}

rule INDICATOR_KB_CERT_00ece6cbf67dc41635a5e5d075f286af23 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "f1f83c96ab00dcb70c0231d946b6fbd6a01e2c94e8f9f30352bbe50e89a9a51c"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "THRANE AGENTUR ApS" and
            pe.signatures[i].serial == "00:ec:e6:cb:f6:7d:c4:16:35:a5:e5:d0:75:f2:86:af:23"
        )
}

rule INDICATOR_KB_CERT_5fb6bae8834edd8d3d58818edc86d7d7 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "026868bbc22c6a37094851e0c6f372da90a8776b01f024badb03033706828088"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Tramplink LLC" and
            pe.signatures[i].serial == "5f:b6:ba:e8:83:4e:dd:8d:3d:58:81:8e:dc:86:d7:d7"
        )
}

rule INDICATOR_KB_CERT_6e0ccbdfb4777e10ea6221b90dc350c2 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "367b3092fbcd132efdbebabdc7240e29e3c91366f78137a27177315d32a926b9"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TRAUMALAB INTERNATIONAL APS" and
            pe.signatures[i].serial == "6e:0c:cb:df:b4:77:7e:10:ea:62:21:b9:0d:c3:50:c2"
        )
}

rule INDICATOR_KB_CERT_1249aa2ada4967969b71ce63bf187c38 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "c139076033e8391c85ba05508c4017736a8a7d9c1350e6b5996dd94b374f403c"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Umbrella LLC" and
            pe.signatures[i].serial == "12:49:aa:2a:da:49:67:96:9b:71:ce:63:bf:18:7c:38"
        )
}

rule INDICATOR_KB_CERT_2dcd0699da08915dde6d044cb474157c {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "13bf3156e66a57d413455973866102b0a1f6d45a1e6de050ca9dcf16ecafb4e2"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VENTE DE TOUT" and
            pe.signatures[i].serial == "2d:cd:06:99:da:08:91:5d:de:6d:04:4c:b4:74:15:7c"
        )
}

rule INDICATOR_KB_CERT_008d52fb12a2511e86bbb0ba75c517eab0 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "9e918ce337aebb755e23885d928e1a67eca6823934935010e82b561b928df2f9"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VThink Software Consulting Inc." and
            pe.signatures[i].serial == "00:8d:52:fb:12:a2:51:1e:86:bb:b0:ba:75:c5:17:ea:b0"
        )
}

rule INDICATOR_KB_CERT_00b1aea98bf0ce789b6c952310f14edde0 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "28324a9746edbdb41c9579032d6eb6ab4fd3e0906f250d4858ce9c5fe5e97469"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Absolut LLC" and
            pe.signatures[i].serial == "00:b1:ae:a9:8b:f0:ce:78:9b:6c:95:23:10:f1:4e:dd:e0"
        )
}

rule INDICATOR_KB_CERT_00f097e59809ae2e771b7b9ae5fc3408d7 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "22ad7df275c8b5036ea05b95ce5da768049bd2b21993549eed3a8a5ada990b1e"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ABEL RENOVATIONS, INC." and
            pe.signatures[i].serial == "00:f0:97:e5:98:09:ae:2e:77:1b:7b:9a:e5:fc:34:08:d7"
        )
}

rule INDICATOR_KB_CERT_2e8023a5a0328f66656e1fc251c82680 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "e3eff064ad23cc4c98cdbcd78e4e5a69527cf2e4"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Philippe Mantes" and
            pe.signatures[i].serial == "2e:80:23:a5:a0:32:8f:66:65:6e:1f:c2:51:c8:26:80"
        )
}

rule INDICATOR_KB_CERT_38b0eaa7c533051a456fb96c4ecf91c4 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "8e2e69b1202210dc9d2155a0f974ab8c325d5297"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Marianne Septier" and
            pe.signatures[i].serial == "38:b0:ea:a7:c5:33:05:1a:45:6f:b9:6c:4e:cf:91:c4"
        )
}

rule INDICATOR_KB_CERT_738db9460a10bb8bc03dc59feac3be5e {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "4cf77e598b603c13cdcd1a676ca61513558df746"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Jocelyn Bennett" and
            pe.signatures[i].serial == "73:8d:b9:46:0a:10:bb:8b:c0:3d:c5:9f:ea:c3:be:5e"
        )
}

rule INDICATOR_KB_CERT_141d6dafed065980d97520e666493396 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "28225705d615a47de0d1b0e324b5b9ca7c11ce48"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Ralph Schmidt" and
            pe.signatures[i].serial == "14:1d:6d:af:ed:06:59:80:d9:75:20:e6:66:49:33:96"
        )
}

rule INDICATOR_KB_CERT_07cf63bdccc15c55e5ce785bdfbeaacf {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "3306df7607bed04187d23c1eb93adf2998e51d01"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "REITSUPER ESTATE LLC" and
            pe.signatures[i].serial == "07:cf:63:bd:cc:c1:5c:55:e5:ce:78:5b:df:be:aa:cf"
        )
}

rule INDICATOR_KB_CERT_0382cd4b6ed21ed7c3eaea266269d000 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "e600612ffcd002718b7d03a49d142d07c5a04154"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "LOOK AND FEEL SP Z O O" and
            pe.signatures[i].serial == "03:82:cd:4b:6e:d2:1e:d7:c3:ea:ea:26:62:69:d0:00"
        )
}

rule INDICATOR_KB_CERT_08653ef2ed9e6ebb56ffa7e93f963235 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "1567d022b47704a1fd7ab71ff60a121d0c1df33a"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Haw Farm LIMITED" and
            pe.signatures[i].serial == "08:65:3e:f2:ed:9e:6e:bb:56:ff:a7:e9:3f:96:32:35"
        )
}

rule INDICATOR_KB_CERT_0ddce8cdc91b5b649bb4b45ffbba6c6c {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "23c446940a9cdc9f502b92d7928e3b3fde6d3735"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SLIM DOG GROUP SP Z O O" and
            pe.signatures[i].serial == "0d:dc:e8:cd:c9:1b:5b:64:9b:b4:b4:5f:fb:ba:6c:6c"
        )
}

rule INDICATOR_KB_CERT_4af27cd14f5c809eec1f46e483f03898 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "5fa9a98f003f2680718cbe3a7a3d57d7ba347ecb"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DAhan Advertising planning" and
            pe.signatures[i].serial == "4a:f2:7c:d1:4f:5c:80:9e:ec:1f:46:e4:83:f0:38:98"
        )
}

rule INDICATOR_KB_CERT_105765998695197de4109828a68a4ee0 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "5ddae14820d6f189e637f90b81c4fdb78b5419dc"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Cryptonic ApS" and
            pe.signatures[i].serial == "10:57:65:99:86:95:19:7d:e4:10:98:28:a6:8a:4e:e0"
        )
}

rule INDICATOR_KB_CERT_53f575f7c33ee007887f30680486db5e {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "a42d8f60663dd86265e566f33d0ed5554e4c9a50"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "RET PTY. LTD." and
            pe.signatures[i].serial == "53:f5:75:f7:c3:3e:e0:07:88:7f:30:68:04:86:db:5e"
        )
}

rule INDICATOR_KB_CERT_7e89b9df006bd1aa4c48d865039634ca {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "63ad44acaa7cd7f8249423673fbf3c3273e7b2dc"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Dummy" and
            pe.signatures[i].serial == "7e:89:b9:df:00:6b:d1:aa:4c:48:d8:65:03:96:34:ca"
        )
}

rule INDICATOR_KB_CERT_0ddeb53f957337fbeaf98c4a615b149d {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "91cabea509662626e34326687348caf2dd3b4bba"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Mozilla Corporation" and
            pe.signatures[i].serial == "0d:de:b5:3f:95:73:37:fb:ea:f9:8c:4a:61:5b:14:9d"
        )
}

rule INDICATOR_KB_CERT_00c88af896b6452241fe00e3aaec11b1f8 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "9ce1cbf5be77265af2a22e28f8930c2ac5641e12"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TeamViewer Germany GmbH" and
            pe.signatures[i].serial == "00:c8:8a:f8:96:b6:45:22:41:fe:00:e3:aa:ec:11:b1:f8"
        )
}

rule INDICATOR_KB_CERT_09e015e98e4fabcc9ac43e042c96090d {
    meta:
        author = "ditekSHen"
        description = "Detects BestEncrypt commercial disk encryption and wiping software signing certificate"
        thumbprint = "04e407118516053ff248503b31d6eec6daf4a809"
        reference1 = "https://www.virustotal.com/gui/file/859f845ee7c741f34ce8bd53d0fe806eccc2395fc413077605fae3db822094b4/details"
        reference2 = "https://blog.macnica.net/blog/2020/11/dtrack.html"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Jetico Inc. Oy" and
            pe.signatures[i].serial == "09:e0:15:e9:8e:4f:ab:cc:9a:c4:3e:04:2c:96:09:0d"
        )
}

rule INDICATOR_KB_CERT_118d813d830f218c0f46d4fc {
    meta:
        author = "ditekSHen"
        description = "Detects BestEncrypt commercial disk encryption and wiping software signing certificate"
        thumbprint = "bd16f70bf6c2ef330c5a4f3a27856a0d030d77fa"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Shang Hai Shen Wei Wang Luo Ke Ji You Xian Gong Si" and
            pe.signatures[i].serial == "11:8d:81:3d:83:0f:21:8c:0f:46:d4:fc"
        )
}

rule INDICATOR_KB_CERT_2304ecf0ea2b2736beddd26a903ba952 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "d59a63e230cef77951cb73a8d65576f00c049f44"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE6\\x88\\x90\\xE9\\x83\\xBD\\xE5\\x90\\x89\\xE8\\x83\\x9C\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE8\\xB4\\xA3\\xE4\\xBB\\xBB\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and
            pe.signatures[i].serial == "23:04:ec:f0:ea:2b:27:36:be:dd:d2:6a:90:3b:a9:52"
        )
}

rule INDICATOR_KB_CERT_4d78e90e0950fc630000000055657e1a {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "fd010fdee2314f5d87045d1d7bf0da01b984b0fe"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Telus Health Solutions Inc." and
            pe.signatures[i].serial == "4d:78:e9:0e:09:50:fc:63:00:00:00:00:55:65:7e:1a"
        )
}

rule INDICATOR_KB_CERT_0092bc051f1811bb0b86727c36394f7849 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "d1f9930521e172526a9f018471d4575d60d8ad8f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MISTO EKONOMSKE STORITVE, d.o.o." and
            pe.signatures[i].serial == "00:92:bc:05:1f:18:11:bb:0b:86:72:7c:36:39:4f:78:49"
        )
}

rule INDICATOR_KB_CERT_b4f42e2c153c904fda64c957ed7e1028 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "ed4c50ab4f173cf46386a73226fa4dac9cadc1c4"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "NONO spol. s r.o." and
            pe.signatures[i].serial == "b4:f4:2e:2c:15:3c:90:4f:da:64:c9:57:ed:7e:10:28"
        )
}

rule INDICATOR_KB_CERT_00ac307e5257bb814b818d3633b630326f {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "4d6a089ec4edcac438717c1d64a8be4ef925a9c6"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Aqua Direct s.r.o." and
            pe.signatures[i].serial == "00:ac:30:7e:52:57:bb:81:4b:81:8d:36:33:b6:30:32:6f"
        )
}

rule INDICATOR_KB_CERT_063a7d09107eddd8aa1f733634c6591b {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "a03f9b3f3eb30ac511463b24f2e59e89ee4c6d4a"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Smart Line Logistics" and
            pe.signatures[i].serial == "06:3a:7d:09:10:7e:dd:d8:aa:1f:73:36:34:c6:59:1b"
        )
}

rule INDICATOR_KB_CERT_4c687a0022c36f89e253f91d1f6954e2 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "4412007ae212d12cea36ed56985bd762bd9fb54a"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "HETCO ApS" and
            pe.signatures[i].serial == "4c:68:7a:00:22:c3:6f:89:e2:53:f9:1d:1f:69:54:e2"
        )
}

rule INDICATOR_KB_CERT_3cee26c125b8c188f316c3fa78d9c2f1 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "9efcf68a289d9186ec17e334205cb644c2b6a147"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Bitubit LLC" and
            pe.signatures[i].serial == "3c:ee:26:c1:25:b8:c1:88:f3:16:c3:fa:78:d9:c2:f1"
        )
}

rule INDICATOR_KB_CERT_a0a27aefd067ac62ce0247b72bf33de3 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "42c2842fa674fdca14c9786aaec0c3078a4f1755"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Cfbcdabfdbdccaaccadfeaacacf" and
            pe.signatures[i].serial == "a0:a2:7a:ef:d0:67:ac:62:ce:02:47:b7:2b:f3:3d:e3"
        )
}

rule INDICATOR_KB_CERT_eee8cf0a0e4c78faa03d07470161a90e {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "32eda5261359e76a4e66da1ba82db7b7a48295d2"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Aafabffdbdbcbfcaebdf" and
            pe.signatures[i].serial == "ee:e8:cf:0a:0e:4c:78:fa:a0:3d:07:47:01:61:a9:0e"
        )
}

rule INDICATOR_KB_CERT_79e1cc0f6722e1a2c4647c21023ca4ee {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "41d2f4f810a6edf42b3717cf01d4975476f63cba"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SPAGETTI LTD" and
            pe.signatures[i].serial == "79:e1:cc:0f:67:22:e1:a2:c4:64:7c:21:02:3c:a4:ee"
        )
}

rule INDICATOR_KB_CERT_6d688ecf46286fe4b6823b91384eca86 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "970205140b48d684d0dc737c0fe127460ccfac4f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "AtomPark Software JSC" and
            pe.signatures[i].serial == "6d:68:8e:cf:46:28:6f:e4:b6:82:3b:91:38:4e:ca:86"
        )
}

rule INDICATOR_KB_CERT_9aa99f1b75a463460d38c4539fae4f73 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "b2ea9e771631f95a927c29b044284ef4f84a2069"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Beaacdfaeeccbbedadcb" and
            pe.signatures[i].serial == "9a:a9:9f:1b:75:a4:63:46:0d:38:c4:53:9f:ae:4f:73"
        )
}

rule INDICATOR_KB_CERT_e414655f025399cca4d7225d89689a04 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "98643cef3dc22d0cc730be710c5a30ae25d226c1"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE6\\xAF\\x94\\xE5\\x90\\xBE\\xE8\\xBF\\xAA\\xE5\\x90\\xBE\\xE8\\xBF\\xAA\\xE4\\xBC\\x8A\\xE4\\xBC\\x8A\\xE8\\xBF\\xAA\\xE5\\x90\\xBE\\xE5\\x90\\xBE\\xE4\\xBC\\x8A\\xE4\\xBC\\x8A\\xE6\\x8F\\x90\\xE4\\xBC\\x8A\\xE6\\xAF\\x94\\xE6\\x8F\\x90\\xE8\\xBF\\xAA\\xE8\\xBF\\xAA\\xE4\\xBC\\x8A\\xE4\\xBC\\x8A\\xE4\\xBC\\x8A\\xE6\\x8F\\x90\\xE7\\xBB\\xB4\\xE6\\xAF\\x94" and
            pe.signatures[i].serial == "e4:14:65:5f:02:53:99:cc:a4:d7:22:5d:89:68:9a:04"
        )
}

rule INDICATOR_KB_CERT_64f82ed8a90f92a940be2bb90fbf6f48 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "4d00f5112caf80615852ffe1f4ee72277ed781c3"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Klimate Vision Plus" and
            pe.signatures[i].serial == "64:f8:2e:d8:a9:0f:92:a9:40:be:2b:b9:0f:bf:6f:48"
        )
}

rule INDICATOR_KB_CERT_00f0031491b673ecdf533d4ebe4b54697f {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "01e201cce1024237978baccf5b124261aa5edb01"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Eebbffbceacddbfaeefaecdbaf" and
            pe.signatures[i].serial == "00:f0:03:14:91:b6:73:ec:df:53:3d:4e:be:4b:54:69:7f"
        )
}

rule INDICATOR_KB_CERT_becd4ef55ced54e5bcde595d872ae7eb {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "72ae9b9a32b4c16b5a94e2b4587bc51a91b27052"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Dedbfdefcac" and
            pe.signatures[i].serial == "be:cd:4e:f5:5c:ed:54:e5:bc:de:59:5d:87:2a:e7:eb"
        )
}

rule INDICATOR_KB_CERT_55b5e1cf84a89c4e023399784b42a268 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "940345ed6266b67a768296ad49e51bbaa6ee8e97"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Fbbdefaccbbcdc" and
            pe.signatures[i].serial == "55:b5:e1:cf:84:a8:9c:4e:02:33:99:78:4b:42:a2:68"
        )
}

rule INDICATOR_KB_CERT_84c3a47b739f1835d35b755d1e6741b5 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "8057f20f9f385858416ec3c0bd77394eff595b69"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Bddbdcfabededdeadbefed" and
            pe.signatures[i].serial == "84:c3:a4:7b:73:9f:18:35:d3:5b:75:5d:1e:67:41:b5"
        )
}

rule INDICATOR_KB_CERT_28f6ca1f249cfb6bdb16bc57aaf0bd79 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "0811c227816282094d5212d3c9116593f70077ab"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Cdcafaabbdcaaaeaaee" and
            pe.signatures[i].serial == "28:f6:ca:1f:24:9c:fb:6b:db:16:bc:57:aa:f0:bd:79"
        )
}

rule INDICATOR_KB_CERT_2c3e87b9d430c2f0b14fc1152e961f1a {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "80daa4ad14fc420d7708f2855e6fab085ca71980"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Abfaacccde" and
            pe.signatures[i].serial == "2c:3e:87:b9:d4:30:c2:f0:b1:4f:c1:15:2e:96:1f:1a"
        )
}

rule INDICATOR_KB_CERT_4808c88ea243eefa47610d5f5f0d02a2 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "5dc400de1133be3ff17ff09f8a1fd224b3615e5a"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Bfcdcdfcdfcaaeff" and
            pe.signatures[i].serial == "48:08:c8:8e:a2:43:ee:fa:47:61:0d:5f:5f:0d:02:a2"
        )
}

rule INDICATOR_KB_CERT_2f184a6f054dc9f7c74a63714b14ce33 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed AprelTech Silent Install Builder certificate"
        thumbprint = "ec9c6a537f6d7a0e63a4eb6aeb0df9d5b466cc58"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "APREL Tehnologija d.o.o." and
            pe.signatures[i].serial == "2f:18:4a:6f:05:4d:c9:f7:c7:4a:63:71:4b:14:ce:33"
        )
}

rule INDICATOR_KB_CERT_00ced72cc75aa0ebce09dc0283076ce9b1 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "db77b48a7f16fecd49029b65f122fa0782b4318f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Valerie LLC" and
            pe.signatures[i].serial == "00:ce:d7:2c:c7:5a:a0:eb:ce:09:dc:02:83:07:6c:e9:b1"
        )
}

rule INDICATOR_KB_CERT_c4564802095258281a284809930dcf43 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "73db2555f20b171ce9502eb6507add9fa53a5bf3"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Cfeaaeedaefddfaaccefcdbae" and
            pe.signatures[i].serial == "c4:56:48:02:09:52:58:28:1a:28:48:09:93:0d:cf:43"
        )
}

rule INDICATOR_KB_CERT_3d31ed3b22867f425db86fb532eb449f {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "1e708efa130d1e361afb76cc94ba22aca3553590"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Badfcbdbcdbfafcaeebad" and
            pe.signatures[i].serial == "3d:31:ed:3b:22:86:7f:42:5d:b8:6f:b5:32:eb:44:9f"
        )
}

rule INDICATOR_KB_CERT_531549ed4d2d53fc7e1beb47c6b13d58 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "a8e1f6e32e5342265dd3e28cc65060fb7221c529"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Bdabfbdfbcbab" and
            pe.signatures[i].serial == "53:15:49:ed:4d:2d:53:fc:7e:1b:eb:47:c6:b1:3d:58"
        )
}

rule INDICATOR_KB_CERT_8035ed9c58ea895505b05ff926d486bc {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "b82a7f87b7d7ccea50bba5fe8d8c1c745ebcb916"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Fecddacdddfaadcddcabceded" and
            pe.signatures[i].serial == "80:35:ed:9c:58:ea:89:55:05:b0:5f:f9:26:d4:86:bc"
        )
}

rule INDICATOR_KB_CERT_ca646b4275406df639cf603756f63d77 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "2a68cfad2d82caae48d4dcbb49aa73aaf3fe79dd"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SHOECORP LIMITED" and
            pe.signatures[i].serial == "ca:64:6b:42:75:40:6d:f6:39:cf:60:37:56:f6:3d:77"
        )
}

rule INDICATOR_KB_CERT_00e267fdbdc16f22e8185d35c437f84c87 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "cdf4a69402936ece82f3f9163e6cc648bcbb2680"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "APOTHEKA, s.r.o." and
            pe.signatures[i].serial == "00:e2:67:fd:bd:c1:6f:22:e8:18:5d:35:c4:37:f8:4c:87"
        )
}

rule INDICATOR_KB_CERT_00taffias {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "88d563dccb2ffc9c5f6d6a3721ad17203768735a"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TAFFIAS" and
            pe.signatures[i].serial == "00"
        )
}

rule INDICATOR_KB_CERT_9f2492304fc9c93844dea7e5d6f0ec77 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "33015f23712f36e3ec310cfd1b16649abb645a98"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Bbddebeea" and
            pe.signatures[i].serial == "9f:24:92:30:4f:c9:c9:38:44:de:a7:e5:d6:f0:ec:77"
        )
}

rule INDICATOR_KB_CERT_dca9012634e8b609884fe9284d30eff5 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "60971c18c7efb4a294f1d8ee802ff3d581c77834"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Bebaeefaeba" and (
                pe.signatures[i].serial == "dc:a9:01:26:34:e8:b6:09:88:4f:e9:28:4d:30:ef:f5" or
                pe.signatures[i].serial == "00:dc:a9:01:26:34:e8:b6:09:88:4f:e9:28:4d:30:ef:f5"    
            )
        )
}

rule INDICATOR_KB_CERT_781ec65c3e38392d4c2f9e7f55f5c424 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "5d20e8f899c7e48a0269c2b504607632ba833e40"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Facacafbfddbdbfad" and
            pe.signatures[i].serial == "78:1e:c6:5c:3e:38:39:2d:4c:2f:9e:7f:55:f5:c4:24"
        )
}

rule INDICATOR_KB_CERT_bd1e93d5787a737eef930c70986d2a69 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "921e5d7f9f05272b566533393d7194ea9227e582"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Cdefedddbdedbcbfffbeadb" and
            pe.signatures[i].serial == "bd:1e:93:d5:78:7a:73:7e:ef:93:0c:70:98:6d:2a:69"
        )
}

rule INDICATOR_KB_CERT_b0009bb062f52eb6001ba79606de243d {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "c89f06937d24b7f13be5edba5e0e2f4e05bc9b13"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Fbfdddcfabc" and
            pe.signatures[i].serial == "b0:00:9b:b0:62:f5:2e:b6:00:1b:a7:96:06:de:24:3d"
        )
}

rule INDICATOR_KB_CERT_294e7a2ccfc28ed02843ecff25f2ac98 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "a57a2de9b04a80e9290df865c0abd3b467318144"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Eadbaadbdcecafdfafbe" and
            pe.signatures[i].serial == "29:4e:7a:2c:cf:c2:8e:d0:28:43:ec:ff:25:f2:ac:98"
        )
}

rule INDICATOR_KB_CERT_a61b5590c2d8dc70a31f8ea78cda4353 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "d1f77736e8594e026f67950ca2bf422bb12abc3a"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Bdddcfaebffbfdcabaffe" and
            pe.signatures[i].serial == "a6:1b:55:90:c2:d8:dc:70:a3:1f:8e:a7:8c:da:43:53"
        )
}

rule INDICATOR_KB_CERT_21c9a6daff942f2db6a0614d {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "7dd9acb2ef0402883c65901ebbafd06e5293d391"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Ledger SAS" and
            pe.signatures[i].serial == "21:c9:a6:da:ff:94:2f:2d:b6:a0:61:4d"
        )
}

rule INDICATOR_KB_CERT_1f55ae3fca38827cde6cc7ca1c0d2731 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "a279fa4186ef598c5498ba5c0037c7bd4bd57272"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Fcceaeafbbdccccddfbbb" and
            pe.signatures[i].serial == "1f:55:ae:3f:ca:38:82:7c:de:6c:c7:ca:1c:0d:27:31"
        )
}

rule INDICATOR_KB_CERT_008d1bae9f7aef1a2bcc0d392f3edf3a36 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "5927654acf9c66912ff7b41dab516233d98c9d72"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Beaffbebfeebbefbeeb" and
            pe.signatures[i].serial == "00:8d:1b:ae:9f:7a:ef:1a:2b:cc:0d:39:2f:3e:df:3a:36"
        )
}

rule INDICATOR_KB_CERT_239ba103c2943d2dff5e3211d6800d09 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "d8ea0533af5c180ce1f4d6bc377b736208b3efbb"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Bcafaecbecacbca" and
            pe.signatures[i].serial == "23:9b:a1:03:c2:94:3d:2d:ff:5e:32:11:d6:80:0d:09"
        )
}

rule INDICATOR_KB_CERT_205b80a74a5dddedea6b84a1e1c44010 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "1a743595dfaa29cd215ec82a6cd29bb434b709cf"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Befadbffde" and
            pe.signatures[i].serial == "20:5b:80:a7:4a:5d:dd:ed:ea:6b:84:a1:e1:c4:40:10"
        )
}

rule INDICATOR_KB_CERT_6c8d0cf4d1593ee8dc8d34be71e90251 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "d481d73bcf1e45db382d0e345f3badde6735d17d"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Dbdbecdbdfafdc" and
            pe.signatures[i].serial == "6c:8d:0c:f4:d1:59:3e:e8:dc:8d:34:be:71:e9:02:51"
        )
}

rule INDICATOR_KB_CERT_7d08a74747557d6016aaaf47a679312f {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "d7fdad88c626b8e6d076f3f414bbae353f444618"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Abfacfbdcd" and
            pe.signatures[i].serial == "7d:08:a7:47:47:55:7d:60:16:aa:af:47:a6:79:31:2f"
        )
}

rule INDICATOR_KB_CERT_2095c6f1eadb65ce02862bd620623b92 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "940a4d4a5aadef70d8c14caac6f11d653e71800f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Febeecad" and
            pe.signatures[i].serial == "20:95:c6:f1:ea:db:65:ce:02:86:2b:d6:20:62:3b:92"
        )
}

rule INDICATOR_KB_CERT_0b1f8cd59e64746beae153ecca21066b {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "74b2e146a82f2b71f8eb4b13ebbb6f951757d8c2"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Mozilla Corporation" and
            pe.signatures[i].serial == "0b:1f:8c:d5:9e:64:74:6b:ea:e1:53:ec:ca:21:06:6b"
        )
}

rule INDICATOR_KB_CERT_899e32c9bf2b533b9275c39f8f9ff96d {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "329af76d7c84a90f2117893adc255115c3c961c7"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Eecaaffcbfdffaedcfec" and
            pe.signatures[i].serial == "89:9e:32:c9:bf:2b:53:3b:92:75:c3:9f:8f:9f:f9:6d"
        )
}

rule INDICATOR_KB_CERT_0b5759bc22ad2128b8792e8535f9161e {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "ddfd6a93a8d33f0797d5fdfdb9abf2b66e64350a"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Ceeacfeacafdcdffabdbbacf" and
            pe.signatures[i].serial == "0b:57:59:bc:22:ad:21:28:b8:79:2e:85:35:f9:16:1e"
        )
}

rule INDICATOR_KB_CERT_630cf0e612f12805ffa00a41d1032d7c {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "107af72db66ec4005ed432e4150a0b6f5a9daf2d"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Dadebfaca" and
            pe.signatures[i].serial == "63:0c:f0:e6:12:f1:28:05:ff:a0:0a:41:d1:03:2d:7c"
        )
}

rule INDICATOR_KB_CERT_603bce30597089d068320fc77e400d06 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "4ddda7e006afb108417627f8f22a6fa416e3f264"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Fcaddefffedacfc" and
            pe.signatures[i].serial == "60:3b:ce:30:59:70:89:d0:68:32:0f:c7:7e:40:0d:06"
        )
}

rule INDICATOR_KB_CERT_5d5d03edb4ec4e185caa3041824ab75c {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "f6c9c564badc1bbd8a804c5e20ab1a0eff89d4c0"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Ffcdcbacfeaedbfbcecccafeb" and
            pe.signatures[i].serial == "5d:5d:03:ed:b4:ec:4e:18:5c:aa:30:41:82:4a:b7:5c"
        )
}

rule INDICATOR_KB_CERT_aec009984fa957f3f48fe3104ca9babc {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "9d5b6bc86775395992a25d21d696d05d634a89d1"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Ceefaccdedbfbbaaaadacdbf" and
            pe.signatures[i].serial == "ae:c0:09:98:4f:a9:57:f3:f4:8f:e3:10:4c:a9:ba:bc"
        )
}

rule INDICATOR_KB_CERT_283518f1940a11caf187646d8063d61d {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "aaeb19203b71e26c857613a5a2ba298c79910f5d"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Eeeeeeba" and
            pe.signatures[i].serial == "28:35:18:f1:94:0a:11:ca:f1:87:64:6d:80:63:d6:1d"
        )
}

rule INDICATOR_KB_CERT_72f3e4707b94d0eef214384de9b36e {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "e2a5a2823b0a56c88bfcb2788aa4406e084c4c9b"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Eaaebecedccfd" and
            pe.signatures[i].serial == "72:f3:e4:70:7b:94:d0:ee:f2:14:38:4d:e9:b3:6e"
        )
}

rule INDICATOR_KB_CERT_00d875b3e3f2db6c3eb426e24946066111 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "d27211a59dc8a4b3073d116621b6857c3d70ed04"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Kubit LLC" and
            pe.signatures[i].serial == "00:d8:75:b3:e3:f2:db:6c:3e:b4:26:e2:49:46:06:61:11"
        )
}

rule INDICATOR_KB_CERT_3990362c34015ce4c23ecc3377fd3c06 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "48444dec9d6839734d8383b110faabe05e697d45"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "RZOH ApS" and
            pe.signatures[i].serial == "39:90:36:2c:34:01:5c:e4:c2:3e:cc:33:77:fd:3c:06"
        )
}

rule INDICATOR_KB_CERT_54a6d33f73129e0ef059ccf51be0c35e {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "8ada307ab3a8983857d122c4cb48bf3b77b49c63"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "STAFFORD MEAT COMPANY, INC." and
            pe.signatures[i].serial == "54:a6:d3:3f:73:12:9e:0e:f0:59:cc:f5:1b:e0:c3:5e"
        )
}

rule INDICATOR_KB_CERT_0a55c15f733bf1633e9ffae8a6e3b37d {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "591f68885fc805a10996262c93aab498c81f3010"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Osnova OOO" and
            pe.signatures[i].serial == "0a:55:c1:5f:73:3b:f1:63:3e:9f:fa:e8:a6:e3:b3:7d"
        )
}

rule INDICATOR_KB_CERT_00f675139ea68b897a865a98f8e4611f00 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "06d46ee9037080c003983d76be3216b7cad528f8"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BS TEHNIK d.o.o." and
            pe.signatures[i].serial == "00:f6:75:13:9e:a6:8b:89:7a:86:5a:98:f8:e4:61:1f:00"
        )
}

rule INDICATOR_KB_CERT_121fca3cfa4bd011669f5cc4e053aa3f {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "84b5ef4f981020df2385754ab1296821fa2f8977"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Kymijoen Projektipalvelut Oy" and
            pe.signatures[i].serial == "12:1f:ca:3c:fa:4b:d0:11:66:9f:5c:c4:e0:53:aa:3f"
        )
}

rule INDICATOR_KB_CERT_62b80fc5e1c02072019c88ee356152c1 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "0a83c0f116020fc1f43558a9a08b1f8bcbb809e0"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Inversum" and
            pe.signatures[i].serial == "62:b8:0f:c5:e1:c0:20:72:01:9c:88:ee:35:61:52:c1"
        )
}

rule INDICATOR_KB_CERT_01803bc7537a1818c4ab135469963c10 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "197839b47cf975c3d6422404cbbbb5bc94f4eb46"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Rare Ideas LLC" and
            pe.signatures[i].serial == "01:80:3b:c7:53:7a:18:18:c4:ab:13:54:69:96:3c:10"
        )
}

rule INDICATOR_KB_CERT_f0e150c304de35f2e9086185581f4053 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "c0a448b9101f48309a8e5a67c11db09da14b54bb"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Rare Ideas, LLC" and
            pe.signatures[i].serial == "f0:e1:50:c3:04:de:35:f2:e9:08:61:85:58:1f:40:53"
        )
}

rule INDICATOR_KB_CERT_a1a3e7280e0a2df12f84309649820519 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "33d254c711937b469d1b08ef15b0a9f5b4d27250"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Nir Sofer" and
            pe.signatures[i].serial == "a1:a3:e7:28:0e:0a:2d:f1:2f:84:30:96:49:82:05:19"
        )
}

rule INDICATOR_KB_CERT_1fb984d5a7296ba74445c23ead7d20aa {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "c852fc9670391ff077eb2590639051efa42db5c9"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DrWeb Digital LLC" and
            pe.signatures[i].serial == "1f:b9:84:d5:a7:29:6b:a7:44:45:c2:3e:ad:7d:20:aa"
        )
}

rule INDICATOR_KB_CERT_c314a8736f82c411b9f02076a6db4771 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "9c49d7504551ad4ddffad206b095517a386e8a14"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Cbcbaeaabbfcebfcbbeeffeadfc" and
            pe.signatures[i].serial == "c3:14:a8:73:6f:82:c4:11:b9:f0:20:76:a6:db:47:71"
        )
}

rule INDICATOR_KB_CERT_5f7ef778d51cd33a5fc0d2e035ccd29d {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "87229a298b8de0c7b8d4e23119af1e7850a073f5"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Ffadbcfabbe" and
            pe.signatures[i].serial == "5f:7e:f7:78:d5:1c:d3:3a:5f:c0:d2:e0:35:cc:d2:9d"
        )
}

rule INDICATOR_KB_CERT_00ab1d5e43e4dde77221381e21a764c082 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "b84a817517ed50dbae5439be54248d30bd7a3290"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Dadddbffbfcbdaaeeccecbbffac" and
            pe.signatures[i].serial == "00:ab:1d:5e:43:e4:dd:e7:72:21:38:1e:21:a7:64:c0:82"
        )
}

rule INDICATOR_KB_CERT_4743e140c05b33f0449023946bd05acb {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "7b32c8cc35b86608c522a38c4fe38ebaa57f27675504cba32e0ab6babbf5094a"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "STROI RENOV SARL" and
            pe.signatures[i].serial == "47:43:e1:40:c0:5b:33:f0:44:90:23:94:6b:d0:5a:cb"
        )
}

rule INDICATOR_KB_CERT_2c1ee9b583310b5e34a1ee6945a34b26 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "7af96a09b6c43426369126cfffac018f11e5562cb64d32e5140cff3f138ffea4"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Artmarket" and
            pe.signatures[i].serial == "2c:1e:e9:b5:83:31:0b:5e:34:a1:ee:69:45:a3:4b:26"
        )
}

rule INDICATOR_KB_CERT_00d338f8a490e37e6c2be80a0e349929fa {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "480a9ce15fc76e03f096fda5af16e44e0d6a212d6f09a898f51ad5206149bbe1"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SAGUARO ApS" and
            pe.signatures[i].serial == "00:d3:38:f8:a4:90:e3:7e:6c:2b:e8:0a:0e:34:99:29:fa"
        )
}

rule INDICATOR_KB_CERT_778906d40695f65ba518db760df44cd3 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "1103debcb1e48f7dda9cec4211c0a7a9c1764252"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            //pe.signatures[i].subject contains "\\xD0\\x9E\\xD0\\x9E\\xD0\\x9E \"\\xD0\\x98\\xD0\\x9D\\xD0\\xA2\\xD0\\x95\\xD0\\x9B\\xD0\\x9B\\xD0\\x98\\xD0\\xA2\"" and
            pe.signatures[i].serial == "77:89:06:d4:06:95:f6:5b:a5:18:db:76:0d:f4:4c:d3"
        )
}

rule INDICATOR_KB_CERT_45eb9187a2505d8e6c842e6d366ad0c8 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "63938d34572837514929fa7ae3cfebedf6d2cb65"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BAKERA s.r.o." and
            pe.signatures[i].serial == "45:eb:91:87:a2:50:5d:8e:6c:84:2e:6d:36:6a:d0:c8"
        )
}

rule INDICATOR_KB_CERT_cbc2af7d82295a8535f3b26b47522640 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "08d2c03d0959905b4b04caee1202b8ed748a8bd0"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Eabfdafffefaccaedaec" and
            pe.signatures[i].serial == "cb:c2:af:7d:82:29:5a:85:35:f3:b2:6b:47:52:26:40"
        )
}

rule INDICATOR_KB_CERT_0ca1d9391cf5fe3e696831d98d6c35a6 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "0689776ca5ca0ca9641329dc29efdb61302d7378"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "www.norton.com" and
            pe.signatures[i].serial == "0c:a1:d9:39:1c:f5:fe:3e:69:68:31:d9:8d:6c:35:a6"
        )
}

rule INDICATOR_KB_CERT_43a36a26ebc78e111a874d8211a95e3f {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "a346bda33b5b3bea04b299fe87c165c4f221645a"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Efacefcafeabbdcbcea" and
            pe.signatures[i].serial == "43:a3:6a:26:eb:c7:8e:11:1a:87:4d:82:11:a9:5e:3f"
        )
}

rule INDICATOR_KB_CERT_5172caa2119185382343fcbe09c43bee {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "fd9b3f6b0eb9bd9baf7cbdc79ae7979b7ddad770"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Aefcdac" and
            pe.signatures[i].serial == "51:72:ca:a2:11:91:85:38:23:43:fc:be:09:c4:3b:ee"
        )
}

rule INDICATOR_KB_CERT_009245d1511923f541844faa3c6bfebcbe {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "509cbd2cd38ae03461745c7d37f6bbe44c6782cf"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "LEHTEH d.o.o.," and
            pe.signatures[i].serial == "00:92:45:d1:51:19:23:f5:41:84:4f:aa:3c:6b:fe:bc:be"
        )
}

rule INDICATOR_KB_CERT_00e161f76da3b5e4623892c8e6fda1ea3d {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "df5fbfbfd47875b580b150603de240ead9c7ad27"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TGN Nedelica d.o.o." and
            pe.signatures[i].serial == "00:e1:61:f7:6d:a3:b5:e4:62:38:92:c8:e6:fd:a1:ea:3d"
        )
}

rule INDICATOR_KB_CERT_009faf8705a3eaef9340800cc4fd38597c {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "40c572cc19e7ca4c2fb89c96357eff4c7489958e"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Tekhnokod LLC" and
            pe.signatures[i].serial == "00:9f:af:87:05:a3:ea:ef:93:40:80:0c:c4:fd:38:59:7c"
        )
}

rule INDICATOR_KB_CERT_2888cf0f953a4a3640ee4cfc6304d9d4 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "eb5f5ab7294ba39f2b77085f47382bd7e759ff3a"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Lotte Schmidt" and
            pe.signatures[i].serial == "28:88:cf:0f:95:3a:4a:36:40:ee:4c:fc:63:04:d9:d4"
        )
}

rule INDICATOR_KB_CERT_00c8edcfe8be174c2f204d858c5b91dea5 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "7f5f205094940793d1028960e0f0e8b654f9956e"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Paarcopy Oy" and
            pe.signatures[i].serial == "00:c8:ed:cf:e8:be:17:4c:2f:20:4d:85:8c:5b:91:de:a5"
        )
}

rule INDICATOR_KB_CERT_1a311630876f694fe1b75d972a953bca {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "d473ec0fe212b7847f1a4ee06eff64e2a3b4001e"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "GTEC s.r.o." and
            pe.signatures[i].serial == "1a:31:16:30:87:6f:69:4f:e1:b7:5d:97:2a:95:3b:ca"
        )
}

rule INDICATOR_KB_CERT_00a496bc774575c31abec861b68c36dcb6 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "b2c70d30c0b34bfeffb8a9cb343e5cad5f6bcbf7"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ORGLE DVORSAK, d.o.o" and
            pe.signatures[i].serial == "00:a4:96:bc:77:45:75:c3:1a:be:c8:61:b6:8c:36:dc:b6"
        )
}

rule INDICATOR_KB_CERT_00ea720222d92dc8d48e3b3c3b0fc360a6 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "522d0f1ca87ef784994dfd63cb0919722dfdb79f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "CAVANAGH NETS LIMITED" and
            pe.signatures[i].serial == "00:ea:72:02:22:d9:2d:c8:d4:8e:3b:3c:3b:0f:c3:60:a6"
        )
}

rule INDICATOR_KB_CERT_333ca7d100b139b0d9c1a97cb458e226 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "d618cf7ef3a674ff1ea50800b4d965de0ff463cb"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FSE, d.o.o." and
            pe.signatures[i].serial == "33:3c:a7:d1:00:b1:39:b0:d9:c1:a9:7c:b4:58:e2:26"
        )
}

rule INDICATOR_KB_CERT_58ec8821aa2a3755e1075f73321756f4 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "19dd0d7f2edf32ea285577e00dd13c966844cfa4"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Cbebbfeaddcbcccffdcdc" and
            pe.signatures[i].serial == "58:ec:88:21:aa:2a:37:55:e1:07:5f:73:32:17:56:f4"
        )
}

rule INDICATOR_KB_CERT_0940fa9a4080f35052b2077333769c2f {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "da154c058cd75ff478b248701799ea8c683dd7a5"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PROFF LAIN, OOO" and
            pe.signatures[i].serial == "09:40:fa:9a:40:80:f3:50:52:b2:07:73:33:76:9c:2f"
        )
}

rule INDICATOR_KB_CERT_56fff139df5ae7e788e5d72196dd563a {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "0f69ccb73a6b98f548d00f0b740b6e42907efaad"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Cifromatika LLC" and
            pe.signatures[i].serial == "56:ff:f1:39:df:5a:e7:e7:88:e5:d7:21:96:dd:56:3a"
        )
}

rule INDICATOR_KB_CERT_03d433fdc2469e9fd878c80bc0545147 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "64e90267e6359060a8669aebb94911e92bd0c5f3"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xEC\\xA3\\xBC\\xEC\\x8B\\x9D\\xED\\x9A\\x8C\\xEC\\x82\\xAC \\xEC\\x97\\x98\\xEB\\xA6\\xAC\\xEC\\x8B\\x9C\\xEC\\x98\\xA8\\xEB\\x9E\\xA9" and
            pe.signatures[i].serial == "03:d4:33:fd:c2:46:9e:9f:d8:78:c8:0b:c0:54:51:47"
        )
}

rule INDICATOR_KB_CERT_0be3f393d1ef0272aed0e2319c1b5dd0 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "7745253a3f65311b84d8f64b74f249364d29e765"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Invincea, Inc." and
            pe.signatures[i].serial == "0b:e3:f3:93:d1:ef:02:72:ae:d0:e2:31:9c:1b:5d:d0"
        )
}

rule INDICATOR_KB_CERT_65628c146ace93037fc58659f14bd35f {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "b59165451be46b8d72d09191d0961c755d0107c8"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ESET, spol. s r.o." and
            pe.signatures[i].serial == "65:62:8c:14:6a:ce:93:03:7f:c5:86:59:f1:4b:d3:5f"
        )
}

rule INDICATOR_KB_CERT_0084817e07288a5025b9435570e7fec1d3 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "f22e8c59b7769e4a9ade54aee8aaf8404a7feaa7"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE8\\xB4\\xBC\\xE8\\x89\\xBE\\xE5\\xBE\\xB7\\xE8\\xB4\\xBC\\xE6\\x8F\\x90\\xD0\\xAD\\xD0\\xAD\\xE6\\x8F\\x90\\xE8\\xB4\\xBC\\xE8\\xB4\\xBC\\xD0\\xAD\\xE5\\xBE\\xB7\\xE8\\xB4\\xBC\\xE8\\xB4\\xBC\\xE5\\xB0\\x94\\xE6\\x8F\\x90\\xE8\\x89\\xBE\\xE6\\x8F\\x90\\xE8\\xB4\\xBC\\xE5\\xB0\\x94\\xE6\\x8F\\x90\\xE8\\xB4\\xBC\\xE8\\x89\\xBE\\xD0\\xAD\\xE8\\x89\\xBE" and
            pe.signatures[i].serial == "00:84:81:7e:07:28:8a:50:25:b9:43:55:70:e7:fe:c1:d3"
        )
}

rule INDICATOR_KB_CERT_4d26bab89fcf7ff9fa4dc4847e563563 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "2be34a7a39df38f66d5550dcfa01850c8f165c81"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "qvarn pty ltd" and
            pe.signatures[i].serial == "4d:26:ba:b8:9f:cf:7f:f9:fa:4d:c4:84:7e:56:35:63"
        )
}

rule INDICATOR_KB_CERT_00d9d419c9095a79b1f764297addb935da {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "7d45ec21c0d6fd0eb84e4271655eb0e005949614"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Nova soft" and
            pe.signatures[i].serial == "00:d9:d4:19:c9:09:5a:79:b1:f7:64:29:7a:dd:b9:35:da"
        )
}

rule INDICATOR_KB_CERT_02e44d7d1d38ae223b27a02bacd79b53 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "34e0ecae125302d5b1c4a7412dbf17bdc1b59f04"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Zhuhai Kingsoft Office Software Co., Ltd." and
            pe.signatures[i].serial == "02:e4:4d:7d:1d:38:ae:22:3b:27:a0:2b:ac:d7:9b:53"
        )
}

rule INDICATOR_KB_CERT_041868dd49840ff44f8e3d3070568350 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "e104f236e3ee7d21a0ea8053fe8fc5c412784079"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Zhuhai Kingsoft Office Software Co., Ltd." and
            pe.signatures[i].serial == "04:18:68:dd:49:84:0f:f4:4f:8e:3d:30:70:56:83:50"
        )
}

rule INDICATOR_KB_CERT_c501b7176b29a3cb737361cf85414874 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "0788801185a6bf70b805c2b97a7c6ce66cfbb38d"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE5\\x8B\\x92\\xE8\\x89\\xBE\\xE8\\xAF\\xB6\\xE8\\x89\\xBE\\xE8\\xB4\\x9D\\xE8\\xAF\\xB6\\xE8\\xAF\\xB6\\xE8\\xB4\\x9D\\xE5\\x90\\xBE\\xE5\\xBC\\x97\\xE5\\xBC\\x97\\xE5\\x90\\xBE\\xE8\\xAF\\xB6\\xE5\\x8B\\x92\\xE8\\xB4\\x9D\\xE5\\xBC\\x97\\xE5\\x90\\xBE\\xE5\\x90\\xBE\\xE8\\xAF\\xB6\\xE8\\x89\\xBE\\xE5\\x90\\xBE\\xE5\\x90\\xBE\\xE8\\x89\\xBE\\xE5\\xBC\\x97\\xE5\\xBC\\x97" and
            pe.signatures[i].serial == "c5:01:b7:17:6b:29:a3:cb:73:73:61:cf:85:41:48:74"
        )
}

rule INDICATOR_KB_CERT_234bf4ef892df307373638014b35ab37 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "348f7e395c77e29c1e17ef9d9bd24481657c7ae7"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            //pe.signatures[i].subject contains "\\xD0\\x9E\\xD0\\x9E\\xD0\\x9E \"\\xD0\\xA1\\xD0\\x9A\\xD0\\x90\\xD0\\xA0\\xD0\\x90\\xD0\\x91\\xD0\\x95\\xD0\\x99\"" and
            pe.signatures[i].serial == "23:4b:f4:ef:89:2d:f3:07:37:36:38:01:4b:35:ab:37"
        )
}

rule INDICATOR_KB_CERT_c650ae531100a91389a7f030228b3095 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "05eebfec568abc5fc4b2fd9e5eca087b02e49f53"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "POKEROWA STRUNA SP Z O O" and
            pe.signatures[i].serial == "c6:50:ae:53:11:00:a9:13:89:a7:f0:30:22:8b:30:95"
        )
}

rule INDICATOR_KB_CERT_4f8ebbb263f3cbe558d37118c43f8d58 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "3f27a35fe7af06977138d02ad83ddbf13a67b7c3"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Maxthon Technology Co, Ltd." and
            pe.signatures[i].serial == "4f:8e:bb:b2:63:f3:cb:e5:58:d3:71:18:c4:3f:8d:58"
        )
}

rule INDICATOR_KB_CERT_01ea62e443cb2250c870ff6bb13ba98e {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "f293eed3ff3d548262cddc43dce58cfc7f763622"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Tencent Technology(Shenzhen) Company Limited" and
            pe.signatures[i].serial == "01:ea:62:e4:43:cb:22:50:c8:70:ff:6b:b1:3b:a9:8e"
        )
}

rule INDICATOR_KB_CERT_726ee7f5999b9e8574ec59969c04955c {
    meta:
        author = "ditekSHen"
        description = "Detects IntelliAdmin commercial remote administration signing certificate"
        thumbprint = "2fb952bc1e3fcf85f68d6e2cb5fc46a519ce3fa9"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "IntelliAdmin, LLC" and
            pe.signatures[i].serial == "72:6e:e7:f5:99:9b:9e:85:74:ec:59:96:9c:04:95:5c"
        )
}

rule INDICATOR_KB_CERT_0a005d2e2bcd4137168217d8c727747c {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "df788aa00eb400b552923518108eb1d4f5b7176b"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Beijing JoinHope Image Technology Ltd." and
            pe.signatures[i].serial == "0a:00:5d:2e:2b:cd:41:37:16:82:17:d8:c7:27:74:7c"
        )
}

rule INDICATOR_KB_CERT_00d3d74ae548830d5b1bca9856e16c564a {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "3f996b75900d566bc178f36b3f4968e2a08365e8"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Insite Software Inc." and
            pe.signatures[i].serial == "00:d3:d7:4a:e5:48:83:0d:5b:1b:ca:98:56:e1:6c:56:4a"
        )
}

rule INDICATOR_KB_CERT_41f8253e1ceafbfd8e49f32c34a68f9e {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "02e739740b88328ac9c4a6de0ee703b7610f977b"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Shenzhen Smartspace Software technology Co.,Limited" and
            pe.signatures[i].serial == "41:f8:25:3e:1c:ea:fb:fd:8e:49:f3:2c:34:a6:8f:9e"
        )
}

rule INDICATOR_KB_CERT_0a5b4f67ad8b22afc2debe6ce5f8f679 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "1213865af7ddac1568830748dbdda21498dfb0ba"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Farad LLC" and
            pe.signatures[i].serial == "0a:5b:4f:67:ad:8b:22:af:c2:de:be:6c:e5:f8:f6:79"
        )
}

rule INDICATOR_KB_CERT_65cd323c2483668b90a44a711d2a6b98 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "188810cf106a5f38fe8aa0d494cbd027da9edf97"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Giperion" and
            pe.signatures[i].serial == "65:cd:32:3c:24:83:66:8b:90:a4:4a:71:1d:2a:6b:98"
        )
}

rule INDICATOR_KB_CERT_0d07705fa0e0c4827cc287cfcdec20c4 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "ba5f8c3d961d0df838361b4aa5ec600a70abe1e0"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Binance Holdings Limited" and
            pe.signatures[i].serial == "0d:07:70:5f:a0:e0:c4:82:7c:c2:87:cf:cd:ec:20:c4"
        )
}

rule INDICATOR_KB_CERT_0f7e3fda780e47e171864d8f5386bc05 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "1e3dd5576fc57fa2dd778221a60bd33f97087f74"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Louhos Solutions Oy" and
            pe.signatures[i].serial == "0f:7e:3f:da:78:0e:47:e1:71:86:4d:8f:53:86:bc:05"
        )
}

rule INDICATOR_KB_CERT_0f9d91c6aba86f4e54cbb9ef57e68346 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "3c92c9274ab6d3dd520b13029a2490c4a1d98bc0"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Kaspersky Lab" and
            pe.signatures[i].serial == "0f:9d:91:c6:ab:a8:6f:4e:54:cb:b9:ef:57:e6:83:46"
        )
}

rule INDICATOR_KB_CERT_07f9d80b85ceff7ee3f58dc594fe66b6 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "bf9254919794c1075ea027889c5d304f1121c653"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Kaspersky Lab" and
            pe.signatures[i].serial == "07:f9:d8:0b:85:ce:ff:7e:e3:f5:8d:c5:94:fe:66:b6"
        )
}

rule INDICATOR_KB_CERT_c2cbbd946bc3fdb944d522931d61d51a {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with Sordum Software certificate, particularly Defender Control"
        thumbprint = "f5e71628a478a248353bf0177395223d2c5a0e43"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Sordum Software" and
            pe.signatures[i].serial == "c2:cb:bd:94:6b:c3:fd:b9:44:d5:22:93:1d:61:d5:1a"
        )
}

rule INDICATOR_KB_CERT_6e3b09f43c3a0fd53b7d600f08fae2b5 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "677054afcbfecb313f93f27ed159055dc1559ad0"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Divisible Limited" and
            pe.signatures[i].serial == "6e:3b:09:f4:3c:3a:0f:d5:3b:7d:60:0f:08:fa:e2:b5"
        )
}

rule INDICATOR_KB_CERT_00aa12c95d2bcde0ce141c6f1145b0d7ef {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "1383c4aa2900882f9892696c537e83f1fb20a43f"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PROKON, OOO" and
            pe.signatures[i].serial == "00:aa:12:c9:5d:2b:cd:e0:ce:14:1c:6f:11:45:b0:d7:ef"
        )
}

rule INDICATOR_KB_CERT_03e9eb4dff67d4f9a554a422d5ed86f3 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "8f2de7e770a8b1e412c2de131064d7a52da62287"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "philandro Software GmbH" and
            pe.signatures[i].serial == "03:e9:eb:4d:ff:67:d4:f9:a5:54:a4:22:d5:ed:86:f3"
        )
}

rule INDICATOR_KB_CERT_4a7f07c5d4ad2e23f9e8e03f0e229dd4 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "b37e7f9040c4adc6d29da6829c7a35a2f6a56fdb"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Danalis LLC" and
            pe.signatures[i].serial == "4a:7f:07:c5:d4:ad:2e:23:f9:e8:e0:3f:0e:22:9d:d4"
        )
}

rule INDICATOR_KB_CERT_c6d7ad852af211bf48f19cc0242dcd72 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "bddcef09f222ea4270d4a1811c10f4fcf98e4125"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "APDZQKILIIQVIJSCTY" and
            pe.signatures[i].serial == "c6:d7:ad:85:2a:f2:11:bf:48:f1:9c:c0:24:2d:cd:72"
        )
}

rule INDICATOR_KB_CERT_0084888d5a12228e8950683ecdab62fe7a {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "390b23ed9750745e8441e35366b294a2a5c66fcd"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Ub30 Limited" and
            pe.signatures[i].serial == "00:84:88:8d:5a:12:22:8e:89:50:68:3e:cd:ab:62:fe:7a"
        )
}

rule INDICATOR_KB_CERT_709d547a2f09d39c4c2334983f2cbf50 {
    meta:
        author = "ditekSHen"
        description = "Detects executables signed with stolen, revoked or invalid certificates"
        thumbprint = "f10095c5e36e6bce0759f52dd11137756adc3b53"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BMUZVYUGWSQWLAIISX" and
            pe.signatures[i].serial == "70:9d:54:7a:2f:09:d3:9c:4c:23:34:98:3f:2c:bf:50"
        )
}