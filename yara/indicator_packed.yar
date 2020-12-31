import "pe"

rule INDICATOR_EXE_Packed_ConfuserEx {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with ConfuserEx Mod"
        snort2_sid = "930016-930018"
        snort3_sid = "930005-930006"
    strings:
        $s1 = "ConfuserEx " ascii
        $s2 = "ConfusedByAttribute" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_EXE_Packed_ConfuserEx_Custom {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with ConfuserEx Custom; outside of GIT"
    strings:
        $s1 = { 43 6f 6e 66 75 73 65 72 45 78 20 76 [1-2] 2e [1-2] 2e [1-2] 2d 63 75 73 74 6f 6d }
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_EXE_Packed_ConfuserExMod_BedsProtector {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with ConfuserEx Mod Beds Protector"
        snort2_sid = "930019-930024"
        snort3_sid = "930007-930008"
    strings:
        $s1 = "Beds Protector v" ascii
        $s2 = "Beds-Protector-v" ascii
    condition:
        uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_EXE_Packed_ConfuserExMod_Trinity {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with ConfuserEx Mod Trinity Protector"
        snort2_sid = "930025-930030"
        snort3_sid = "930009-930010"
    strings:
        $s1 = "Trinity0-protecor|" ascii
        $s2 = "#TrinityProtector" fullword ascii
        $s3 = /Trinity\d-protector\|/ ascii
    condition:
        uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_EXE_Packed_PS2EXE {
    meta:
        author = "ditekSHen"
        description = "Detects executables built or packed with PS2EXE"
        snort2_sid = "930004-930006"
        snort3_sid = "930001"
    strings:
        $s1 = "PS2EXE" fullword ascii
        $s2 = "PS2EXEApp" fullword ascii
        $s3 = "PS2EXEHost" fullword ascii
        $s4 = "PS2EXEHostUI" fullword ascii
        $s5 = "PS2EXEHostRawUI" fullword ascii
    condition:
         uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_EXE_Packed_LSD {
    meta:
        author = "ditekSHen"
        description = "Detects executables built or packed with LSD packer"
        snort2_sid = "930058-930060"
        snort3_sid = "930021"
    strings:
        $s1 = "This file is packed with the LSD executable packer" ascii
        $s2 = "http://lsd.dg.com" ascii
        $s3 = "&V0LSD!$" fullword ascii
    condition:
         (uint16(0) == 0x5a4d or uint16(0)== 0x457f) and 1 of them
}

rule INDICATOR_EXE_Packed_AspireCrypt {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with AspireCrypt"
        snort2_sid = "930013-930015"
        snort3_sid = "930004"
    strings:
        $s1 = "AspireCrypt" fullword ascii
        $s2 = "aspirecrypt.net" ascii
        $s3 = "protected by AspireCrypt" ascii
    condition:
        uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_EXE_Packed_Spices {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with 9Rays.Net Spices.Net Obfuscator."
        snort2_sid = "930001-930003"
        snort3_sid = "930000"
    strings:
        $s1 = "9Rays.Net Spices.Net" ascii
        $s2 = "protected by 9Rays.Net Spices.Net Obfuscator" ascii
    condition:
        uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_JAVA_Packed_Allatori {
    meta:
        author = "ditekSHen"
        description = "Detects files packed with Allatori Java Obfuscator"
    strings:
        $s1 = "# Obfuscation by Allatori Obfuscator" ascii wide
    condition:
        all of them
}

rule INDICATOR_EXE_Packed_ASPack {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with ASPack"
        snort2_sid = "930007-930009"
        snort3_sid = "930002"
    //strings:
    //    $s1 = { 00 00 ?? 2E 61 73 70 61 63 6B 00 00 }
    condition:
        uint16(0) == 0x5a4d and //all of them or
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".aspack"
            )
        )
}

rule INDICATOR_EXE_Packed_Titan {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with Titan"
        snort2_sid = "930010-930012"
        snort3_sid = "930003"
    strings:
        $s1 = { 00 00 ?? 2e 74 69 74 61 6e 00 00 }
    condition:
        uint16(0) == 0x5a4d and all of them or 
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".titan"
            )
        )
}

rule INDICATOR_EXE_Packed_aPLib {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with aPLib."
    strings:
        $header = { 41 50 33 32 18 00 00 00 [0-35] 4D 38 5A 90 }
    condition:
        ((uint32(0) == 0x32335041 and uint32(24) == 0x905a384d) or (uint16(0) == 0x5a4d and $header ))
}

rule INDICATOR_EXE_Packed_LibZ {
    meta:
        author = "ditekSHen"
        description = "Detects executables built or packed with LibZ"
        snort2_sid = "930055-930057"
        snort3_sid = "930019-930020"
    strings:
        $s1 = "LibZ.Injected" fullword ascii
        $s2 = "{0:N}.dll" fullword wide
        $s3 = "asmz://(?<guid>[0-9a-fA-F]{32})/(?<size>[0-9]+)(/(?<flags>[a-zA-Z0-9]*))?" fullword wide
        $s4 = "Software\\Softpark\\LibZ" fullword wide
        $s5 = "(AsmZ/{" wide
        $s6 = "asmz://" ascii
        $s7 = "GetRegistryDWORD" ascii
        $s8 = "REGISTRY_KEY_NAME" fullword ascii
        $s9 = "REGISTRY_KEY_PATH" fullword ascii
        $s10 = "InitializeDecoders" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 5 of them
}

rule INDICATOR_EXE_Packed_Enigma {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with Enigma"
        snort2_sid = "930052-930054"
        snort3_sid = "930018"
    strings:
        $s1 = ".enigma0" fullword ascii
        $s2 = ".enigma1" fullword ascii
        $s3 = ".enigma2" fullword ascii
        $s4 = ".enigma3" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 2 of them or
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".enigma0" or
                pe.sections[i].name == ".enigma1" or
                pe.sections[i].name == ".enigma2" or
                pe.sections[i].name == ".enigma3"
            )
        )
}

rule INDICATOR_EXE_Python_Byte_Compiled {
    meta:
        author = "ditekSHen"
        description = "Detects python-byte compiled executables"
    strings:
        $s1 = "b64decode" ascii
        $s2 = "decompress" ascii
    condition:
        uint32(0) == 0x0a0df303 and filesize < 5KB and all of them
}

rule INDICATOR_MSI_EXE2MSI {
    meta:
        author = "ditekSHen"
        description = "Detects executables converted to .MSI packages using a free online converter."
        snort2_sid = "930061-930063"
        snort3_sid = "930022"
    strings:
        $winin = "Windows Installer" ascii
        $title = "Exe to msi converter free" ascii
    condition:
        uint32(0) == 0xe011cfd0 and ($winin and $title)
}

rule INDICATOR_EXE_Packed_MPress {
    meta:
        author = "ditekSHen"
        description = "Detects executables built or packed with MPress PE compressor"
        snort2_sid = "930031-930033"
        snort3_sid = "930011"
    strings:
        $s1 = ".MPRESS1" fullword ascii
        $s2 = ".MPRESS2" fullword ascii
    condition:
         uint16(0) == 0x5a4d and 1 of them or
         for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".MPRESS1" or
                pe.sections[i].name == ".MPRESS2"
            )
        )
}

rule INDICATOR_EXE_Packed_Nate {
    meta:
        author = "ditekSHen"
        description = "Detects executables built or packed with Nate packer"
        snort2_sid = "930034-930036"
        snort3_sid = "930012"
    strings:
        $s1 = "@.nate0" fullword ascii
        $s2 = "`.nate1" fullword ascii
    condition:
         uint16(0) == 0x5a4d and 1 of them or
         for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".nate0" or
                pe.sections[i].name == ".nate1"
            )
        )
}

rule INDICATOR_EXE_Packed_VMProtect {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with VMProtect."
        snort2_sid = "930049-930051"
        snort3_sid = "930017"
    strings:
        $s1 = ".vmp0" fullword ascii
        $s2 = ".vmp1" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them or
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".vmp0" or
                pe.sections[i].name == ".vmp1"
            )
        )
}

rule INDICATOR_EXE_DotNET_Encrypted {
    meta:
        author = "ditekSHen"
        description = "Detects encrypted or obfuscated .NET executables"
    strings:
        $s1 = "FromBase64String" fullword ascii
        $s2 = "ToCharArray" fullword ascii
        $s3 = "ReadBytes" fullword ascii
        $s4 = "add_AssemblyResolve" fullword ascii
        $s5 = "MemoryStream" fullword ascii
        $s6 = "CreateDecryptor" fullword ascii

         // 08 00 00 00 00 00 1e 01 00 01 00 54 02 16 WrapNonExceptionThrows 01
        $bytes1 = { 08 01 00 08 00 00 00 00 00 1e 01 00 01 00 54 02
                    16 57 72 61 70 4e 6f 6e 45 78 63 65 70 74 69 6f 
                    6e 54 68 72 6f 77 73 01 }
        // 00 00 BSJB...v2.0.50727 00 00 00 00 05 00
        // 00 00 BSJB...v4.0.30319 00 00 00 00 05 00
        $bytes2 = { 00 00 42 53 4a 42 01 00 01 00 00 00 00 00 0c 00 
                    00 00 76 3? 2e 3? 2e ?? ?? ?? ?? ?? 00 00 00 00
                    05 00 }
        // #Strings...#US...#GUID...#Blob
        $bytes3 = { 00 00 23 53 74 72 69 6e 67 73 00 00 00 00 [5] 00 
                    00 00 23 55 53 00 [5] 00 00 00 23 47 55 49 44 00 
                    00 00 [6] 00 00 23 42 6c 6f 62 00 00 00 }
        // .GetString.set_WorkingDirectory.WaitForExit.Close.Thread.System.Threading.Sleep.ToInt32.get_MainModule.ProcessModule.get_FileName.Split.
        $bytes4 = { 00 47 65 74 53 74 72 69 6e 67 00 73 65 74 5f 57
                    6f 72 6b 69 6e 67 44 69 72 65 63 74 6f 72 79 00
                    57 61 69 74 46 6f 72 45 78 69 74 00 43 6c 6f 73
                    65 00 54 68 72 65 61 64 00 53 79 73 74 65 6d 2e
                    54 68 72 65 61 64 69 6e 67 00 53 6c 65 65 70 00
                    54 6f 49 6e 74 33 32 00 67 65 74 5f 4d 61 69 6e
                    4d 6f 64 75 6c 65 00 50 72 6f 63 65 73 73 4d 6f
                    64 75 6c 65 00 67 65 74 5f 46 69 6c 65 4e 61 6d
                    65 00 53 70 6c 69 74 00 }
    condition:
        uint16(0) == 0x5a4d and 3 of ($bytes*) and all of ($s*)
}

rule INDICATOR_PY_Packed_PyMinifier {
    meta:
        author = "ditekSHen"
        description = "Detects python code potentially obfuscated using PyMinifier"
    strings:
        $s1 = "exec(lzma.decompress(base64.b64decode("
    condition:
        (uint32(0) == 0x6f706d69 or uint16(0) == 0x2123 or uint16(0) == 0x0a0d or uint16(0) == 0x5a4d) and all of them
}

rule INDICATOR_EXE_Packed_BoxedApp {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with BoxedApp"
        snort2_sid = "930037-930042"
        snort3_sid = "930013-930014"
    strings:
        $s1 = "BoxedAppSDK_HookFunction" fullword ascii
        $s2 = "BoxedAppSDK_StaticLib.cpp" ascii
        $s3 = "embedding BoxedApp into child processes: %s" ascii
        $s4 = "GetCommandLineA preparing to intercept" ascii
    condition:
        uint16(0) == 0x5a4d and 2 of them or
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name contains ".bxpck"
            )
        )
}

rule INDICATOR_EXE_Packed_eXPressor {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with eXPressor"
        snort2_sid = "930043-930048"
        snort3_sid = "930015-930016"
    strings:
        $s1 = "eXPressor_InstanceChecker_" fullword ascii
        $s2 = "This application was packed with an Unregistered version of eXPressor" ascii
        $s3 = ", please visit www.cgsoftlabs.ro" ascii
        $s4 = /eXPr-v\.\d+\.\d+/ ascii
    condition:
        uint16(0) == 0x5a4d and 2 of them or
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name contains ".ex_cod"
            )
        )
}

rule INDICATOR_EXE_Packed_MEW {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with MEW"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == "MEW" or
                pe.sections[i].name == "\x02\xd2u\xdb\x8a\x16\xeb\xd4"
            )
        )
}

rule INDICATOR_EXE_Packed_RLPack {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with RLPACK"
        snort2_sid = "930064-930066"
        snort3_sid = "930023"
    strings:
        $s1 = ".packed" fullword ascii
        $s2 = ".RLPack" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them or
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".RLPack"
            )
        )
}

rule INDICATOR_EXE_Packed_Cassandra {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with Cassandra/CyaX"
    strings:
        $s1 = "AntiEM" fullword ascii wide
        $s2 = "AntiSB" fullword ascii wide
        $s3 = "Antis" fullword ascii wide
        $s4 = "XOR_DEC" fullword ascii wide
        $s5 = "StartInject" fullword ascii wide
        $s6 = "DetectGawadaka" fullword ascii wide
        $c1 = "CyaX-Sharp" ascii wide
        $c2 = "CyaX_Sharp" ascii wide
        $c3 = "CyaX-PNG" ascii wide
        $c4 = "CyaX_PNG" ascii wide
        $pdb = "\\CyaX\\obj\\Debug\\CyaX.pdb" ascii wide
    condition:
        (uint16(0) == 0x5a4d and (4 of ($s*) or 2 of ($c*) or $pdb)) or (7 of them)
}

rule INDICATOR_EXE_Packed_Themida {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with Themida"
        snort2_sid = "930067-930069"
        snort3_sid = "930024"
    strings:
        $s1 = ".themida" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them or
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".themida"
            )
        )
}

rule INDICATOR_EXE_Packed_SilentInstallBuilder {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with Silent Install Builder"
        snort2_sid = "930070-930072"
        snort3_sid = "930025"
    strings:
        $s1 = "C:\\Users\\Operations\\Source\\Workspaces\\Sib\\Sibl\\Release\\Sibuia.pdb" fullword ascii
        $s2 = "->mb!Silent Install Builder Demo Package." fullword wide
    condition:
        uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_EXE_Packed_NyanXCat_CSharpLoader {
    meta:
        author = "ditekSHen"
        description = "Detects .NET executables utilizing NyanX-CAT C# Loader"
        snort2_sid = "930073-930075"
        snort3_sid = "930026"
    strings:
        $s1 = { 00 50 72 6f 67 72 61 6d 00 4c 6f 61 64 65 72 00 4e 79 61 6e 00 }
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_EXE_Packed_Loader {
    meta:
        author = "ditekSHen"
        description = "Detects packed executables observed in Molerats"
    strings:
        $l1 = "loaderx86.dll" fullword ascii
        $l2 = "loaderx86" fullword ascii
        $l3 = "loaderx64.dll" fullword ascii
        $l4 = "loaderx64" fullword ascii
        $s1 = "ImportCall_Zw" wide
        $s2 = "DllInstall" ascii wide
        $s3 = "evb*.tmp" fullword wide
        $s4 = "WARNING ZwReadFileInformation" ascii
        $s5 = "LoadLibrary failed with module " fullword wide
    condition:
        uint16(0) == 0x5a4d and 2 of ($l*) and 4 of ($s*)
}

rule INDICATOR_EXE_Packed_Bonsai {
    meta:
         author = "ditekSHen"
        description = "Detects .NET executables developed using Bonsai"
    strings:
        $bonsai1 = "<Bonsai." ascii
        $bonsai2 = "Bonsai.Properties" ascii
        $bonsai3 = "Bonsai.Core.dll" fullword wide
        $bonsai4 = "Bonsai.Design." wide
    condition:
        uint16(0) == 0x5a4d and 2 of ($bonsai*)
}

rule INDICATOR_EXE_Packed_UPolyX {
    meta:
        author = "ditekSHen"
        description = "Detects executables packed with UPolyX"
    strings:
        $s1 = { 81 fd 00 fb ff ff 83 d1 ?? 8d 14 2f 83 fd fc 76 ?? 8a 02 42 88 07 47 49 75 }
        //$s2 = { e2 ?? ff ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
        //$s3 = { 55 8b ec ?? 00 bd 46 00 8b ?? b9 ?? 00 00 00 80 ?? ?? 51 }
        //$s4 = { bb ?? ?? ?? ?? 83 ec 04 89 1c 24 ?? b9 ?? 00 00 00 80 33 }
        //$s5 = { e8 00 00 00 00 59 83 c1 07 51 c3 c3 }
        //$s6 = { 83 ec 04 89 ?? 24 59 ?? ?? 00 00 00 }
    condition:
        uint16(0) == 0x5a4d and 1 of them and
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name contains "UPX"
            )
        )
}
