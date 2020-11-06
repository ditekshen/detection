import "pe"

rule INDICATOR_EXE_Packed_ConfuserEx {
    meta:
        description = "Detects executables packed with ConfuserEx Mod"
        author = "ditekSHen"
    strings:
        $s1 = "ConfuserEx " ascii
        $s2 = "ConfusedByAttribute" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_EXE_Packed_ConfuserExMod_BedsProtector {
    meta:
        description = "Detects executables packed with ConfuserEx Mod Beds Protector"
        author = "ditekSHen"
    strings:
        $s1 = "Beds Protector v" ascii
        $s2 = "Beds-Protector-v" ascii
    condition:
        uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_EXE_Packed_ConfuserEx_Trinity {
    meta:
        description = "Detects executables packed with ConfuserEx Mod Trinity Protector"
        author = "ditekSHen"
    strings:
        $s1 = "Trinity0-protecor|" ascii
        $s2 = "#TrinityProtector" fullword ascii
        $s3 = /Trinity\d-protector\|/ ascii
    condition:
        uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_EXE_Packed_PS2EXE {
    meta:
        description = "Detects executables built or packed with PS2EXE"
        author = "ditekSHen"
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
        description = "Detects executables built or packed with LSD packer"
        author = "ditekSHen"
    strings:
        $s1 = "This file is packed with the LSD executable packer" ascii
        $s2 = "http://lsd.dg.com" ascii
        $s3 = "&V0LSD!$" fullword ascii
    condition:
         (uint16(0) == 0x5a4d or uint16(0)== 0x457f) and 1 of them
}

rule INDICATOR_EXE_Packed_AspireCrypt {
    meta:
        description = "Detects executables packed with AspireCrypt"
        author = "ditekSHen"
    strings:
        $s1 = "AspireCrypt" fullword ascii
        $s2 = "aspirecrypt.net" ascii
        $s3 = "protected by AspireCrypt" ascii
    condition:
        uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_EXE_Packed_Spices {
    meta:
        description = "Detects executables packed with 9Rays.Net Spices.Net Obfuscator."
        author = "ditekSHen"
    strings:
        $s1 = "9Rays.Net Spices.Net" ascii
        $s2 = "protected by 9Rays.Net Spices.Net Obfuscator" ascii
    condition:
        uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_JAVA_Packed_Allatori {
    meta:
        description = "Detects files packed with Allatori Java Obfuscator"
        author = "ditekSHen"
    strings:
        $s1 = "# Obfuscation by Allatori Obfuscator" ascii wide
    condition:
        all of them
}

rule INDICATOR_EXE_Packed_ASPack {
    meta:
        description = "Detects executables packed with ASPack"
        author = "ditekSHen"
    strings:
        $s1 = { 00 00 ?? 2E 61 73 70 61 63 6B 00 00 }
    condition:
        uint16(0) == 0x5a4d and all of them or
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".aspack"
            )
        )
}

rule INDICATOR_EXE_Packed_Titan {
    meta:
        description = "Detects executables packed with Titan"
        author = "ditekSHen"
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
        description = "Detects executables packed with aPLib."
        author = "ditekSHen"
    strings:
        $header = { 41 50 33 32 18 00 00 00 [0-35] 4D 38 5A 90 }
    condition:
        ((uint32(0) == 0x32335041 and uint32(24) == 0x905a384d) or (uint16(0) == 0x5a4d and $header ))
}

rule INDICATOR_EXE_Packed_LibZ {
    meta:
        description = "Detects executables built or packed with LibZ"
        author = "ditekSHen"
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
        description = "Detects executables packed with Enigma"
        author = "ditekSHen"
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
        description = "Detects python-byte compiled executables"
        author = "ditekSHen"
    strings:
        $s1 = "b64decode" ascii
        $s2 = "decompress" ascii
    condition:
        uint32(0) == 0x0a0df303 and filesize < 5KB and all of them
}

rule INDICATOR_MSI_EXE2MSI {
    meta:
        description = "Detects executables converted to .MSI packages using a free online converter."
        author = "ditekSHen"
    strings:
        $winin = "Windows Installer" ascii
        $title = "Exe to msi converter free" ascii
    condition:
        uint32(0) == 0xe011cfd0 and ($winin and $title)
}

rule INDICATOR_EXE_Packed_MPress {
    meta:
        description = "Detects executables built or packed with MPress PE compressor"
        author = "ditekSHen"
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
        description = "Detects executables built or packed with Nate packer"
        author = "ditekSHen"
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
        description = "Detects executables packed with VMProtect."
        author = "ditekSHen"
    strings:
        $s1 = ".vmp0" fullword ascii
        $s2 = ".vmp1" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 1 of them or
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == ".vmp0" or
                pe.sections[i].name == ".vmp1"
            )
        )
}

rule INDICATOR_EXE_Packed_Salfram {
    meta:
        description = "Detects Salfram executables"
        reference = "https://blog.talosintelligence.com/2020/09/salfram-robbing-place-without-removing.html"
        author = "ditekSHen"
    strings:
        $s1 = "This Salfram cannot be run is DOS mode" fullword ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_EXE_DotNET_Encrypted {
    meta:
        description = "Detects encrypted or obfuscated .NET executables"
        author = "ditekSHen"
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
        description = "Detects python code potentially obfuscated using PyMinifier"
        author = "ditekSHen"
    strings:
        $s1 = "exec(lzma.decompress(base64.b64decode("
    condition:
        (uint32(0) == 0x6f706d69 or uint16(0) == 0x2123 or uint16(0) == 0x0a0d or uint16(0) == 0x5a4d) and all of them
}

rule INDICATOR_EXE_Packed_BoxedApp {
    meta:
        description = "Detects executables packed with BoxedApp"
        author = "ditekSHen"
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
        description = "Detects executables packed with eXPressor"
        author = "ditekSHen"
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
        description = "Detects executables packed with MEW"
        author = "ditekSHen"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0 .. pe.number_of_sections) : (
            (
                pe.sections[i].name == "MEW" or
                pe.sections[i].name == "\x02\xd2u\xdb\x8a\x16\xeb\xd4"
            )
        )
}
