import "pe"

rule INDICATOR_SUSPICIOUS_Ransomware {
    meta:
        description = "detects command variations typically used by ransomware"
        author = "ditekSHen"
    strings:
        $cmd1 = "cmd /c \"WMIC.exe shadowcopy delet\"" ascii wide nocase
        $cmd2 = "vssadmin.exe Delete Shadows /all /quiet" ascii wide nocase
        $cmd3 = "vssadmin Delete Shadows /all /quiet" ascii wide nocase
        $cmd4 = "bcdedit /set {default} recoveryenabled no" ascii wide nocase
        $cmd5 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii wide nocase
        $cmd6 = "wmic SHADOWCOPY DELETE" ascii wide nocase
        $cmd7 = "wbadmin delete catalog -quiet" ascii wide nocase
    condition:
        (uint16(0) == 0x5a4d and 1 of them) or (2 of them)
}

rule INDICATOR_SUSPICIOUS_ReflectiveLoader {
    meta:
        description = "detects Reflective DLL injection artifacts"
        author = "ditekSHen"
    strings:
        $s1 = "_ReflectiveLoader@" ascii wide
        $s2 = "ReflectiveLoader@" ascii wide
    condition:
        uint16(0) == 0x5a4d and (1 of them or (
            pe.exports("ReflectiveLoader@4") or
            pe.exports("_ReflectiveLoader@4") or
            pe.exports("ReflectiveLoader")
            )
        )
}

rule INDICATOR_SUSPICIOUS_IMG_Embedded_Archive {
    meta:
        description = "Detects images embedding archives. Observed in TheRat RAT."
        author = "@ditekSHen"
    strings:
        $sevenzip1 = { 37 7a bc af 27 1c 00 04 } // 7ZIP, regardless of password-protection
        $sevenzip2 = { 37 e4 53 96 c9 db d6 07 } // 7ZIP zisofs compression format    
        $zipwopass = { 50 4b 03 04 14 00 00 00 } // None password-protected PKZIP
        $zipwipass = { 50 4b 03 04 33 00 01 00 } // Password-protected PKZIP
        $zippkfile = { 50 4b 03 04 0a 00 02 00 } // PKZIP
        $rarheade1 = { 52 61 72 21 1a 07 01 00 } // RARv4
        $rarheade2 = { 52 65 74 75 72 6e 2d 50 } // RARv5
        $rarheade3 = { 52 61 72 21 1a 07 00 cf } // RAR
        $mscabinet = { 4d 53 46 54 02 00 01 00 } // Microsoft cabinet file
        $zlockproe = { 50 4b 03 04 14 00 01 00 } // ZLock Pro encrypted ZIP
        $winzip    = { 57 69 6E 5A 69 70 }       // WinZip compressed archive 
        $pklite    = { 50 4B 4C 49 54 45 }       // PKLITE compressed ZIP archive
        $pksfx     = { 50 4B 53 70 58 }          // PKSFX self-extracting executable compressed file
    condition:
        // JPEG or JFIF or PNG or BMP
        (uint32(0) == 0xe0ffd8ff or uint32(0) == 0x474e5089 or uint16(0) == 0x4d42) and 1 of them
}

rule INDICATOR_SUSPICIOUS_EXE_UACBypass_EventViewer {
    meta:
        description = "detects Windows exceutables potentially bypassing UAC using eventvwr.exe"
        author = "ditekSHen"
    strings:
        $s1 = "\\Classes\\mscfile\\shell\\open\\command" ascii wide nocase
        $s2 = "eventvwr.exe" ascii wide nocase
    condition:
       uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_SUSPICIOUS_EXE_UACBypass_CleanMgr {
    meta:
        description = "detects Windows exceutables potentially bypassing UAC using cleanmgr.exe"
        author = "ditekSHen"
    strings:
        $s1 = "\\Enviroment\\windir" ascii wide nocase
        $s2 = "\\system32\\cleanmgr.exe" ascii wide nocase
    condition:
       uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_SUSPICIOUS_EXE_Enable_OfficeMacro {
    meta:
        description = "Detects Windows executables referencing Office macro registry keys. Observed modifying Office configurations via the registy to enable macros"
        author = "@ditekSHen"
    strings:
        $s1 = "\\Word\\Security\\VBAWarnings" ascii wide
        $s2 = "\\PowerPoint\\Security\\VBAWarnings" ascii wide
        $s3 = "\\Excel\\Security\\VBAWarnings" ascii wide

        $h1 = "5c576f72645c53656375726974795c5642415761726e696e6773" nocase ascii wide
        $h2 = "5c506f776572506f696e745c53656375726974795c5642415761726e696e6773" nocase ascii wide
        $h3 = "5c5c457863656c5c5c53656375726974795c5c5642415761726e696e6773" nocase ascii wide

        $d1 = "5c%57%6f%72%64%5c%53%65%63%75%72%69%74%79%5c%56%42%41%57%61%72%6e%69%6e%67%73" nocase ascii
        $d2 = "5c%50%6f%77%65%72%50%6f%69%6e%74%5c%53%65%63%75%72%69%74%79%5c%56%42%41%57%61%72%6e%69%6e%67%73" nocase ascii
        $d3 = "5c%5c%45%78%63%65%6c%5c%5c%53%65%63%75%72%69%74%79%5c%5c%56%42%41%57%61%72%6e%69%6e%67%73" nocase ascii
    condition:
        uint16(0) == 0x5a4d and (2 of ($s*) or 2 of ($h*) or 2 of ($d*))
}

rule INDICATOR_SUSPICIOUS_EXE_Disable_OfficeProtectedView {
    meta:
        description = "Detects Windows executables referencing Office ProtectedView registry keys. Observed modifying Office configurations via the registy to disable ProtectedView"
        author = "@ditekSHen"
    strings:
        $s1 = "\\Security\\ProtectedView\\DisableInternetFilesInPV" ascii wide
        $s2 = "\\Security\\ProtectedView\\DisableAttachementsInPV" ascii wide
        $s3 = "\\Security\\ProtectedView\\DisableUnsafeLocationsInPV" ascii wide

        $h1 = "5c53656375726974795c50726f746563746564566965775c44697361626c65496e7465726e657446696c6573496e5056" nocase ascii wide
        $h2 = "5c53656375726974795c50726f746563746564566965775c44697361626c65417474616368656d656e7473496e5056" nocase ascii wide
        $h3 = "5c53656375726974795c50726f746563746564566965775c44697361626c65556e736166654c6f636174696f6e73496e5056" nocase ascii wide

        $d1 = "5c%53%65%63%75%72%69%74%79%5c%50%72%6f%74%65%63%74%65%64%56%69%65%77%5c%44%69%73%61%62%6c%65%49%6e%74%65%72%6e%65%74%46%69%6c%65%73%49%6e%50%56" nocase ascii
        $d2 = "5c%53%65%63%75%72%69%74%79%5c%50%72%6f%74%65%63%74%65%64%56%69%65%77%5c%44%69%73%61%62%6c%65%41%74%74%61%63%68%65%6d%65%6e%74%73%49%6e%50%56" nocase ascii
        $d3 = "5c%53%65%63%75%72%69%74%79%5c%50%72%6f%74%65%63%74%65%64%56%69%65%77%5c%44%69%73%61%62%6c%65%55%6e%73%61%66%65%4c%6f%63%61%74%69%6f%6e%73%49%6e%50%56" nocase ascii
    condition:
         uint16(0) == 0x5a4d and (2 of ($s*) or 2 of ($h*) or 2 of ($d*))
}

rule INDICATOR_SUSPICIOUS_EXE_SandboxProductID {
    meta:
        description = "Detects binaries and memory artifcats referencing sandbox product IDs"
        author = "ditekSHen"
    strings:
        $id1 = "76487-337-8429955-22614" fullword ascii wide // Anubis Sandbox
        $id2 = "76487-644-3177037-23510" fullword ascii wide // CW Sandbox
        $id3 = "55274-640-2673064-23950" fullword ascii wide // Joe Sandbox
        $id4 = "76487-640-1457236-23837" fullword ascii wide // Anubis Sandbox
        $id5 = "76497-640-6308873-23835" fullword ascii wide // CWSandbox
        $id6 = "76487-640-1464517-23259" fullword ascii wide // ??
    condition:
        uint16(0) == 0x5a4d and 2 of them
}

rule INDICATOR_SUSPICIOUS_EXE_SandboxHookingDLL {
    meta:
        description = "Detects binaries and memory artifcats referencing sandbox DLLs typically observed in sandbox evasion"
        author = "ditekSHen"
    strings:
        $dll1 = "sbiedll.dll" nocase fullword ascii wide 
        $dll2 = "dbghelp.dll" nocase fullword ascii wide  
        $dll3 = "api_log.dll" nocase fullword ascii wide  
        $dll4 = "pstorec.dll" nocase fullword ascii wide  
        $dll5 = "dir_watch.dll" nocase fullword ascii wide
        $dll6 = "vmcheck.dll" nocase fullword ascii wide  
        $dll7 = "wpespy.dll" nocase fullword ascii wide   
        $dll8 = "SxIn.dll" nocase fullword ascii wide     
        $dll9 = "Sf2.dll" nocase fullword ascii wide     
        $dll10 = "deploy.dll" nocase fullword ascii wide   
        $dll11 = "avcuf32.dll" nocase fullword ascii wide  
        $dll12 = "BgAgent.dll" nocase fullword ascii wide  
        $dll13 = "guard32.dll" nocase fullword ascii wide  
        $dll14 = "wl_hook.dll" nocase fullword ascii wide  
        $dll15 = "QOEHook.dll" nocase fullword ascii wide  
        $dll16 = "a2hooks32.dll" nocase fullword ascii wide
        $dll17 = "tracer.dll" nocase fullword ascii wide
        $dll18 = "APIOverride.dll" nocase fullword ascii wide
        $dll19 = "NtHookEngine.dll" nocase fullword ascii wide
        $dll20 = "LOG_API.DLL" nocase fullword ascii wide
        $dll21 = "LOG_API32.DLL" nocase fullword ascii wide
        $dll22 = "vmcheck32.dll" nocase ascii wide
        $dll23 = "vmcheck64.dll" nocase ascii wide
    condition:
        uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_SUSPICIOUS_AHK_Downloader {
    meta:
        description = "Detects AutoHotKey binaries acting as second stage droppers"
        author = "ditekSHen"
    strings:
        $d1 = "URLDownloadToFile, http" ascii
        $d2 = "URLDownloadToFile, file" ascii
        $s1 = ">AUTOHOTKEY SCRIPT<" fullword wide
        $s2 = "open \"%s\" alias AHK_PlayMe" fullword wide
        $s3 = /AHK\s(Keybd|Mouse)/ fullword wide
    condition:
        uint16(0) == 0x5a4d and (1 of ($d*) and 1 of ($s*))
}
