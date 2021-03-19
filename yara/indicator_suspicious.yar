import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_GENRansomware {
    meta:
        description = "detects command variations typically used by ransomware"
        author = "ditekSHen"
    strings:
        $cmd1 = "cmd /c \"WMIC.exe shadowcopy delet\"" ascii wide nocase
        $cmd2 = "vssadmin.exe Delete Shadows /all /quiet" ascii wide nocase
        $cmd3 = "Delete Shadows /all /quiet" ascii wide nocase
        $cmd4 = "/set {default} recoveryenabled no" ascii wide nocase
        $cmd5 = "/set {default} bootstatuspolicy ignoreallfailures" ascii wide nocase
        $cmd6 = "wmic SHADOWCOPY DELETE" ascii wide nocase
        $cmd7 = "\\Microsoft\\Windows\\SystemRestore\\SR\" /disable" ascii wide nocase
        $cmd8 = "resize shadowstorage /for=c: /on=c: /maxsize=" ascii wide nocase
        $wp1 = "delete catalog -quiet" ascii wide nocase
        $wp2 = "wbadmin delete backup" ascii wide nocase
        $wp3 = "delete systemstatebackup" ascii wide nocase
    condition:
        (uint16(0) == 0x5a4d and 2 of ($cmd*) or (1 of ($cmd*) and 1 of ($wp*))) or (4 of them)
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
        //$dll2 = "dbghelp.dll" nocase fullword ascii wide  
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
        $dll24 = "cuckoomon.dll" nocase ascii wide
    condition:
        uint16(0) == 0x5a4d and 3 of them
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

rule INDICATOR_SUSPICIOUS_EXE_UACBypass_CMSTPCOM {
    meta:
        description = "Detects Windows exceutables bypassing UAC using CMSTP COM interfaces. MITRE (T1218.003)"
        author = "ditekSHen"
    strings:
        // CMSTPLUA
        $guid1 = "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" ascii wide nocase
        // CMLUAUTIL
        $guid2 = "{3E000D72-A845-4CD9-BD83-80C07C3B881F}" ascii wide nocase
        // Connection Manager LUA Host Object
        $guid3 = "{BA126F01-2166-11D1-B1D0-00805FC1270E}" ascii wide nocase
        $s1 = "CoGetObject" fullword ascii wide
        $s2 = "Elevation:Administrator!new:" fullword ascii wide
    condition:
       uint16(0) == 0x5a4d and (1 of ($guid*) and 1 of ($s*))
}

rule INDICATOR_SUSPICOUS_EXE_References_VEEAM {
    meta:
        description = "Detects executables containing many references to VEEAM. Observed in ransomware"
    strings:
        $s1 = "VeeamNFSSvc" ascii wide nocase
        $s2 = "VeeamRESTSvc" ascii wide nocase
        $s3 = "VeeamCloudSvc" ascii wide nocase
        $s4 = "VeeamMountSvc" ascii wide nocase
        $s5 = "VeeamBackupSvc" ascii wide nocase
        $s6 = "VeeamBrokerSvc" ascii wide nocase
        $s7 = "VeeamDeploySvc" ascii wide nocase
        $s8 = "VeeamCatalogSvc" ascii wide nocase
        $s9 = "VeeamTransportSvc" ascii wide nocase
        $s10 = "VeeamDeploymentService" ascii wide nocase
        $s11 = "VeeamHvIntegrationSvc" ascii wide nocase
        $s12 = "VeeamEnterpriseManagerSvc" ascii wide nocase
        $s13 = "\"Veeam Backup Catalog Data Service\"" ascii wide nocase
        $e1 = "veeam.backup.agent.configurationservice.exe" ascii wide nocase
        $e2 = "veeam.backup.brokerservice.exe" ascii wide nocase
        $e3 = "veeam.backup.catalogdataservice.exe" ascii wide nocase
        $e4 = "veeam.backup.cloudservice.exe" ascii wide nocase
        $e5 = "veeam.backup.externalinfrastructure.dbprovider.exe" ascii wide nocase
        $e6 = "veeam.backup.manager.exe" ascii wide nocase
        $e7 = "veeam.backup.mountservice.exe" ascii wide nocase
        $e8 = "veeam.backup.service.exe" ascii wide nocase
        $e9 = "veeam.backup.uiserver.exe" ascii wide nocase
        $e10 = "veeam.backup.wmiserver.exe" ascii wide nocase
        $e11 = "veeamdeploymentsvc.exe" ascii wide nocase
        $e12 = "veeamfilesysvsssvc.exe" ascii wide nocase
        $e13 = "veeam.guest.interaction.proxy.exe" ascii wide nocase
        $e14 = "veeamnfssvc.exe" ascii wide nocase
        $e15 = "veeamtransportsvc.exe" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and 3 of them
}

rule INDICATOR_SUSPICIOUS_Binary_References_Browsers {
    meta:
        description = "Detects binaries (Windows and macOS) referencing many web browsers. Observed in information stealers."
        author = "ditekSHen"
    strings:
        $s1 = "Uran\\User Data" nocase ascii wide
        $s2 = "Amigo\\User Data" nocase ascii wide
        $s3 = "Torch\\User Data" nocase ascii wide
        $s4 = "Chromium\\User Data" nocase ascii wide
        $s5 = "Nichrome\\User Data" nocase ascii wide
        $s6 = "Google\\Chrome\\User Data" nocase ascii wide
        $s7 = "360Browser\\Browser\\User Data" nocase ascii wide
        $s8 = "Maxthon3\\User Data" nocase ascii wide
        $s9 = "Comodo\\User Data" nocase ascii wide
        $s10 = "CocCoc\\Browser\\User Data" nocase ascii wide
        $s11 = "Vivaldi\\User Data" nocase ascii wide
        $s12 = "Opera Software\\" nocase ascii wide
        $s13 = "Kometa\\User Data" nocase ascii wide
        $s14 = "Comodo\\Dragon\\User Data" nocase ascii wide
        $s15 = "Sputnik\\User Data" nocase ascii wide
        $s16 = "Google (x86)\\Chrome\\User Data" nocase ascii wide
        $s17 = "Orbitum\\User Data" nocase ascii wide
        $s18 = "Yandex\\YandexBrowser\\User Data" nocase ascii wide
        $s19 = "K-Melon\\User Data" nocase ascii wide
        $s20 = "Flock\\Browser" nocase ascii wide
        $s21 = "ChromePlus\\User Data" nocase ascii wide
        $s22 = "UCBrowser\\" nocase ascii wide
        $s23 = "Mozilla\\SeaMonkey" nocase ascii wide
        $s24 = "Apple\\Apple Application Support\\plutil.exe" nocase ascii wide
        $s25 = "Preferences\\keychain.plist" nocase ascii wide
        $s26 = "SRWare Iron" ascii wide
        $s27 = "CoolNovo" ascii wide
        $s28 = "BlackHawk\\Profiles" ascii wide
        $s29 = "CocCoc\\Browser" ascii wide
        $s30 = "Cyberfox\\Profiles" ascii wide
        $s31 = "Epic Privacy Browser\\" ascii wide
        $s32 = "K-Meleon\\" ascii wide
        $s33 = "Maxthon5\\Users" ascii wide
        $s34 = "Nichrome\\User Data" ascii wide
        $s35 = "Pale Moon\\Profiles" ascii wide
        $s36 = "Waterfox\\Profiles" ascii wide
        $s37 = "Amigo\\User Data" ascii wide
        $s38 = "CentBrowser\\User Data" ascii wide
        $s39 = "Chedot\\User Data" ascii wide
        $s40 = "RockMelt\\User Data" ascii wide
        $s41 = "Go!\\User Data" ascii wide
        $s42 = "7Star\\User Data" ascii wide
        $s43 = "QIP Surf\\User Data" ascii wide
        $s44 = "Elements Browser\\User Data" ascii wide
        $s45 = "TorBro\\Profile" ascii wide
        $s46 = "Suhba\\User Data" ascii wide
        $s47 = "Secure Browser\\User Data" ascii wide
        $s48 = "Mustang\\User Data" ascii wide
        $s49 = "Superbird\\User Data" ascii wide
        $s50 = "Xpom\\User Data" ascii wide
        $s51 = "Bromium\\User Data" ascii wide
        $s52 = "Brave\\" nocase ascii wide
        $s53 = "Google\\Chrome SxS\\User Data" ascii wide
        $s54 = "Microsoft\\Internet Explorer" ascii wide
        $s55 = "Packages\\Microsoft.MicrosoftEdge_" ascii wide
        $s56 = "IceDragon\\Profiles" ascii wide
        $s57 = "\\AdLibs\\" nocase ascii wide
        $s58 = "Moonchild Production\\Pale Moon" nocase ascii wide
        $s59 = "Firefox\\Profiles" nocase ascii wide
        $s60 = "AVG\\Browser\\User Data" nocase ascii wide
        $s61 = "Kinza\\User Data" nocase ascii wide
        $s62 = "URBrowser\\User Data" nocase ascii wide
        $s63 = "AVAST Software\\Browser\\User Data" nocase ascii wide
        $s64 = "SalamWeb\\User Data" nocase ascii wide
        $s65 = "Slimjet\\User Data" nocase ascii wide
        $s66 = "Iridium\\User Data" nocase ascii wide
        $s67 = "Blisk\\User Data" nocase ascii wide
        $s68 = "uCozMedia\\Uran\\User Data" nocase ascii wide
        $s69 = "setting\\modules\\ChromiumViewer" nocase ascii wide
        $s70 = "Citrio\\User Data" nocase ascii wide
        $s71 = "Coowon\\User Data" nocase ascii wide
        $s72 = "liebao\\User Data" nocase ascii wide
        $s73 = "Edge\\User Data" nocase ascii wide
    condition:
        (uint16(0) == 0x5a4d or uint16(0) == 0xfacf) and 6 of them
}

rule INDICATOR_SUSPICIOUS_EXE_References_Confidential_Data_Store {
    meta:
        description = "Detects executables referencing many confidential data stores found in browsers, mail clients, cryptocurreny wallets, etc. Observed in information stealers"
        author = "ditekSHen"
    strings:
        $s1 = "key3.db" nocase ascii wide     // Firefox private keys
        $s2 = "key4.db" nocase ascii wide     // Firefox private keys
        $s3 = "cert8.db" nocase ascii wide    // Firefox certificate database
        $s4 = "logins.json" nocase ascii wide // Firefox encrypted password database
        $s5 = "account.cfn" nocase ascii wide // The Bat! (email client) account credentials
        $s6 = "wand.dat" nocase ascii wide    // Opera password database 
        $s7 = "wallet.dat" nocase ascii wide  // cryptocurreny wallets
    condition:
        uint16(0) == 0x5a4d and 3 of them
}

rule INDICATOR_SUSPICIOUS_EXE_Referenfces_Messaging_Clients {
    meta:
        description = "Detects executables referencing many email and collaboration clients. Observed in information stealers"
        author = "@ditekSHen"
    strings:
        $s1 = "Software\\Microsoft\\Office\\15.0\\Outlook\\Profiles\\Outlook" fullword ascii wide
        $s2 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook" fullword ascii wide
        $s3 = "Software\\Microsoft\\Windows Messaging Subsystem\\Profiles" fullword ascii wide
        $s4 = "HKEY_CURRENT_USER\\Software\\Aerofox\\FoxmailPreview" ascii wide
        $s5 = "HKEY_CURRENT_USER\\Software\\Aerofox\\Foxmail" ascii wide
        $s6 = "VirtualStore\\Program Files\\Foxmail\\mail" ascii wide
        $s7 = "VirtualStore\\Program Files (x86)\\Foxmail\\mail" ascii wide
        $s8 = "Opera Mail\\Opera Mail\\wand.dat" ascii wide
        $s9 = "Software\\IncrediMail\\Identities" ascii wide
        $s10 = "Pocomail\\accounts.ini" ascii wide
        $s11 = "Software\\Qualcomm\\Eudora\\CommandLine" ascii wide
        $s12 = "Mozilla Thunderbird\\nss3.dll" ascii wide
        $s13 = "SeaMonkey\\nss3.dll" ascii wide
        $s14 = "Flock\\nss3.dll" ascii wide
        $s15 = "Postbox\\nss3.dll" ascii wide
        $s16 = "Software\\Microsoft\\Office\\16.0\\Outlook\\Profiles\\Outlook" ascii wide
        $s17 = "CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook" ascii wide
        $s18 = "Software\\Microsoft\\Office\\Outlook\\OMI Account Manager\\Accounts" ascii wide
        $s19 = "Software\\Microsoft\\Internet Account Manager\\Accounts" ascii wide
        $s20 = "Files\\Telegram" ascii wide
        $s21 = "Telegram Desktop\\tdata" ascii wide
        $s22 = "Files\\Discord" ascii wide
        $s23 = "Steam\\config" ascii wide
        $s24 = ".purple\\accounts.xml" ascii wide // pidgin
        $s25 = "Skype\\" ascii wide
        $s26 = "Pigdin\\accounts.xml" ascii wide
        $s27 = "Psi\\accounts.xml" ascii wide
        $s28 = "Psi+\\accounts.xml" ascii wide
        $s29 = "Psi\\profiles" ascii wide
        $s30 = "Psi+\\profiles" ascii wide
        $s31 = "Microsoft\\Windows Mail\\account{" ascii wide
        $s32 = "}.oeaccount" ascii wide
        $s33 = "Trillian\\users" ascii wide
        $s34 = "Google Talk\\Accounts" nocase ascii wide
        $s35 = "Microsoft\\Windows Live Mail"  nocase ascii wide
        $s36 = "Google\\Google Talk" nocase ascii wide
        $s37 = "Yahoo\\Pager" nocase ascii wide
        $s38 = "BatMail\\" nocase ascii wide
        $s39 = "POP Peeper\\poppeeper.ini" nocase ascii wide
    condition:
        uint16(0) == 0x5a4d and 6 of them
}

rule INDICATOR_SUSPICIOUS_EXE_Referenfces_File_Transfer_Clients {
    meta:
        description = "Detects executables referencing many file transfer clients. Observed in information stealers"
        author = "ditekSHen"
    strings:
        $s1 = "FileZilla\\recentservers.xml" ascii wide
        $s2 = "Ipswitch\\WS_FTP\\" ascii wide
        $s3 = "SOFTWARE\\\\Martin Prikryl\\\\WinSCP 2\\\\Sessions" ascii wide
        $s4 = "SOFTWARE\\Martin Prikryl\\WinSCP 2\\Sessions" ascii wide
        $s5 = "CoreFTP\\sites" ascii wide
        $s6 = "FTPWare\\COREFTP\\Sites" ascii wide
        $s7 = "HKEY_CURRENT_USERSoftwareFTPWareCOREFTPSites" ascii wide
        $s8 = "FTP Navigator\\Ftplist.txt" ascii wide
        $s9 = "FlashFXP\\3quick.dat" ascii wide
        $s10 = "SmartFTP\\" ascii wide
        $s11 = "cftp\\Ftplist.txt" ascii wide
        $s12 = "Software\\DownloadManager\\Passwords\\" ascii wide
        $s13 = "jDownloader\\config\\database.script" ascii wide
        $s14 = "FileZilla\\sitemanager.xml" ascii wide
        $s15 = "Far Manager\\Profile\\PluginsData\\" ascii wide
        $s16 = "FTPGetter\\Profile\\servers.xml" ascii wide
        $s17 = "FTPGetter\\servers.xml" ascii wide
        $s18 = "Estsoft\\ALFTP\\" ascii wide
        $s19 = "Far\\Plugins\\FTP\\" ascii wide
        $s20 = "Far2\\Plugins\\FTP\\" ascii wide
        $s21 = "Ghisler\\Total Commander" ascii wide
        $s22 = "LinasFTP\\Site Manager" ascii wide
        $s23 = "CuteFTP\\sm.dat" ascii wide
        $s24 = "FlashFXP\\4\\Sites.dat" ascii wide
        $s25 = "FlashFXP\\3\\Sites.dat" ascii wide
        $s26 = "VanDyke\\Config\\Sessions\\" ascii wide
        $s27 = "FTP Explorer\\" ascii wide
        $s28 = "TurboFTP\\" ascii wide
        $s29 = "FTPRush\\" ascii wide
        $s30 = "LeapWare\\LeapFTP\\" ascii wide
        $s31 = "FTPGetter\\" ascii wide
        $s32 = "Far\\SavedDialogHistory\\" ascii wide
        $s33 = "Far2\\SavedDialogHistory\\" ascii wide
        $s34 = "GlobalSCAPE\\CuteFTP " ascii wide
        $s35 = "Ghisler\\Windows Commander" ascii wide
        $s36 = "BPFTP\\Bullet Proof FTP\\" ascii wide
        $s37 = "Sota\\FFFTP" ascii wide
        $s38 = "FTPClient\\Sites" ascii wide
        $s39 = "SOFTWARE\\Robo-FTP 3.7\\" ascii wide
        $s40 = "MAS-Soft\\FTPInfo\\" ascii wide
        $s41 = "SoftX.org\\FTPClient\\Sites" ascii wide
        $s42 = "BulletProof Software\\BulletProof FTP Client\\" ascii wide
        $s43 = "BitKinex\\bitkinex.ds" ascii wide
        $s44 = "Frigate3\\FtpSite.XML" ascii wide
        $s45 = "Directory Opus\\ConfigFiles" ascii wide
        $s56 = "SoftX.org\\FTPClient\\Sites" ascii wide
        $s57 = "South River Technologies\\WebDrive\\Connections" ascii wide
    condition:
        uint16(0) == 0x5a4d and 6 of them
}

rule INDICATOR_SUSPICIOUS_EXE_References_CryptoWallets {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing many cryptocurrency mining wallets or apps. Observed in information stealers"
    strings:
        $app1 = "Ethereum" nocase ascii wide
        $app2 = "Bitcoin" nocase ascii wide
        $app3 = "Litecoin" nocase ascii wide
        $app4 = "NavCoin4" nocase ascii wide
        $app5 = "ByteCoin" nocase ascii wide
        $app6 = "PotCoin" nocase ascii wide
        $app7 = "Gridcoin" nocase ascii wide
        $app8 = "VERGE" nocase ascii wide
        $app9 = "DogeCoin" nocase ascii wide
        $app10 = "FlashCoin" nocase ascii wide
        $app11 = "Sia" nocase ascii wide
        $app12 = "Reddcoin" nocase ascii wide
        $app13 = "Electrum" nocase ascii wide
        $app14 = "Emercoin" nocase ascii wide
        $app15 = "Exodus" nocase ascii wide
        $app16 = "BBQCoin" nocase ascii wide
        $app17 = "Franko" nocase ascii wide
        $app18 = "IOCoin" nocase ascii wide
        $app19 = "Ixcoin" nocase ascii wide
        $app20 = "Mincoin" nocase ascii wide
        $app21 = "YACoin" nocase ascii wide
        $app22 = "Zcash" nocase ascii wide
        $app23 = "devcoin" nocase ascii wide
        $app24 = "Dash" nocase ascii wide
        $app25 = "Monero" nocase ascii wide
        $app26 = "Riot Games\\" nocase ascii wide
        $app27 = "qBittorrent\\" nocase ascii wide
        $app28 = "Battle.net\\" nocase ascii wide
        $app29 = "Steam\\" nocase ascii wide
        $app30 = "Valve\\Steam\\" nocase ascii wide
        $app31 = "Anoncoin" nocase ascii wide
        $app32 = "DashCore" nocase ascii wide
        $app33 = "DevCoin" nocase ascii wide
        $app34 = "DigitalCoin" nocase ascii wide
        $app35 = "Electron" nocase ascii wide
        $app36 = "ElectrumLTC" nocase ascii wide
        $app37 = "FlorinCoin" nocase ascii wide
        $app38 = "FrancoCoin" nocase ascii wide
        $app39 = "JAXX" nocase ascii wide
        $app40 = "MultiDoge" ascii wide
        $app41 = "TerraCoin" ascii wide
        $app42 = "Electrum-LTC" ascii wide
        $app43 = "ElectrumG" ascii wide
        $app44 = "Electrum-btcp" ascii wide
        $app45 = "MultiBitHD" ascii wide
        $app46 = "monero-project" ascii wide
        $app47 = "Bitcoin-Qt" ascii wide
        $app48 = "BitcoinGold-Qt" ascii wide
        $app49 = "Litecoin-Qt" ascii wide
        $app50 = "BitcoinABC-Qt" ascii wide
        $app51 = "Exodus Eden" ascii wide
        $app52 = "myether" ascii wide
        $app53 = "factores-Binance" ascii wide
        $app54 = "metamask" ascii wide
        $app55 = "kucoin" ascii wide
        $app56 = "cryptopia" ascii wide
        $app57 = "binance" ascii wide
        $app58 = "hitbtc" ascii wide
        $app59 = "litebit" ascii wide
        $app60 = "coinEx" ascii wide
        $app61 = "blockchain" ascii wide

        $ne1 = "C:\\src\\pgriffais_incubator-w7\\Steam\\main\\src\\external\\libjingle-0.4.0\\talk/base/scoped_ptr.h" fullword wide
        $ne2 = "\"%s\\bin\\%slauncher.exe\" -hproc %x -hthread %x -baseoverlayname %s\\%s" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (not any of ($ne*) and 6 of them)
}

rule INDICATOR_SUSPICIOUS_ClearWinLogs {
    meta:
        author = "ditekSHen"
        description = "Detects executables containing commands for clearing Windows Event Logs"
    strings:
        $cmd1 = "wevtutil.exe clear-log" ascii wide nocase
        $cmd2 = "wevtutil.exe cl " ascii wide nocase
        $cmd3 = ".ClearEventLog()" ascii wide nocase
        $cmd4 = "Foreach-Object {wevtutil cl \"$_\"}" ascii wide nocase
        $cmd5 = "('wevtutil.exe el') DO (call :do_clear" ascii wide nocase
        $cmd6 = "| ForEach { Clear-EventLog $_.Log }" ascii wide nocase
        $cmd7 = "('wevtutil.exe el') DO wevtutil.exe cl \"%s\"" ascii wide nocase
        $t1 = "wevtutil" ascii wide nocase
        $l1 = "cl Application" ascii wide nocase
        $l2 = "cl System" ascii wide nocase
        $l3 = "cl Setup" ascii wide nocase
        $l4 = "cl Security" ascii wide nocase
        $l5 = "sl Security /e:false" ascii wide nocase
        $ne1 = "wevtutil.exe cl Aplicaci" fullword wide
        $ne2 = "wevtutil.exe cl Application /bu:C:\\admin\\backup\\al0306.evtx" fullword wide
        $ne3 = "wevtutil.exe cl Application /bu:C:\\admin\\backups\\al0306.evtx" fullword wide
    condition:
        uint16(0) == 0x5a4d and not any of ($ne*) and ((1 of ($cmd*)) or (1 of ($t*) and 3 of ($l*)))
}

rule INDICATOR_SUSPICIOUS_DisableWinDefender {
    meta:
        author = "ditekSHen"
        description = "Detects executables containing artifcats associated with disabling Widnows Defender"
    strings:
        $reg1 = "SOFTWARE\\Microsoft\\Windows Defender\\Features" ascii wide nocase
        $reg2 = "SOFTWARE\\Policies\\Microsoft\\Windows Defender" ascii wide nocase
        $s1 = "Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $true" ascii wide nocase
        $s2 = "Set-MpPreference -DisableArchiveScanning $true" ascii wide nocase
        $s3 = "Set-MpPreference -DisableIntrusionPreventionSystem $true" ascii wide nocase
        $s4 = "Set-MpPreference -DisableScriptScanning $true" ascii wide nocase
        $s5 = "Set-MpPreference -SubmitSamplesConsent 2" ascii wide nocase
        $s6 = "Set-MpPreference -MAPSReporting 0" ascii wide nocase
        $s7 = "Set-MpPreference -HighThreatDefaultAction 6" ascii wide nocase
        $s8 = "Set-MpPreference -ModerateThreatDefaultAction 6" ascii wide nocase
        $s9 = "Set-MpPreference -LowThreatDefaultAction 6" ascii wide nocase
        $s10 = "Set-MpPreference -SevereThreatDefaultAction 6" ascii wide nocase
        $pdb = "\\Disable-Windows-Defender\\obj\\Debug\\Disable-Windows-Defender.pdb" ascii
    condition:
        uint16(0) == 0x5a4d and ((1 of ($reg*) and 1 of ($s*)) or ($pdb))
}

rule INDICATOR_SUSPICIOUS_USNDeleteJournal {
    meta:
        author = "ditekSHen"
        description = "Detects executables containing anti-forensic artifcats of deletiing USN change journal. Observed in ransomware"
    strings:
        $cmd1 = "fsutil.exe" ascii wide nocase
        $s1 = "usn deletejournal /D C:" ascii wide nocase
        $s2 = "fsutil.exe usn deletejournal" ascii wide nocase
        $s3 = "fsutil usn deletejournal" ascii wide nocase
        $s4 = "fsutil file setZeroData offset=0" ascii wide nocase
        $ne1 = "fsutil usn readdata C:\\Temp\\sample.txt" wide
        $ne2 = "fsutil transaction query {0f2d8905-6153-449a-8e03-7d3a38187ba1}" wide
        $ne3 = "fsutil resource start d:\\foobar d:\\foobar\\LogDir\\LogBLF::TxfLog d:\\foobar\\LogDir\\LogBLF::TmLog" wide
        $ne4 = "fsutil objectid query C:\\Temp\\sample.txt" wide
    condition:
        uint16(0) == 0x5a4d and (not any of ($ne*) and ((1 of ($cmd*) and 1 of ($s*)) or 1 of ($s*)))
}

rule INDICATOR_SUSPICIOUS_GENInfoStealer {
    meta:
        author = "ditekSHen"
        description = "Detects executables containing common artifcats observed in infostealers"
    strings:
        $f1 = "FileZilla\\recentservers.xml" ascii wide
        $f2 = "FileZilla\\sitemanager.xml" ascii wide
        $f3 = "SOFTWARE\\\\Martin Prikryl\\\\WinSCP 2\\\\Sessions" ascii wide
        $b1 = "Chrome\\User Data\\" ascii wide
        $b2 = "Mozilla\\Firefox\\Profiles" ascii wide
        $b3 = "Software\\Microsoft\\Internet Explorer\\IntelliForms\\Storage2" ascii wide
        $b4 = "Opera Software\\Opera Stable\\Login Data" ascii wide
        $b5 = "YandexBrowser\\User Data\\" ascii wide
        $s1 = "key3.db" nocase ascii wide
        $s2 = "key4.db" nocase ascii wide
        $s3 = "cert8.db" nocase ascii wide
        $s4 = "logins.json" nocase ascii wide
        $s5 = "account.cfn" nocase ascii wide
        $s6 = "wand.dat" nocase ascii wide
        $s7 = "wallet.dat" nocase ascii wide
        $a1 = "username_value" ascii wide
        $a2 = "password_value" ascii wide
        $a3 = "encryptedUsername" ascii wide
        $a4 = "encryptedPassword" ascii wide
        $a5 = "httpRealm" ascii wide
    condition:
        uint16(0) == 0x5a4d and ((2 of ($f*) and 2 of ($b*) and 1 of ($s*) and 3 of ($a*)) or (14 of them))
}

rule INDICATOR_SUSPICIOUS_NTLM_Exfiltration_IPPattern {
    meta:
        author = "ditekSHen"
        description = "Detects NTLM hashes exfiltration patterns in command line and various file types"
    strings:
        // Example (CMD): net use \\1.2.3.4@80\t
        $s1 = /net\suse\s\\\\([0-9]{1,3}\.){3}[0-9]{1,3}@(80|443|445)/ ascii wide
        // Example (PDF): /F (\\\\IP@80\\t)
        $s2 = /\/F\s\(\\\\\\\\([0-9]{1,3}\.){3}[0-9]{1,3}@(80|443|445)/ ascii wide
        // Example (LNK): URL=file://IP@80/t.htm
        $s3 = /URL=file:\/\/([0-9]{1,3}\.){3}[0-9]{1,3}@(80|443|445)/ ascii wide
        // Example (ICO): IconFile=\\IP@80\t.ico
        $s4 = /IconFile=\\\\([0-9]{1,3}\.){3}[0-9]{1,3}@(80|443|445)/ ascii wide
        // Example (DOC, DOCX): Target="file://IP@80/t.dotx"
        $s5 = /Target=\x22:\/\/([0-9]{1,3}\.){3}[0-9]{1,3}@(80|443|445)/ ascii wide
        // Example (Subdoc ??): ///IP@80/t
        $s6 = /\/\/\/([0-9]{1,3}\.){3}[0-9]{1,3}@(80|443|445)/ ascii wide
        // Example (over SSL) - DavWWWRoot keyword actually triggers WebDAV forcibly
        $s7 = /\\\\([0-9]{1,3}\.){3}[0-9]{1,3}@SSL@\d+\\DavWWWRoot/ ascii wide

        // OOXML in addtion to PK magic
        $mso1 = "word/" ascii
        $mso2 = "ppt/" ascii
        $mso3 = "xl/" ascii
        $mso4 = "[Content_Types].xml" ascii
    condition:
        ((uint32(0) == 0x46445025 or (uint16(0) == 0x004c and uint32(4) == 0x00021401) or uint32(0) == 0x00010000 or (uint16(0) == 0x4b50 and 1 of ($mso*))) and 1 of ($s*)) or 1 of ($s*)
}

rule INDICATOR_SUSPICIOUS_PWSH_B64Encoded_Concatenated_FileEXEC {
    meta:
        author = "ditekSHen"
        description = "Detects PowerShell scripts containing patterns of base64 encoded files, concatenation and execution"
    strings:
        $b1 = "::WriteAllBytes(" ascii
        $b2 = "::FromBase64String(" ascii
        $b3 = "::UTF8.GetString(" ascii

        $s1 = "-join" nocase ascii
        $s2 = "[Char]$_"
        $s3 = "reverse" nocase ascii
        $s4 = " += " ascii

        $e1 = "System.Diagnostics.Process" ascii
        $e2 = /StartInfo\.(Filename|UseShellExecute)/ ascii
        $e3 = /-eq\s'\.(exe|dll)'\)/ ascii
        $e4 = /(Get|Start)-(Process|WmiObject)/ ascii
    condition:
        #s4 > 10 and ((3 of ($b*)) or (1 of ($b*) and 2 of ($s*) and 1 of ($e*)) or (8 of them))
}

rule INDICATOR_SUSPICIOUS_PWSH_AsciiEncoding_Pattern {
    meta:
        author = "ditekSHen"
        description = "Detects PowerShell scripts containing ASCII encoded files"
    strings:
        $enc1 = "[char[]]([char]97..[char]122)" ascii
        $enc2 = "[char[]]([char]65..[char]90)" ascii
        $s1 = ".DownloadData($" ascii
        $s2 = "[Net.SecurityProtocolType]::TLS12" ascii
        $s3 = "::WriteAllBytes($" ascii
        $s4 = "::FromBase64String($" ascii
        $s5 = "Get-Random" ascii
    condition:
        1 of ($enc*) and 4 of ($s*) and filesize < 2500KB
}

rule INDICATOR_SUSPICIOUS_JS_Hex_B64Encoded_EXE {
    meta:
        author = "ditekSHen"
        description = "Detects JavaScript files hex and base64 encoded executables"
    strings:
        $s1 = ".SaveToFile" ascii
        $s2 = ".Run" ascii
        $s3 = "ActiveXObject" ascii
        $s4 = "fromCharCode" ascii
        $s5 = "\\x66\\x72\\x6F\\x6D\\x43\\x68\\x61\\x72\\x43\\x6F\\x64\\x65" ascii
        $binary = "\\x54\\x56\\x71\\x51\\x41\\x41" ascii
        $pattern = /[\s\{\(\[=]_0x[0-9a-z]{3,6}/ ascii
    condition:
        $binary and $pattern and 2 of ($s*) and filesize < 2500KB
}

rule INDICATOR_SUSPICIOUS_JS_LocalPersistence {
    meta:
        author = "ditekSHen"
        description = "Detects JavaScript files used for persistence and executable or script execution"
    strings:
        $s1 = "ActiveXObject" ascii
        $s2 = "Shell.Application" ascii
        $s3 = "ShellExecute" ascii

        $ext1 = ".exe" ascii
        $ext2 = ".ps1" ascii
        $ext3 = ".lnk" ascii
        $ext4 = ".hta" ascii
        $ext5 = ".dll" ascii
        $ext6 = ".vb" ascii
        $ext7 = ".com" ascii
        $ext8 = ".js" ascii

        $action = "\"Open\"" ascii
    condition:
       $action and 2 of ($s*) and 1 of ($ext*) and filesize < 500KB
}

rule INDICATOR_SUSPICIOUS_WMIC_Downloader {
    meta:
        author = "ditekSHen"
        description = "Detects files utilizing WMIC for whitelisting bypass and downloading second stage payloads"
    strings:
        $s1 = "WMIC.exe os get /format:\"http" wide
        $s2 = "WMIC.exe computersystem get /format:\"http" wide
        $s3 = "WMIC.exe dcomapp get /format:\"http" wide
        $s4 = "WMIC.exe desktop get /format:\"http" wide
    condition:
        (uint16(0) == 0x004c or uint16(0) == 0x5a4d) and 1 of them
}

rule INDICATOR_SUSPICIOUS_AMSI_Bypass {
    meta:
        author = "ditekSHen"
        description = "Detects AMSI bypass pattern"
    strings:
        $v1_1 = "[Ref].Assembly.GetType(" ascii nocase
        $v1_2 = "System.Management.Automation.AmsiUtils" ascii
        $v1_3 = "GetField(" ascii nocase
        $v1_4 = "amsiInitFailed" ascii
        $v1_5 = "NonPublic,Static" ascii
        $v1_6 = "SetValue(" ascii nocase
    condition:
        5 of them and filesize < 2000KB
}

rule INDICATOR_SUSPICIOUS_EXE_PE_ResourceTuner {
    meta:
        author = "ditekSHen"
        description = "Detects executables with modified PE resources using the unpaid version of Resource Tuner"
    strings:
        $s1 = "Modified by an unpaid evaluation copy of Resource Tuner 2 (www.heaventools.com)" fullword wide
    condition:
        uint16(0) == 0x5a4d and all of them 
}

rule INDICATOR_SUSPICIOUS_EXE_ASEP_REG_Reverse {
    meta:
        author = "ditekSHen"
        description = "Detects file containing reversed ASEP Autorun registry keys"
    strings:
        $s1 = "nuR\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s2 = "ecnOnuR\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s3 = "secivreSnuR\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s4 = "xEecnOnuR\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s5 = "ecnOsecivreSnuR\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s6 = "yfitoN\\nogolniW\\noisreVtnerruC\\TN swodniW\\tfosorciM" ascii wide nocase
        $s7 = "tiniresU\\nogolniW\\noisreVtnerruC\\TN swodniW\\tfosorciM" ascii wide nocase
        $s8 = "nuR\\rerolpxE\\seiciloP\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s9 = "stnenopmoC dellatsnI\\puteS evitcA\\tfosorciM" ascii wide nocase
        $s10 = "sLLD_tinIppA\\swodniW\\noisreVtnerruC\\TN swodniW\\tfosorciM" ascii wide nocase
        $s11 = "snoitpO noitucexE eliF egamI\\noisreVtnerruC\\TN swodniW\\tfosorciM" ascii wide nocase
        $s12 = "llehS\\nogolniW\\noisreVtnerruC\\TN swodniW\\tfosorciM" ascii wide nocase
        $s13 = "daol\\swodniW\\noisreVtnerruC\\TN swodniW\\tfosorciM" ascii wide nocase
        $s14 = "daoLyaleDtcejbOecivreSllehS\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s15 = "nuRotuA\\rossecorP\\dnammoC\\tfosorciM" ascii wide nocase
        $s16 = "putratS\\sredloF llehS resU\\rerolpxE\\noisreVtnerruC\\swodniW\\tfosorciM" ascii wide nocase
        $s17 = "sllDtreCppA\\reganaM noisseS\\lortnoC\\teSlortnoCtnerruC\\metsyS" ascii wide nocase
        $s18 = "sllDtreCppA\\reganaM noisseS\\lortnoC\\100teSlortnoC\\metsyS" ascii wide nocase
        $s19 = ")tluafeD(\\dnammoC\\nepO\\llehS\\elifexE\\sessalC\\erawtfoS" ascii wide nocase
        $s20 = ")tluafeD(\\dnammoC\\nepO\\llehS\\elifexE\\sessalC\\edoN2346woW\\erawtfoS" ascii wide nocase
    condition:
        1 of them and filesize < 2000KB
}

rule INDICATOR_SUSPICIOUS_EXE_SQLQuery_ConfidentialDataStore {
    meta:
        author = "ditekSHen"
        description = "Detects executables containing SQL queries to confidential data stores. Observed in infostealers"
    strings:
        $select = "select " ascii wide nocase
        $table1 = " from credit_cards" ascii wide nocase
        $table2 = " from logins" ascii wide nocase
        $table3 = " from cookies" ascii wide nocase
        $table4 = " from moz_cookies" ascii wide nocase
        $column1 = "name" ascii wide nocase
        $column2 = "password_value" ascii wide nocase
        $column3 = "encrypted_value" ascii wide nocase
        $column4 = "card_number_encrypted" ascii wide nocase
        $column5 = "isHttpOnly" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and 2 of ($table*) and 2 of ($column*) and $select
}

rule INDICATOR_SUSPICIOUS_References_SecTools {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing many IR and analysis tools"
    strings:
        $s1 = "procexp.exe" nocase ascii wide
        $s2 = "perfmon.exe" nocase ascii wide
        $s3 = "autoruns.exe" nocase ascii wide
        $s4 = "autorunsc.exe" nocase ascii wide
        $s5 = "ProcessHacker.exe" nocase ascii wide
        $s6 = "procmon.exe" nocase ascii wide
        $s7 = "sysmon.exe" nocase ascii wide
        $s8 = "procdump.exe" nocase ascii wide
        $s9 = "apispy.exe" nocase ascii wide
        $s10 = "dumpcap.exe" nocase ascii wide
        $s11 = "emul.exe" nocase ascii wide
        $s12 = "fortitracer.exe" nocase ascii wide
        $s13 = "hookanaapp.exe" nocase ascii wide
        $s14 = "hookexplorer.exe" nocase ascii wide
        $s15 = "idag.exe" nocase ascii wide
        $s16 = "idaq.exe" nocase ascii wide
        $s17 = "importrec.exe" nocase ascii wide
        $s18 = "imul.exe" nocase ascii wide
        $s19 = "joeboxcontrol.exe" nocase ascii wide
        $s20 = "joeboxserver.exe" nocase ascii wide
        $s21 = "multi_pot.exe" nocase ascii wide
        $s22 = "ollydbg.exe" nocase ascii wide
        $s23 = "peid.exe" nocase ascii wide
        $s24 = "petools.exe" nocase ascii wide
        $s25 = "proc_analyzer.exe" nocase ascii wide
        $s26 = "regmon.exe" nocase ascii wide
        $s27 = "scktool.exe" nocase ascii wide
        $s28 = "sniff_hit.exe" nocase ascii wide
        $s29 = "sysanalyzer.exe" nocase ascii wide
        $s30 = "CaptureProcessMonitor.sys" nocase ascii wide
        $s31 = "CaptureRegistryMonitor.sys" nocase ascii wide
        $s32 = "CaptureFileMonitor.sys" nocase ascii wide
    condition:
         uint16(0) == 0x5a4d and 4 of them
}

rule INDICATOR_SUSPICIOUS_References_SecTools_B64Encoded {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing many base64-encoded IR and analysis tools names"
    strings:
        $s1 = "VGFza21ncg==" ascii wide  // Taskmgr
        $s2 = "dGFza21ncg==" ascii wide  // taskmgr
        $s3 = "UHJvY2Vzc0hhY2tlcg" ascii wide // ProcessHacker
        $s4 = "cHJvY2V4cA" ascii wide  // procexp
        $s5 = "cHJvY2V4cDY0" ascii wide  // procexp64
        $s6 = "aHR0cCBhbmFseXplci" ascii wide // http analyzer
        $s7 = "ZmlkZGxlcg" ascii wide // fiddler
        $s8 = "ZWZmZXRlY2ggaHR0cCBzbmlmZmVy" ascii wide // effetech http sniffer
        $s9 = "ZmlyZXNoZWVw" ascii wide // firesheep
        $s10 = "SUVXYXRjaCBQcm9mZXNzaW9uYWw" ascii wide // IEWatch Professional
        $s11 = "ZHVtcGNhcA" ascii wide // dumpcap
        $s12 = "d2lyZXNoYXJr" ascii wide //wireshark
        $s13 = "c3lzaW50ZXJuYWxzIHRjcHZpZXc" ascii wide // sysinternals tcpview
        $s14 = "TmV0d29ya01pbmVy" ascii wide // NetworkMiner
        $s15 = "TmV0d29ya1RyYWZmaWNWaWV3" ascii wide // NetworkTrafficView
        $s16 = "SFRUUE5ldHdvcmtTbmlmZmVy" ascii wide // HTTPNetworkSniffer
        $s17 = "dGNwZHVtcA" ascii wide // tcpdump
        $s18 = "aW50ZXJjZXB0ZXI" ascii wide // intercepter
        $s19 = "SW50ZXJjZXB0ZXItTkc" ascii wide // Intercepter-NG
        $s20 = "b2xseWRiZw" ascii wide // ollydbg
        $s21 = "eDY0ZGJn" ascii wide // x64dbg
        $s22 = "eDMyZGJn" ascii wide // x32dbg
        $s23 = "ZG5zcHk" ascii wide // dnspy
        $s24 = "ZGU0ZG90" ascii wide // de4dot
        $s25 = "aWxzcHk" ascii wide // ilspy
        $s26 = "ZG90cGVla" ascii wide // dotpeek
        $s27 = "aWRhNjQ" ascii wide // ida64
        $s28 = "UkRHIFBhY2tlciBEZXRlY3Rvcg" ascii wide // RDG Packer Detector
        $s29 = "Q0ZGIEV4cGxvcmVy" ascii wide // CFF Explorer
        $s30 = "UEVpRA" ascii wide // PEiD
        $s31 = "cHJvdGVjdGlvbl9pZA" ascii wide // protection_id
        $s32 = "TG9yZFBF" ascii wide // LordPE
        $s33 = "cGUtc2lldmU=" ascii wide // pe-sieve
        $s34 = "TWVnYUR1bXBlcg" ascii wide // MegaDumper
        $s35 = "VW5Db25mdXNlckV4" ascii wide // UnConfuserEx
        $s36 = "VW5pdmVyc2FsX0ZpeGVy" ascii wide // Universal_Fixer
        $s37 = "Tm9GdXNlckV4" ascii wide // NoFuserEx
    condition:
         uint16(0) == 0x5a4d and 4 of them
}

rule INDICATOR_SUSPICIOUS_References_Sandbox_Artifacts {
    meta:
        author = "ditekSHen"
        description = "Detects executables referencing sandbox artifacts"
    strings:
        $s1 = "C:\\agent\\agent.pyw" ascii wide
        $s2 = "C:\\sandbox\\starter.exe" ascii wide
        $s3 = "c:\\ipf\\BDCore_U.dll" ascii wide
        $s4 = "C:\\cwsandbox_manager" ascii wide
        $s5 = "C:\\cwsandbox" ascii wide
        $s6 = "C:\\Stuff\\odbg110" ascii wide
        $s7 = "C:\\gfisandbox" ascii wide
        $s8 = "C:\\Virus Analysis" ascii wide
        $s9 = "C:\\iDEFENSE\\SysAnalyzer" ascii wide
        $s10 = "c:\\gnu\\bin" ascii wide
        $s11 = "C:\\SandCastle\\tools" ascii wide
        $s12 = "C:\\cuckoo\\dll" ascii wide
        $s13 = "C:\\MDS\\WinDump.exe" ascii wide
        $s14 = "C:\\tsl\\Raptorclient.exe" ascii wide
        $s15 = "C:\\guest_tools\\start.bat" ascii wide
        $s16 = "C:\\tools\\aswsnx\\snxcmd.exe" ascii wide
        $s17 = "C:\\Winap\\ckmon.pyw" ascii wide
        $s18 = "c:\\tools\\decodezeus" ascii wide
        $s19 = "c:\\tools\\aswsnx" ascii wide
        $s20 = "C:\\sandbox\\starter.exe" ascii wide
        $s21 = "C:\\Kit\\procexp.exe" ascii wide
        $s22 = "c:\\tracer\\mdare32_0.sys" ascii wide
        $s23 = "C:\\tool\\malmon" ascii wide
        $s24 = "C:\\Samples\\102114\\Completed" ascii wide
        $s25 = "c:\\vmremote\\VmRemoteGuest.exe" ascii wide
        $s26 = "d:\\sandbox_svc.exe" ascii wide
    condition:
        uint16(0) == 0x5a4d and 3 of them
}

rule INDICATOR_SUSPICIOUS_EXE_Embedded_Gzip_B64Encoded_File {
     meta:
        author = "ditekSHen"
        description = "Detects executables containing bas64 encoded gzip files"
    strings:
        $s1 = "H4sIAAAAAAAEA" ascii
        $s2 = "AEAAAAAAAIs4H" ascii
    condition:
        uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_SUSPICIOUS_EXE_RawGitHub_URL {
     meta:
        author = "ditekSHen"
        description = "Detects executables containing URLs to raw contents of a Github gist"
    strings:
        $url1 = "https://gist.githubusercontent.com/" ascii wide
        $url2 = "https://raw.githubusercontent.com/" ascii wide
        $raw = "/raw/" ascii wide
    condition:
        uint16(0) == 0x5a4d and (($url1 and $raw) or ($url2))
}

rule INDICATOR_SUSPICIOUS_EXE_RawPaste_URL {
     meta:
        author = "ditekSHen"
        description = "Detects executables containing URLs to raw contents of a paste"
    strings:
        $u1 = "https://pastebin.com/" ascii wide
        $u2 = "https://paste.ee/" ascii wide
        $u3 = "https://pastecode.xyz/" ascii wide
        $u4 = "https://rentry.co/" ascii wide
        $u5 = "https://paste.nrecom.net/" ascii wide
        $u6 = "https://hastebin.com/" ascii wide
        $u7 = "https://privatebin.info/" ascii wide
        $u8 = "https://penyacom.org/" ascii wide
        $u9 = "https://controlc.com/" ascii wide
        $u10 = "https://tiny-paste.com/" ascii wide
        $u11 = "https://paste.teknik.io/" ascii wide
        $s1 = "/raw/" ascii wide
    condition:
        uint16(0) == 0x5a4d and (1 of ($u*) and all of ($s*))
}

rule INDICATOR_SUSPICIOUS_PWSH_PasswordCredential_RetrievePassword {
    meta:
        author = "ditekSHen"
        description = "Detects PowerShell content designed to retrieve passwords from host"
    strings:
        $namespace = "Windows.Security.Credentials.PasswordVault" ascii wide nocase
        $method1 = "RetrieveAll()" ascii wide nocase
        $method2 = ".RetrievePassword()" ascii wide nocase
    condition:
       $namespace and 1 of ($method*)
}

rule INDICATOR_SUSPICIOUS_Stomped_PECompilation_Timestamp_InTheFuture {
    meta:
        author = "ditekSHen"
        description = "Detect executables with stomped PE compilation timestamp that is greater than local current time"
    condition:
        uint16(0) == 0x5a4d and pe.timestamp > time.now()
}

rule INDICATOR_SUSPICIOUS_EXE_UACBypass_EnvVarScheduledTasks {
    meta:
        author = "ditekSHen"
        description = "detects Windows exceutables potentially bypassing UAC (ab)using Environment Variables in Scheduled Tasks"
    strings:
        $s1 = "\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup" ascii wide
        $s2 = "\\Environment" ascii wide
        $s3 = "schtasks" ascii wide
        $s4 = "/v windir" ascii wide
    condition:
       all of them
}

rule INDICATOR_SUSPICIOUS_EXE_UACBypass_fodhelper {
    meta:
        author = "ditekSHen"
        description = "detects Windows exceutables potentially bypassing UAC using fodhelper.exe"
    strings:
        $s1 = "\\software\\classes\\ms-settings\\shell\\open\\command" ascii wide nocase
        $s2 = "DelegateExecute" ascii wide
        $s3 = "fodhelper" ascii wide
        $s4 = "ConsentPromptBehaviorAdmin" ascii wide
    condition:
       all of them
}

/*
rule INDICATOR_SUSPICIOUS_EXE_Contains_MD5_Named_DLL {
    meta:
        author = "ditekSHen"
        description = "detects Windows exceutables potentially bypassing UAC using fodhelper.exe"
    strings:
        $s1 = /[a-f0-9]{32}\.dll/ ascii wide nocase
    condition:
       uint16(0) == 0x5a4d and all of them
}
*/

rule INDICATOR_SUSPICIOUS_Finger_Download_Pattern {
    meta:
        author = "ditekSHen"
        description = "Detects files embedding and abusing the finger command for download"
    strings:
        $pat1 = /finger(\.exe)?\s.{1,50}@.{7,}\|/ ascii wide
        $pat2 = "-Command \"finger" ascii wide
        $ne1 = "Nmap service detection probe list" ascii
    condition:
       not any of ($ne*) and any of ($pat*)
}

rule INDICATOR_SUSPICIOUS_EXE_UACBypass_CMSTPCMD {
    meta:
        author = "ditekSHen"
        description = "Detects Windows exceutables bypassing UAC using CMSTP utility, command line and INF"
    strings:
        $s1 = "c:\\windows\\system32\\cmstp.exe" ascii wide nocase
        $s2 = "taskkill /IM cmstp.exe /F" ascii wide nocase
        $s3 = "CMSTPBypass" fullword ascii
        $s4 = "CommandToExecute" fullword ascii
        $s5 = "RunPreSetupCommands=RunPreSetupCommandsSection" fullword wide
        $s6 = "\"HKLM\", \"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\CMMGR32.EXE\", \"ProfileInstallPath\", \"%UnexpectedError%\", \"\"" fullword wide nocase
    condition:
       uint16(0) == 0x5a4d and 3 of them
}

rule INDICATOR_SUSPICIOUS_JS_WMI_ExecQuery {
    meta:
        author = "ditekSHen"
        description = "Detects JS potentially executing WMI queries"
    strings:
        $ex = ".ExecQuery(" ascii nocase
        $s1 = "GetObject(" ascii nocase
        $s2 = "String.fromCharCode(" ascii nocase
        $s3 = "ActiveXObject(" ascii nocase
        $s4 = ".Sleep(" ascii nocase
    condition:
       ($ex and 2 of ($s*))
}