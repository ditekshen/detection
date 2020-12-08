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
        $wp1 = "wbadmin delete catalog -quiet" ascii wide nocase
        $wp2 = "wbadmin delete backup" ascii wide nocase
        $wp3 = "wbadmin delete systemstatebackup" ascii wide nocase
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
        $s2 = "Amigo\\User\\User Data" nocase ascii wide
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
    condition:
        uint16(0) == 0x5a4d and 6 of them
}

rule INDICATOR_SUSPICIOUS_ClearWinLogs {
    meta:
        description = "Detects executables containing commands for clearing Windows Event Logs"
        author = "ditekSHen"
    strings:
        $cmd1 = "wevtutil.exe clear-log" ascii wide nocase
        $cmd2 = "wevtutil.exe cl " ascii wide nocase
        $cmd3 = ".ClearEventLog()" ascii wide nocase
        $cmd4 = "Foreach-Object {wevtutil cl \"$_\"}" ascii wide nocase
        $cmd5 = "('wevtutil.exe el') DO (call :do_clear" ascii wide nocase
        $cmd6 = "| ForEach { Clear-EventLog $_.Log }" ascii wide nocase
    condition:
        uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_SUSPICIOUS_DisableWinDefender {
    meta:
        description = "Detects executables containing artifcats associated with disabling Widnows Defender"
        author = "ditekSHen"
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
    condition:
        uint16(0) == 0x5a4d and (1 of ($reg*) and 1 of ($s*))
}