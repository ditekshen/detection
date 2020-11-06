rule INDICATOR_TOOL_PWS_LaZagne {
    meta:
        description = "Detects LaZagne post-exploitation password stealing tool. It is typically embedded with malware in the binary resources."
        author = "ditekSHen"
    strings:
        $s1 = "blaZagne.exe.manifest" fullword ascii
        $S2 = "opyi-windows-manifest-filename laZagne.exe.manifest" fullword ascii
        $s3 = "lazagne.softwares.windows." ascii
        $s4 = "lazagne.softwares.sysadmin." ascii
        $s5 = "lazagne.softwares.php." ascii
        $s6 = "lazagne.softwares.memory." ascii
        $s7 = "lazagne.softwares.databases." ascii
        $s8 = "lazagne.softwares.browsers." ascii
        $s9 = "lazagne.config.write_output(" fullword ascii
        $s10 = "lazagne.config." ascii
    condition:
       uint16(0) == 0x5a4d and any of them
}

rule INDICATOR_TOOL_PWS_Credstealer {
    meta:
        description = "Detects Python executable for stealing credentials including domain environments. Observed in MuddyWater."
        author = "ditekSHen"
    strings:
        $s1 = "PYTHON27.DLL" fullword wide
        $s2 = "C:\\Python27\\lib\\site-packages\\py2exe\\boot_common.pyR" fullword ascii
        $s3 = "C:\\Python27\\lib\\site-packages\\py2exe\\boot_common.pyt" fullword ascii
        $s4 = "subprocess.pyc" fullword ascii
        $s5 = "MyGetProcAddress(%p, %p(%s)) -> %p" fullword ascii
        $p1 = "Dump SAM hashes from target systemss" fullword ascii
        $p2 = "Dump LSA secrets from target systemss" fullword ascii
        $p3 = "Dump the NTDS.dit from target DCs using the specifed method" fullword ascii
        $p4 = "Dump NTDS.dit password historys" fullword ascii
        $p5 = "Use Kerberos authentication. Grabs credentials from ccache file (KRB5CCNAME) based on target parameterss" fullword ascii
        $p6 = "Retrieve plaintext passwords and other information for accounts pushed through Group Policy Preferencess" fullword ascii
        $p7 = "Combo file containing a list of domain\\username:password or username:password entriess" fullword ascii
    condition:
       uint16(0) == 0x5a4d and (3 of ($s*) and 1 of ($p*))
}

rule INDICATOR_TOOL_CNC_Shootback {
    meta:
        description = "detects Python executable for CnC communication via reverse tunnels. Used by MuddyWater group."
        author = "ditekSHen"
    strings:
        $s1 = "PYTHON27.DLL" fullword wide
        $s2 = "C:\\Python27\\lib\\site-packages\\py2exe\\boot_common.pyR" fullword ascii
        $s3 = "C:\\Python27\\lib\\site-packages\\py2exe\\boot_common.pyt" fullword ascii
        $s4 = "subprocess.pyc" fullword ascii
        $s5 = "MyGetProcAddress(%p, %p(%s)) -> %p" fullword ascii
        $p1 = "Slaver(this pc):" ascii
        $p2 = "Master(another public server):" ascii
        $p3 = "Master(this pc):" ascii
        $p4 = "running as slaver, master addr: {} target: {}R/" fullword ascii
        $p5 = "Customer(this pc): " ascii
        $p6 = "Customer(any internet user):" ascii
        $p7 = "the actual traffic is:  customer <--> master(1.2.3.4) <--> slaver(this pc) <--> ssh(this pc)" fullword ascii
    condition:
       uint16(0) == 0x5a4d and (3 of ($s*) and 2 of ($p*))
}

rule INDICATOR_TOOL_PWS_Fgdump {
    meta:
        description = "detects all versions of the password dumping tool, fgdump. Observed to be used by DustSquad group."
        author = "ditekSHen"
    strings:
        $s1 = "dumping server %s" ascii
        $s2 = "dump on server %s" ascii
        $s3 = "dump passwords: %s" ascii
        $s4 = "Dumping cache" nocase ascii
        $s5 = "SECURITY\\Cache" ascii
        $s6 = "LSASS.EXE process" ascii
        $s7 = " AntiVirus " nocase ascii
        $s8 = " IPC$ " ascii
        $s9 = "Exec failed, GetLastError returned %d" fullword ascii
        $10 = "writable connection to %s" ascii
    condition:
        uint16(0) == 0x5a4d and 5 of them
}

rule INDICATOR_TOOL_PWS_SharpWeb {
    meta:
        description = "detects all versions of the browser password dumping .NET tool, SharpWeb."
        author = "ditekSHen"
    strings:
        $param1 = "logins" nocase wide
        $param2 = "cookies" nocase wide
        $param3 = "edge" nocase wide
        $param4 = "firefox" nocase wide
        $param5 = "chrome" nocase wide

        $path1 = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" wide
        $path2 = "\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\" wide
        $path3 = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cookies" wide
        $path4 = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Bookmarks" wide

        $sql1 = "UPDATE sqlite_temp_master SET sql = sqlite_rename_trigger(sql, %Q), tbl_name = %Q WHERE %s;" nocase wide
        $sql2 = "UPDATE %Q.%s SET type='%s', name=%Q, tbl_name=%Q, rootpage=#%d, sql=%Q WHERE rowid=#%d" nocase wide
        $sql3 = "SELECT action_url, username_value, password_value FROM logins" nocase wide

        $func1 = "get_encryptedPassword" fullword ascii
        $func2 = "<GetLogins>g__GetVaultElementValue0_0" fullword ascii
        $func3 = "<encryptedPassword>k__BackingField" fullword ascii

        $pdb = "\\SharpWeb\\obj\\Debug\\SharpWeb.pdb" fullword ascii
    condition:
        uint16(0) == 0x5a4d and ((1 of ($func*) and 3 of ($param*) and (1 of ($path*) or 1 of ($sql*))) or $pdb)
}

rule INDICATOR_TOOL_PWS_Blackbone {
    meta:
        description = "detects Blackbone password dumping tool on Windows 7-10 operating system."
        author = "ditekSHen"
    strings:
        $s1 = "BlackBone: %s: " ascii
        $s2 = "\\BlackBoneDrv\\" ascii
        $s3 = "\\DosDevices\\BlackBone" fullword wide
        $s4 = "\\Temp\\BBImage.manifest" wide
        $s5 = "\\Device\\BlackBone" fullword wide
        $s6 = "BBExecuteInNewThread" fullword ascii
        $s7 = "BBHideVAD" fullword ascii
        $s8 = "BBInjectDll" fullword ascii
        $s9 = "ntoskrnl.exe" fullword ascii
        $s10 = "WDKTestCert Ton," ascii
    condition:
        uint16(0) == 0x5a4d and 5 of them
}

rule INDICATOR_TOOL_PWS_Mimikatz {
    meta:
        description = "Detects Mimikatz."
        author = "ditekSHen"
    strings:
        $s1 = "mimilib.dll" ascii
        $s2 = "mimidrv.sys" ascii
        $s3 = "mimikatz.exe" ascii
        $s4 = "\\mimidrv.pdb" ascii
        $s5 = "mimikatz" ascii
        $s6 = { 6d 00 69 00 6d 00 69 00 6b 00 61 00 74 00 7a }  // m|00|i|00|m|00|i|00|k|00|a|00|t|00|z     
        $s7 = { 5c 00 6d 00 69 00 6d 00 69 00 64 00 72 00 76 }  // \|00|m|00|i|00|m|00i|00|d|00|r|00|v
        $s8 = { 6d 00 69 00 6d 00 69 00 64 00 72 00 76 }        // m|00|i|00|m|00i|00|d|00|r|00|v
        $s9 = "Lecture KIWI_MSV1_0_" ascii
        $s10 = "Search for LSASS process" ascii

        $f1 = "SspCredentialList" ascii
        $f2 = "KerbGlobalLogonSessionTable" ascii
        $f3 = "LiveGlobalLogonSessionList" ascii
        $f4 = "TSGlobalCredTable" ascii
        $f5 = "g_MasterKeyCacheList" ascii
        $f6 = "l_LogSessList" ascii
        $f7 = "lsasrv!" ascii
        $f8 = "SekurLSA" ascii
        $f9 = /Cached(Unlock|Interative|RemoteInteractive)/ ascii

        // https://github.com/gentilkiwi/mimikatz/blob/master/kiwi_passwords.yar
        $dll_1 = { c7 0? 00 00 01 00 [4-14] c7 0? 01 00 00 00 }
		$dll_2 = { c7 0? 10 02 00 00 ?? 89 4? }
        $sys_x86 = { a0 00 00 00 24 02 00 00 40 00 00 00 [0-4] b8 00 00 00 6c 02 00 00 40 00 00 00 }
		$sys_x64 = { 88 01 00 00 3c 04 00 00 40 00 00 00 [0-4] e8 02 00 00 f8 02 00 00 40 00 00 00 }
    condition:
        uint16(0) == 0x5a4d and (2 of ($*) or 3 of ($f*) or all of ($dll_*) or any of ($sys_*))
}

rule INDICATOR_TOOL_SCN_PortScan {
    meta:
        description = "Detects a port scanner tool observed as second or third stage post-compromise or dropped by malware."
        author = "ditekSHen"
    strings:
        $s1 = "HEAD / HTTP/1.0" fullword ascii
        $s2 = "Result.txt" fullword ascii
        $s3 = "Example: %s SYN " ascii
        $s4 = "Performing Time: %d/%d/%d %d:%d:%d -->" fullword ascii
        $s5 = "Bind On IP: %d.%d.%d.%d" fullword ascii
        $s6 = "SYN Scan: About To Scan %" ascii
        $s7 = "Normal Scan: About To Scan %" ascii
    condition:
        uint16(0) == 0x5a4d and 5 of them
}

rule INDICATOR_TOOL_MEM_mXtract {
    meta:
        description = "Detects mXtract, a linux-based tool that dumps memory for offensive pentration testing and can be used to scan memory for private keys, ips, and passwords using regexes."
        author = "ditekSHen"
    strings:
        $s1 = "_ZN18process_operations10get_rangesEv" fullword ascii
        $s2 = "_ZN4misc10write_dumpESsSs" fullword ascii
        $s3 = "_ZTVNSt8__detail13_Scanner_baseE" fullword ascii
        $s4 = "Running as root is recommended as not all PIDs will be scanned" fullword ascii
        $s5 = "ERROR ATTACHING TO PROCESS" fullword ascii
        $s6 = "ERROR SCANNING MEMORY RANGE" fullword ascii
    condition:
        (uint32(0) == 0x464c457f or uint16(0) == 0x457f) and 3 of them
}

rule INDICATOR_TOOL_PWS_SniffPass {
    meta:
        description = "Detects SniffPass, a password monitoring software that listens on the network and captures passwords over POP3, IMAP4, SMTP, FTP, and HTTP."
        author = "ditekSHen"
    strings:
        $s1 = "\\Release\\SniffPass.pdb" ascii
        $s2 = "Password   Sniffer" fullword wide
        $s3 = "Software\\NirSoft\\SniffPass" fullword ascii
        $s4 = "Sniffed PasswordsCFailed to start" wide
        $s5 = "Pwpcap.dll" fullword ascii
        $s6 = "nmwifi.exe" fullword ascii
        $s7 = "NmApi.dll" fullword ascii
        $s8 = "npptools.dll" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 4 of them
}

rule INDICATOR_TOOL_AVBypass_AVIator {
    meta:
        description = "Detects AVIator, which is a backdoor generator utility, which uses cryptographic and injection techniques in order to bypass AV detection. This was observed to bypass Win.Trojan.AZorult. This rule works for binaries and memory."
        author = "ditekSHen"
    strings:
        $s1 = "msfvenom -p windows/meterpreter" ascii wide
        $s2 = "payloadBox.Text" ascii wide
        $s3 = "APCInjectionCheckBox" ascii wide
        $s4 = "Thread Hijacking (Shellcode Arch: x86, OS Arch: x86)" ascii wide
        $s5 = "injectExistingApp.Text" ascii wide
        $s6 = "Stable execution but can be traced by most AVs" ascii wide
        $s7 = "AV/\\tor" ascii wide
        $s8 = "AvIator.Properties.Resources" ascii wide
        $s9 = "Select injection technique" ascii wide
        $s10 = "threadHijacking_option" ascii wide

        $pwsh1 = "Convert.ToByte(Payload_Encrypted_Without_delimiterChar[" ascii wide
        $pwsh2 = "[DllImport(\"kernel32.dll\", SetLastError = true)]" ascii wide
        $pwsh3 = "IntPtr RtlAdjustPrivilege(" ascii wide
        $pwsh4 = /InjectShellcode\.(THREADENTRY32|CONTEXT64|WriteProcessMemory\(|CloseHandle\(|CONTEXT_FLAGS|CONTEXT\(\);|Thread32Next\()/ ascii wide
        $pwsh5 = "= Payload_Encrypted.Split(',');" ascii wide
        $pwsh6 = "namespace NativePayload_Reverse_tcp" ascii wide
        $pwsh7 = "byte[] Finall_Payload = Decrypt(KEY, _X_to_Bytes);" ascii wide
        $pwsh8 = /ConstantsAndExtCalls\.(WriteProcessMemory\(|CreateRemoteThread\()/ ascii wide
    condition:
        (uint16(0) == 0x5a4d and (3 of ($s*) or 2 of ($pwsh*))) or (3 of ($s*) or 2 of ($pwsh*))
}

rule INDICATOR_TOOL_PWS_PwDump7 {
    meta:
        description = "Detects Pwdump7 password Dumper"
        author = "ditekSHen"
    strings:
        $s1 = "savedump.dat" fullword ascii
        $s2 = "Asd -_- _RegEnumKey fail!" fullword ascii
        $s3 = "\\SAM\\" ascii
        $s4 = "Unable to dump file %S" fullword ascii
        $s5 = "NO PASSWORD" ascii
    condition:
        (uint16(0) == 0x5a4d and 4 of them) or (all of them)
}

rule INDICATOR_TOOL_LTM_SharpExec {
    meta:
        description = "Detects SharpExec lateral movement tool"
        author = "ditekSHen"
    strings:
        $s1 = "fileUploaded" fullword ascii
        $s2 = "$7fbad126-e21c-4c4e-a9f0-613fcf585a71" fullword ascii
        $s3 = "DESKTOP_HOOKCONTROL" fullword ascii
        $s4 = /WINSTA_(ACCESSCLIPBOARD|WINSTA_ALL_ACCESS)/ fullword ascii
        $s5 = /NETBIND(ADD|DISABLE|ENABLE|REMOVE)/ fullword ascii
        $s6 = /SERVICE_(ALL_ACCESS|WIN32_OWN_PROCESS|INTERROGATE)/ fullword ascii
        $s7 = /(Sharp|PS|smb)Exec/ fullword ascii
        $s8 = "lpszPassword" fullword ascii
        $s9 = "lpszDomain" fullword ascii
        $s10 = "wmiexec" fullword ascii
        $s11 = "\\C$\\__LegitFile" wide
        $s12 = "LOGON32_LOGON_NEW_CREDENTIALS" fullword ascii
    condition:
        (uint16(0) == 0x5a4d and 9 of them) or (all of them)
}

rule INDICATOR_TOOL_PRV_AdvancedRun {
    meta:
        description = "Detects NirSoft AdvancedRun privialge escalation tool"
        author = "ditekSHen"
    strings:
        $s1 = "RunAsProcessName" fullword wide
        $s2 = "Process ID/Name:" fullword wide
        $s3 = "swinsta.dll" fullword wide
        $s4 = "User of the selected process0Child of selected process (Using code injection) Specified user name and password" fullword wide
        $s5 = "\"Current User - Allow UAC Elevation$Current User - Without UAC Elevation#Administrator (Force UAC Elevation)" fullword wide
    condition:
        uint16(0) == 0x5a4d and 3 of them
}

rule INDICATOR_TOOL_PWS_Amady {
    meta:
        description = "Detects password stealer DLL. Dropped by Amady"
        author = "ditekSHen"
    strings:
        $s1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders\\AppData" fullword ascii
        $s2 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook" ascii
        $s3 = "\\Mikrotik\\Winbox\\Addresses.cdb" fullword ascii
        $s4 = "\\HostName" fullword ascii
        $s5 = "\\Password" fullword ascii
        $s6 = "SOFTWARE\\RealVNC\\" ascii
        $s7 = "SOFTWARE\\TightVNC\\" ascii
        $s8 = "cred.dll" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 400KB and 7 of them
}

rule INDICATOR_TOOL_SCR_Amady {
    meta:
        description = "Detects screenshot stealer DLL. Dropped by Amady"
        author = "ditekSHen"
    strings:
        $s1 = "User-Agent: Uploador" fullword ascii
        $s2 = "Content-Disposition: form-data; name=\"data\"; filename=\"" fullword ascii
        $s3 = "WebUpload" fullword ascii
        $s4 = "Cannot assign a %s to a %s%List does not allow duplicates ($0%x)%String" wide
        $s5 = "scr.dll" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 700KB and 4 of them
}

rule INDICATOR_TOOL_EXP_EternalBlue {
    meta:
        description = "Detects Windows executables containing EternalBlue explitation artifacts"
        author = "ditekSHen"
    strings:
        $ci1 = "CNEFileIO_" ascii wide
        $ci2 = "coli_" ascii wide
        $ci3 = "mainWrapper" ascii wide

        $dp1 = "EXPLOIT_SHELLCODE" ascii wide
        $dp2 = "ETERNALBLUE_VALIDATE_BACKDOOR" ascii wide
        $dp3 = "ETERNALBLUE_DOUBLEPULSAR_PRESENT" ascii wide
        $dp4 = "//service[name='smb']/port" ascii wide
        $dp5 = /DOUBLEPULSAR_(PROTOCOL_|ARCHITECTURE_|FUNCTION_|DLL_|PROCESS_|COMMAND_|IS_64_BIT)/

        $cm1 = "--DllOrdinal 1 ProcessName lsass.exe --ProcessCommandLine --Protocol SMB --Architecture x64 --Function Rundll" ascii wide
        $cm2 = "--DllOrdinal 1 ProcessName lsass.exe --ProcessCommandLine --Protocol SMB --Architecture x86 --Function Rundll" ascii wide
        $cm3 = "--DaveProxyPort=0 --NetworkTimeout 30 --TargetPort 445 --VerifyTarget True --VerifyBackdoor True --MaxExploitAttempts 3 --GroomAllocations 12 --OutConfig" ascii wide
    condition:
        uint16(0) == 0x5a4d and (2 of ($ci*)) or (2 of ($dp*)) or (1 of ($dp*) and 1 of ($ci*)) or (1 of ($cm*))
}

rule INDICATOR_TOOL_EXP_WebLogic {
    meta:
        description = "Detects Windows executables containing Weblogic exploits commands"
        author = "ditekSHen"
    strings:
        $s1 = "certutil.exe -urlcache -split -f AAAAA BBBBB & cmd.exe /c BBBBB" ascii
        $s2 = "powershell (new-object System.Net.WebClient).DownloadFile('AAAAA','BBBBB')" ascii
    condition:
        uint16(0) == 0x5a4d and 1 of them
}

rule INDICATOR_TOOL_EXP_ApacheStrusts {
    meta:
        description = "Detects Windows executables containing ApacheStruts exploit artifatcs"
        author = "ditekSHen"
    strings:
        // CVE-2017-5638
        $x1 = "apache.struts2.ServletActionContext@getResponse" ascii 
        $e1 = ".getWriter()" ascii
        $e2 = ".getOutputStream()" ascii
        $e3 = ".getInputStream()" ascii

        // CVE-2018-11776
        $x2 = "#_memberAccess" ascii                                   
        $s1 = "ognl.OgnlContext" ascii
        $s2 = "ognl.ClassResolver" ascii
        $s3 = "ognl.TypeConverter" ascii
        $s4 = "ognl.MemberAccess" ascii
    condition:
        (uint16(0) == 0x5a4d or uint16(0) == 0x457f) and ($x1 and 2 of ($e*)) or ($x2 and 1 of ($s*))
}
