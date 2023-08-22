rule MALWARE_Win_RDPCredsStealer {
    meta:
        author = "ditekSHen"
        description = "Detects RDP Credentials Stealer"
        clamav1 = "MALWARE.Win.Trojan.RDPCredsStealer"
    strings:
        $x1 = "MyCredUnPackAuthenticationBufferW Hooked Function" ascii
        $x2 = "\\RDPCredsStealerDLL\\" ascii
        $x3 = "\\RDPCreds.txt" ascii
        $s1 = "CredUnPackAuthenticationBufferW" ascii
        $s2 = "Installing Hooked Function" ascii
        $s3 = "SymLoadModule64" fullword ascii
        $s4 = "memmove" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (2 of ($x*) or (1 of ($x*) and 2 of ($s*)) or 3 of ($s*))
}

rule MALWARE_Win_RDPCredsStealerInjector {
    meta:
        author = "ditekSHen"
        description = "Detects RDP Credentials Stealer injector"
        clamav1 = "MALWARE.Win.Trojan.RDPCredsStealer-Injector"
    strings:
        $s1 = "\\APIHookInjectorBin\\" ascii
        $s2 = "\\RDPCredsStealerDLL.dll" ascii
        $s3 = "DLL Injected" ascii
        $s4 = "Code Injected" ascii
        $s5 = /(OpenProcess|VirtualAllocEx|CreateRemoteThread)\(\) failed:/ fullword ascii
    condition:
        uint16(0) == 0x5a4d and 3 of them
}

rule INDICATOR_TOOL_BURTNCIGAR {
    meta:
        author = "ditekSHen"
        description = "Detects BURNTCIGAR a utility which terminates processes associated with endpoint security software"
        clamav1 = "INDICATOR.Win.TOOL.BURNTCIGAR"
    strings:
        $s1 = "Kill PID =" ascii
        $s2 = "CreateFile Error =" ascii
        $s3 = "\\KillAV" ascii
        $s4 = "DeviceIoControl" ascii
    condition:
        uint16(0) == 0x5a4d and 3 of them
}

rule INDICATOR_TOOL_WEDGECUT {
    meta:
        author = "ditekSHen"
        description = "Detects WEDGECUT a reconnaissance tool to checks hosts are online using ICMP packets"
        clamav1 = "INDICATOR.Win.TOOL.WEDGECUT"
    strings:
        $s1 = "-name" fullword ascii
        $s2 = "-full" fullword ascii
        $s3 = "\\CheckOnline" ascii
        $s4 = "IcmpSendEcho" fullword ascii
        $s5 = "IcmpCloseHandle" fullword ascii
        $s6 = "IcmpCreateFile" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 4 of them
}

rule INDICATOR_RMM_MeshAgent {
   meta:
        author = "ditekSHen"
        description = "Detects MeshAgent. Review RMM Inventory"
        clamav1 = "INDICATOR.Win.RMM.MeshAgent"
        reference1 = "https://github.com/ditekshen/detection/blob/master/RMM_Inventory.csv"
        reference2 = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a"
        reference3 = "https://www.cisa.gov/sites/default/files/2023-06/Guide%20to%20Securing%20Remote%20Access%20Software_clean%20Final_508c.pdf"
        reference4 = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
   strings:
      $x1 = "\\MeshAgent" wide
      $x2 = "Mesh Agent" wide
      $x3 = "MeshDummy" wide
      $x4 = "MeshCentral" wide
      $x5 = "ILibRemoteLogging.c" ascii
      $x6 = "AgentCore/MeshServer_" wide
      $s1 = "var _tmp = 'Detected OS: ' + require('os').Name;" ascii
      $s2 = "console.log(getSHA384FileHash(process.execPath).toString('hex'))" ascii
      $s3 = "ScriptContainer.Create(): Error spawning child process, using [%s]" fullword ascii
      $s4 = "{\"agent\":\"" ascii
      $s6 = "process.versions.commitHash" fullword ascii
      $s7 = "console.log('Error Initializing script from Zip file');process._exit();" fullword ascii
   condition:
      uint16(0) == 0x5a4d and (3 of ($x*) or (1 of ($x*) and 3 of ($s*)) or 6 of ($s*))
}

rule INDICATOR_RMM_MeshAgent_CERT {
    meta:
        author = "ditekSHen"
        description = "Detects Mesh Agent by (default) certificate. Review RMM Inventory"
        reference1 = "https://github.com/ditekshen/detection/blob/master/RMM_Inventory.csv"
        reference2 = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a"
        reference3 = "https://www.cisa.gov/sites/default/files/2023-06/Guide%20to%20Securing%20Remote%20Access%20Software_clean%20Final_508c.pdf"
        reference4 = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].issuer contains "MeshCentralRoot-"
        )
}

rule INDICATOR_RMM_MeshCentral_CERT {
    meta:
        author = "ditekSHen"
        description = "Detects Mesh Central by (default) certificate. Review RMM Inventory"
        reference1 = "https://github.com/ditekshen/detection/blob/master/RMM_Inventory.csv"
        reference2 = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a"
        reference3 = "https://www.cisa.gov/sites/default/files/2023-06/Guide%20to%20Securing%20Remote%20Access%20Software_clean%20Final_508c.pdf"
        reference4 = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].issuer contains "Unizeto Technologies S.A." and 
            pe.signatures[i].subject contains "Open Source Developer"
        )
}

rule INDICATOR_RMM_ConnectWise_ScreenConnect {
    meta:
        author = "ditekSHen"
        description = "Detects ConnectWise Control (formerly ScreenConnect). Review RMM Inventory"
        clamav1 = "INDICATOR.Win.RMM.ConnectWise-ScreenConnect"
        reference1 = "https://github.com/ditekshen/detection/blob/master/RMM_Inventory.csv"
        reference2 = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a"
        reference3 = "https://www.cisa.gov/sites/default/files/2023-06/Guide%20to%20Securing%20Remote%20Access%20Software_clean%20Final_508c.pdf"
        reference4 = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
    strings:
        $s1 = "FILESYSCREENCONNECT.CORE, VERSION=" wide
        $s2 = "feedback.screenconnect.com/Feedback.axd" wide
        $s3 = /ScreenConnect (Software|Client)/ wide
        $s4 = "ScreenConnect.InstallerActions!ScreenConnect." wide
        $s5 = "\\\\.\\Pipe\\TerminalServer\\SystemExecSrvr\\" wide
        $s6 = "\\jmorgan\\Source\\cwcontrol\\Custom\\DotNetRunner\\" wide
        $s7 = "ScreenConnect." ascii
        $s8 = "\\ScreenConnect.Core.pdb" ascii
        $s9 = "relay.screenconnect.com" ascii
    condition:
        (uint16(0) == 0x5a4d or uint16(0) == 0xcfd0) and 3 of them
}

rule INDICATOR_RMM_ConnectWise_ScreenConnect_CERT {
    meta:
        author = "ditekSHen"
        description = "Detects ConnectWise Control (formerly ScreenConnect) by (default) certificate. Review RMM Inventory"
        reference1 = "https://github.com/ditekshen/detection/blob/master/RMM_Inventory.csv"
        reference2 = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a"
        reference3 = "https://www.cisa.gov/sites/default/files/2023-06/Guide%20to%20Securing%20Remote%20Access%20Software_clean%20Final_508c.pdf"
        reference4 = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].issuer contains "DigiCert" and 
            pe.signatures[i].subject contains "Connectwise, LLC"
        )
}

rule INDICATOR_RMM_FleetDeck_Agent {
    meta:
        author = "ditekSHen"
        description = "Detects FleetDeck Agent. Review RMM Inventory"
        clamav1 = "INDICATOR.Win.RMM.FleetDeckAgent"
        reference1 = "https://github.com/ditekshen/detection/blob/master/RMM_Inventory.csv"
        reference2 = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a"
        reference3 = "https://www.cisa.gov/sites/default/files/2023-06/Guide%20to%20Securing%20Remote%20Access%20Software_clean%20Final_508c.pdf"
        reference4 = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
    strings:
        $s1 = "fleetdeck.io/" ascii
        $s2 = "load FleetDeck agent" ascii
        $s3 = ".dev1.fleetdeck.io" ascii
        $s4 = "remoteDesktopSessionMutex" ascii
        $s5 = "main.remoteDesktopWatchdog" fullword ascii
        $s6 = "main.virtualTerminalWatchdog" fullword ascii
        $s7 = "main.meetRemoteDesktop" fullword ascii
        $s8 = "repo.senri.se/prototype3/" ascii
        $s9 = "main.svcIpcClient" fullword ascii
        $s10 = "main.hookMqttLogging" fullword ascii
    condition:
        uint16(0) == 0x5a4d and 4 of them
}

rule INDICATOR_RMM_FleetDeck_Commander {
    meta:
        author = "ditekSHen"
        description = "Detects FleetDeck Commander. Review RMM Inventory"
        clamav1 = "INDICATOR.Win.RMM.FleetDeckCommander"
        reference1 = "https://github.com/ditekshen/detection/blob/master/RMM_Inventory.csv"
        reference2 = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a"
        reference3 = "https://www.cisa.gov/sites/default/files/2023-06/Guide%20to%20Securing%20Remote%20Access%20Software_clean%20Final_508c.pdf"
        reference4 = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
    strings:
        $s1 = "Software\\Microsoft\\FleetDeck Commander" ascii
        $s2 = "fleetdeck.io/prototype3/" ascii
        $s3 = "fleetdeck_commander_launcher.exe" ascii
        $s4 = "fleetdeck_commander_svc.exe" ascii
        $s5 = "|FleetDeck Commander" ascii
        $s6 = "c:\\agent\\_work\\66\\s\\" ascii
    condition:
        uint16(0) == 0x5a4d and 4 of them
}

rule INDICATOR_RMM_FleetDeck_Commander_SVC {
    meta:
        author = "ditekSHen"
        description = "Detects FleetDeck Commander SVC. Review RMM Inventory"
        clamav1 = "INDICATOR.Win.RMM.FleetDeckCommander-SVC"
        reference1 = "https://github.com/ditekshen/detection/blob/master/RMM_Inventory.csv"
        reference2 = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a"
        reference3 = "https://www.cisa.gov/sites/default/files/2023-06/Guide%20to%20Securing%20Remote%20Access%20Software_clean%20Final_508c.pdf"
        reference4 = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
    strings:
        $s1 = "fleetdeckfork/execfuncargs(" ascii
        $s2 = "REG ADD HKEY_CLASSES_ROOT\\%s /V \"URL Protocol\" /T REG_SZ /F" ascii
        $s3 = "proceed: *.fleetdeck.io" ascii
        $s4 = "fleetdeck.io/prototype3/commander_svc" ascii
        $s5 = "commanderupdate.fleetdeck.io" ascii
    condition:
        uint16(0) == 0x5a4d and 4 of them
}

rule INDICATOR_RMM_FleetDeck_Commander_Launcher {
    meta:
        author = "ditekSHen"
        description = "Detects FleetDeck Commander Launcher. Review RMM Inventory"
        clamav1 = "INDICATOR.Win.RMM.FleetDeckCommander-Launcher"
        reference1 = "https://github.com/ditekshen/detection/blob/master/RMM_Inventory.csv"
        reference2 = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a"
        reference3 = "https://www.cisa.gov/sites/default/files/2023-06/Guide%20to%20Securing%20Remote%20Access%20Software_clean%20Final_508c.pdf"
        reference4 = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
    strings:
        $s1 = "fleetdeck.io/prototype3/commander_launcher" ascii
        $s2 = "FleetDeck Commander Launcher" ascii
    condition:
        uint16(0) == 0x5a4d and all of them
}

rule INDICATOR_RMM_FleetDeck_CERT {
    meta:
        author = "ditekSHen"
        description = "Detects FleetDeck agent by (default) certificate. Review RMM Inventory"
        reference1 = "https://github.com/ditekshen/detection/blob/master/RMM_Inventory.csv"
        reference2 = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a"
        reference3 = "https://www.cisa.gov/sites/default/files/2023-06/Guide%20to%20Securing%20Remote%20Access%20Software_clean%20Final_508c.pdf"
        reference4 = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            (
                pe.signatures[i].issuer contains "Sectigo Limited" or
                pe.signatures[i].issuer contains "COMODO CA Limited"
            ) and
             
            pe.signatures[i].subject contains "FleetDeck Inc"
        )
}

rule INDICATOR_RMM_PDQConnect_Agent {
    meta:
        author = "ditekSHen"
        description = "Detects PDQ Connect Agent. Review RMM Inventory"
        reference1 = "https://github.com/ditekshen/detection/blob/master/RMM_Inventory.csv"
        reference2 = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a"
        reference3 = "https://www.cisa.gov/sites/default/files/2023-06/Guide%20to%20Securing%20Remote%20Access%20Software_clean%20Final_508c.pdf"
        reference4 = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
    strings:
        $api1 = "/devices/register" ascii
        $api2 = "/devices/socket/websocket?device_id=" ascii
        $api3 = "/devices/tasks" ascii
        $api4 = "/devices/auth-challenge" ascii
        $api5 = "/devices/receiver/Url" ascii
        $s1 = "sign_pdq.rs" ascii
        $s2 = "x-pdq-dateCredential=(.+?)/" ascii
        $s3 = "pdq-connect-agent" ascii
        $s4 = "PDQ Connect Agent" ascii
        $s5 = "PDQConnectAgent" ascii
        $s6 = "PDQConnectAgentsrc\\logger.rs" ascii
        $s7 = "-PDQ-Key-IdsUser-Agent" ascii
        $s8 = "\\PDQ\\PDQConnectAgent\\" ascii
        $s9 = "\\pdq_connect_agent.pdb" ascii
        $s10 = "task_ids[]PDQ rover" ascii
        $s11 = "https://app.pdq.com/" ascii
    condition:
        (uint16(0) == 0x5a4d or uint16(0) == 0xcfd0) and (4 of ($s*) or (3 of ($api*) and 1 of ($s*)))
}

rule INDICATOR_RMM_PDQConnect_Agent_CERT {
    meta:
        author = "ditekSHen"
        description = "Detects PDQ Connect Agent by (default) certificate. Review RMM Inventory"
        reference1 = "https://github.com/ditekshen/detection/blob/master/RMM_Inventory.csv"
        reference2 = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a"
        reference3 = "https://www.cisa.gov/sites/default/files/2023-06/Guide%20to%20Securing%20Remote%20Access%20Software_clean%20Final_508c.pdf"
        reference4 = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].issuer contains "DigiCert, Inc." and
            pe.signatures[i].subject contains "PDQ.com Corporation"
        )
}
