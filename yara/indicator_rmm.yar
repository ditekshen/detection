import "pe"

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

/*
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
*/

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

rule INDICATOR_RMM_PulseWay_PCMonTaskSrv {
    meta:
        author = "ditekSHen"
        description = "Detects Pulseway pcmontask and service user agent responsible for Remote Control, Screens View, Computer Lock, etc"
        clamav1 = "INDICATOR.Win.RMM.PulseWay"
        reference1 = "https://github.com/ditekshen/detection/blob/master/RMM_Inventory.csv"
        reference2 = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a"
        reference3 = "https://www.cisa.gov/sites/default/files/2023-06/Guide%20to%20Securing%20Remote%20Access%20Software_clean%20Final_508c.pdf"
        reference4 = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
    strings:
        $s1 = "MM.Monitor." ascii
        $s2 = "RDAgentSessionSettingsV" ascii
        $s3 = "CheckForMacOSRemoteDesktopUpdateCompletedEvent" ascii
        $s4 = "ConfirmAgentStarted" ascii
        $s5 = "GetScreenshot" ascii
        $s6 = "UnloadRemoteDesktopDlls" ascii
        $s7 = "CtrlAltDeleteProc" ascii
        $s8 = "$7cfc3b88-6dc4-49fc-9f0a-bf9e9113a14d" ascii
        $s9 = "computermonitor.mmsoft.ro" ascii
    condition:
        (uint16(0) == 0x5a4d or uint16(0) == 0xcfd0) and 7 of them
}

rule INDICATOR_RMM_PulseWay_RemoteDesktop {
    meta:
        author = "ditekSHen"
        description = "Detects Pulseway Rempte Desktop client"
        clamav1 = "INDICATOR.Win.RMM.PulseWay"
        reference1 = "https://github.com/ditekshen/detection/blob/master/RMM_Inventory.csv"
        reference2 = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a"
        reference3 = "https://www.cisa.gov/sites/default/files/2023-06/Guide%20to%20Securing%20Remote%20Access%20Software_clean%20Final_508c.pdf"
        reference4 = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
    strings:
        $s1 = "RemoteControl" ascii
        $s2 = "MM.Monitor.RemoteDesktopClient." ascii
        $s3 = "MM.Monitor.RemoteControl" ascii
        $s4 = "RemoteDesktopClientUpdateInfo" ascii
        $s5 = "ShowRemoteDesktopEnabledSystemsOnly" ascii
        $s6 = "$31f50968-d45c-49d6-ace9-ebc790855a51" ascii
    condition:
        (uint16(0) == 0x5a4d or uint16(0) == 0xcfd0) and 5 of them
}

rule INDICATOR_RMM_PulseWay_CERT {
    meta:
        author = "ditekSHen"
        description = "Detects PulseWay by (default) certificate. Review RMM Inventory"
        reference1 = "https://github.com/ditekshen/detection/blob/master/RMM_Inventory.csv"
        reference2 = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a"
        reference3 = "https://www.cisa.gov/sites/default/files/2023-06/Guide%20to%20Securing%20Remote%20Access%20Software_clean%20Final_508c.pdf"
        reference4 = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].issuer contains "DigiCert, Inc." and
            pe.signatures[i].subject contains "MMSOFT Design Ltd."
        )
}

rule INDICATOR_RMM_ManageEngine_ZohoMeeting {
    meta:
        author = "ditekSHen"
        description = "Detects ManageEngine Zoho Meeting (dc_rds.exe)"
        clamav1 = "INDICATOR.Win.RMM.ManageEngine-ZohoMeeting"
        reference1 = "https://github.com/ditekshen/detection/blob/master/RMM_Inventory.csv"
        reference2 = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a"
        reference3 = "https://www.cisa.gov/sites/default/files/2023-06/Guide%20to%20Securing%20Remote%20Access%20Software_clean%20Final_508c.pdf"
        reference4 = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
    strings:
        $s1 = "bin\\ClientAuthHandler.dll" wide
        $s2 = "AgentHook.dll" wide
        $s3 = "UEMS - Remote Control" wide
        $s4 = "Install hook...." wide
        $s5 = "india.adventnet.com/meet.sas?k=" ascii
        $s6 = "dcTcpSocket::" ascii
        $s7 = "%s/%s?clientId=%s&sessionId=%s&clientName=%s&ticket=%s&connectionId=%s" ascii
        $s8 = ".\\engines\\ccgost\\gost_" ascii
    condition:
        uint16(0) == 0x5a4d and 5 of them
}

/*
rule INDICATOR_RMM_ManageEngine_CERT {
    meta:
        author = "ditekSHen"
        description = "Detects ManageEngine Zoho Meeting by (default) certificate. Review RMM Inventory"
        reference1 = "https://github.com/ditekshen/detection/blob/master/RMM_Inventory.csv"
        reference2 = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a"
        reference3 = "https://www.cisa.gov/sites/default/files/2023-06/Guide%20to%20Securing%20Remote%20Access%20Software_clean%20Final_508c.pdf"
        reference4 = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].issuer contains "Sectigo Limited" and
            pe.signatures[i].subject contains "ZOHO Corporation Private Limited"
            // and pe.signatures[i].serial == "00:d1:9d:b1:a5:42:ff:d3:d9:9b:83:20:8f:e9:e8:0f:e3"
        )
}
*/

rule INDICATOR_RMM_Atera {
    meta:
        author = "ditekSHen"
        description = "Detects Atera. Review RMM Inventory"
        clamav1 = "INDICATOR.Win.RMM.Atera"
        reference1 = "https://github.com/ditekshen/detection/blob/master/RMM_Inventory.csv"
        reference2 = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a"
        reference3 = "https://www.cisa.gov/sites/default/files/2023-06/Guide%20to%20Securing%20Remote%20Access%20Software_clean%20Final_508c.pdf"
        reference4 = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
    strings:
        $s1 = "SOFTWARE\\ATERA Networks\\AlphaAgent" wide
        $s2 = "Monitoring & Management Agent by ATERA" ascii wide
        $s3 = "agent-api-{0}.atera.com" wide
        $s4 = "agent-api.atera.com" wide
        $s5 = "acontrol.atera.com" wide
        $s6 = /Agent\/(PingReply|GetCommandsFallback|GetCommands|GetTime|GetEnvironmentStatus|GetRecurringPackages|AgentStarting|AcknowledgeCommands)/ wide
        $s7 = "\\AlphaControlAgent\\obj\\Release\\AteraAgent.pdb" ascii
        $s8 = "AteraWebAddress" ascii
        $s9 = "AlphaControlAgent.CloudLogsManager+<>" ascii
    condition:
        uint16(0) == 0x5a4d and 4 of them
}

rule INDICATOR_RMM_Atera_CERT {
    meta:
        author = "ditekSHen"
        description = "Detects Atera by certificate. Review RMM Inventory"
        clamav1 = "INDICATOR.Win.RMM.Atera"
        reference1 = "https://github.com/ditekshen/detection/blob/master/RMM_Inventory.csv"
        reference2 = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a"
        reference3 = "https://www.cisa.gov/sites/default/files/2023-06/Guide%20to%20Securing%20Remote%20Access%20Software_clean%20Final_508c.pdf"
        reference4 = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].issuer contains "DigiCert" and
            pe.signatures[i].subject contains "Atera Networks Ltd"
        )
}

rule INDICATOR_RMM_SplashtopStreamer {
    meta:
        author = "ditekSHen"
        description = "Detects Splashtop Streamer. Review RMM Inventory"
        clamav1 = "INDICATOR.Win.RMM.SplashtopStreamer"
        reference1 = "https://github.com/ditekshen/detection/blob/master/RMM_Inventory.csv"
        reference2 = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a"
        reference3 = "https://www.cisa.gov/sites/default/files/2023-06/Guide%20to%20Securing%20Remote%20Access%20Software_clean%20Final_508c.pdf"
        reference4 = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
    strings:
        $s1 = "\\slave\\workspace\\GIT_WIN_SRS_Formal\\Source\\irisserver\\" ascii
        $s2 = ".api.splashtop.com" wide
        $s3 = "Software\\Splashtop Inc.\\Splashtop" wide
        $s4 = "restarted the streamer.%nApp version: %1" wide
        $s5 = "Splashtop-Splashtop Streamer-" wide
        $s6 = "[RemoveStreamer] Send msg 2 cloud(%d:%d:%d)" wide
    condition:
        uint16(0) == 0x5a4d and 4 of them
}

rule INDICATOR_RMM_SplashtopStreamer_CERT {
    meta:
        author = "ditekSHen"
        description = "Detects Splashtop Streamer by certificate. Review RMM Inventory"
        reference1 = "https://github.com/ditekshen/detection/blob/master/RMM_Inventory.csv"
        reference2 = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a"
        reference3 = "https://www.cisa.gov/sites/default/files/2023-06/Guide%20to%20Securing%20Remote%20Access%20Software_clean%20Final_508c.pdf"
        reference4 = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].issuer contains "DigiCert" and
            pe.signatures[i].subject contains "Splashtop Inc."
        )
}
