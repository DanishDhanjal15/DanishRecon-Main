/*
 * CyberRecon-Pro - botnet / DDoS-agent YARA rules.
 * String-based indicators for common DDoS botnet families and classic DDoS agents.
 * Starter coverage - pair with a maintained feed for production use.
 */

rule Mirai_IoT_Botnet
{
    meta:
        description = "Mirai IoT botnet indicators (attack commands / embedded strings)"
        severity = "CRITICAL"
        family = "Mirai"
    strings:
        $b1 = "/bin/busybox" ascii
        $b2 = "MIRAI" ascii nocase
        $c1 = "attack_" ascii
        $c2 = "killer_" ascii
        $c3 = "table_unlock_val" ascii
        $c4 = "table_lock_val" ascii
        $tok = "/dev/watchdog" ascii
    condition:
        ($b2 and $b1) or (2 of ($c*)) or ($tok and $c1)
}

rule Gafgyt_Bashlite_Botnet
{
    meta:
        description = "Gafgyt / BASHLITE / Qbot IoT DDoS botnet indicators"
        severity = "CRITICAL"
        family = "Gafgyt"
    strings:
        $s1 = "PING" ascii
        $s2 = "PONG" ascii
        $a1 = "UDP Flood" ascii nocase
        $a2 = "TCP Flood" ascii nocase
        $a3 = "HOLD Flood" ascii nocase
        $a4 = "JUNK Flood" ascii nocase
        $a5 = "GETLOCALIP" ascii
        $a6 = "SCANNER ON" ascii nocase
    condition:
        3 of ($a*) or ($s1 and $s2 and 1 of ($a*))
}

rule DDoS_Attack_Command_Strings
{
    meta:
        description = "Generic DDoS attack-method command strings seen in bot binaries"
        severity = "HIGH"
    strings:
        $f1 = "syn flood" ascii nocase
        $f2 = "ack flood" ascii nocase
        $f3 = "dns flood" ascii nocase
        $f4 = "http flood" ascii nocase
        $f5 = "slowloris" ascii nocase
        $f6 = "ntp amplification" ascii nocase
        $f7 = "ssdp flood" ascii nocase
    condition:
        2 of them
}

rule Classic_DDoS_Agents_2000
{
    meta:
        description = "Classic DDoS handler/agent families (Trinoo, TFN, Stacheldraht, Shaft)"
        severity = "HIGH"
    strings:
        $trinoo1 = "l44adsl" ascii            // trinoo daemon password
        $trinoo2 = "gOrave" ascii             // trinoo master password
        $trinoo3 = "betaalmostdone" ascii
        $tfn1 = "tribe flood network" ascii nocase
        $tfn2 = "icmp_pkt_size" ascii
        $stach1 = "sicken" ascii
        $stach2 = "stacheldraht" ascii nocase
        $shaft = "alive tijgu" ascii
    condition:
        any of them
}

rule IRC_Bot_CnC_Indicators
{
    meta:
        description = "IRC-controlled bot command-and-control indicators"
        severity = "MEDIUM"
    strings:
        $irc1 = "PRIVMSG" ascii
        $irc2 = "JOIN " ascii
        $irc3 = "NICK " ascii
        $cmd1 = ".ddos" ascii nocase
        $cmd2 = ".flood" ascii nocase
        $cmd3 = ".udp " ascii nocase
        $cmd4 = "!* udp" ascii nocase
    condition:
        (2 of ($irc*)) and (1 of ($cmd*))
}
