/*
 * CyberRecon-Pro - minimal built-in YARA rules.
 * A starter set so the malware module works out of the box. For real coverage, point
 * --yara-rules (or $YARA_RULES) at a maintained rule set such as Florian Roth's
 * signature-base (https://github.com/Neo23x0/signature-base).
 */

rule EICAR_Test_File
{
    meta:
        description = "EICAR anti-virus test string (harmless standard test file)"
        severity = "MEDIUM"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar
}

rule Generic_WebShell_Indicators
{
    meta:
        description = "Common PHP web-shell patterns (eval of request input)"
        severity = "HIGH"
    strings:
        $a = /eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $b = /(system|shell_exec|passthru|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST)/ nocase
        $c = "assert($_" nocase
    condition:
        any of them
}

rule Suspicious_PowerShell_Download_Exec
{
    meta:
        description = "PowerShell download-and-execute one-liner pattern"
        severity = "HIGH"
    strings:
        $dl  = /(DownloadString|DownloadFile|DownloadData)\s*\(/ nocase
        $enc = "-enc" nocase
        $iex = "IEX" nocase
        $wc  = "Net.WebClient" nocase
    condition:
        ($wc and $dl) or ($iex and $dl) or $enc
}
