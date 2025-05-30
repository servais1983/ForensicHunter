/*
    Ce fichier contient toutes les règles YARA connues pour la détection de menaces.
    Il est sous licence GNU-GPLv2 (http://www.gnu.org/licenses/gpl-2.0.html)
*/

import "pe"

// Règles pour les RATs
rule RAT_Cerberus {
    meta:
        description = "Cerberus RAT"
        author = "Jean-Philippe Teissier / @Jipe_"
        date = "2013-01-12"
        filetype = "memory"
        version = "1.0"
    strings:
        $checkin = "Ypmw1Syv023QZD"
        $clientpong = "wZ2pla"
        $serverping = "wBmpf3Pb7RJe"
        $generic = "cerberus" nocase
    condition:
        any of them
}

rule RAT_Zeus {
    meta:
        author = "Xylitol xylitol@malwareint.com"
        date = "2014-03-03"
        description = "Zeus 1.1.3.4"
        reference = "http://www.xylibox.com/2014/03/zeus-1134.html"
    strings:
        $mz = {4D 5A}
        $protocol1 = "X_ID: "
        $protocol2 = "X_OS: "
        $protocol3 = "X_BV: "
        $stringR1 = "InitializeSecurityDescriptor"
        $stringR2 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1)"
    condition:
        ($mz at 0 and all of ($protocol*) and ($stringR1 or $stringR2))
}

// Règles pour les ransomwares
rule RANSOM_WannaCry {
    meta:
        description = "WannaCry Ransomware"
        author = "Felipe Molina (@felmoltor)"
        date = "2017/05/12"
    strings:
        $ms17010_str1 = "PC NETWORK PROGRAM 1.0"
        $ms17010_str2 = "LANMAN1.0"
        $ms17010_str3 = "Windows for Workgroups 3.1a"
        $wannacry_payload_substr1 = "h6agLCqPqVyXi2VSQ8O6Yb9ijBX54j"
        $wannacry_payload_substr2 = "h54WfF9cGigWFEx92bzmOd0UOaZlM"
    condition:
        all of them
}

// Règles pour les packers
rule Packer_JJEncode {
    meta:
        description = "jjencode detection"
        author = "adnan.shukor@gmail.com"
        date = "2015-06-10"
    strings:
        $jjencode = /(\$|[\S]+)=~\[\]\;(\$|[\S]+)\=\{[\_]{3}\:[\+]{2}(\$|[\S]+)\,[\$]{4}\:\(\!\[\]\+["]{2}\)[\S]+/ fullword
    condition:
        $jjencode
}

// Règles pour les APTs
rule APT_Carbanak {
    meta:
        description = "Carbanak Malware"
        author = "Florian Roth"
        date = "2015-09-03"
        score = 70
    strings:
        $s1 = "evict1.pdb" fullword ascii
        $s2 = "http://testing.corp 0" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 100KB and 1 of them
}

// Règles pour les malwares POS
rule POS_BlackPOS {
    meta:
        author = "@patrickrolsen"
        version = "0.1"
        reference = "http://blog.nuix.com/2014/09/08/blackpos-v2-new-variant-or-different-family"
    strings:
        $s1 = "Usage: -[start|stop|install|uninstall"
        $s2 = "\\SYSTEM32\\sc.exe config LanmanWorkstation"
        $s3 = "t.bat"
        $s4 = "mcfmisvc"
    condition:
        uint16(0) == 0x5A4D and all of ($s*)
}

// Règles pour les malwares mobiles
rule Mobile_Mirai_Okiru {
    meta:
        description = "Detects Mirai Okiru MALW"
        reference = "https://www.reddit.com/r/LinuxMalware/comments/7p00i3/quick_notes_for_okiru_satori_variant_of_mirai/"
        date = "2018-01-05"
    strings:
        $hexsts01 = { 68 7f 27 70 60 62 73 3c 27 28 65 6e 69 28 65 72 }
        $hexsts02 = { 74 7e 65 68 7f 27 73 61 73 77 3c 27 28 65 6e 69 }
    condition:
        all of them and is__elf and filesize < 100KB
}

// Règles pour les anti-debug
rule AntiDebug_PEB {
    meta:
        weight = 1
        Author = "naxonez"
        reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
    strings:
        $ = "IsDebugged"
    condition:
        any of them
}

// Règles pour les maldocs
rule Maldoc_Kaba {
    meta:
        author = "@patrickrolsen"
        maltype = "APT.Kaba"
        filetype = "RTF"
        version = "0.1"
        description = "Kaba APT Maldoc"
        date = "2013-12-10"
    strings:
        $magic1 = { 7b 5c 72 74 30 31 }
        $magic2 = { 7b 5c 72 74 66 31 }
        $magic3 = { 7b 5c 72 74 78 61 33 }
        $author1 = { 4A 6F 68 6E 20 44 6F 65 }
        $author2 = { 61 75 74 68 6f 72 20 53 74 6f 6e 65 }
    condition:
        ($magic1 or $magic2 or $magic3 at 0) and all of ($author*)
}

// Règles pour les webshells
rule WebShell_Generic {
    meta:
        description = "Generic WebShell Detection"
        author = "ForensicHunter"
        date = "2024"
    strings:
        $php_shell = "<?php system($_GET['cmd']); ?>"
        $asp_shell = "<% Response.Write(Server.CreateObject(\"WScript.Shell\").Exec(Request.QueryString(\"cmd\")).StdOut.ReadAll()) %>"
        $jsp_shell = "<%@ page import=\"java.io.*\" %>"
    condition:
        any of them
}

// Règles pour les exploits
rule Exploit_MS17_010 {
    meta:
        description = "MS17-010 EternalBlue Exploit"
        author = "ForensicHunter"
        date = "2024"
    strings:
        $eternalblue = "EternalBlue"
        $doublepulsar = "DoublePulsar"
        $smb_exploit = "SMBv1"
    condition:
        any of them
}

// Règles pour le cryptomining
rule Crypto_Miner {
    meta:
        description = "Cryptocurrency Mining Malware"
        author = "ForensicHunter"
        date = "2024"
    strings:
        $xmr = "monero"
        $eth = "ethereum"
        $miner = "miner"
        $pool = "pool"
    condition:
        2 of them
}

// Règles pour les capacités malveillantes
rule Capability_Keylogger {
    meta:
        description = "Keylogger Detection"
        author = "ForensicHunter"
        date = "2024"
    strings:
        $keyboard = "keyboard"
        $hook = "SetWindowsHookEx"
        $keystroke = "keystroke"
    condition:
        2 of them
}

rule WebShell_Test {
    meta:
        description = "WebShell PHP ultra-flexible (pour tests)"
        author = "ForensicHunter"
        date = "2024"
    strings:
        $php_shell1 = /<\?php\s*system\s*\(\s*\$_GET\s*\[\s*['\"]cmd['\"]\s*\]\s*\)\s*;\s*\?>/
        $php_shell2 = /<\?php\n*system\s*\(\s*\$_GET\s*\[\s*['\"]cmd['\"]\s*\]\s*\)\s*;\n*\?>/
    condition:
        any of them
}

rule Zeus_Test {
    meta:
        description = "Zeus test très permissif (pour tests)"
        author = "ForensicHunter"
        date = "2024"
    strings:
        $protocol1 = "X_ID: "
        $protocol2 = "X_OS: "
        $protocol3 = "X_BV: "
        $stringR1 = "InitializeSecurityDescriptor"
        $stringR2 = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1)"
    condition:
        all of them
}

/*
Index global de toutes les règles YARA du projet
*/

include "./malware_index.yar"
include "./webshells_index.yar"
include "./packers_index.yar"
include "./maldocs_index.yar"
include "./exploit_kits_index.yar"
include "./email_index.yar"
include "./cve_rules_index.yar"
include "./crypto_index.yar"
include "./capabilities_index.yar"
include "./antidebug_antivm_index.yar"
include "./mobile_malware_index.yar" 