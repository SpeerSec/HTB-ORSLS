import argparse
import argcomplete

skills_dict = {
  "APT": [
    "rpc enumeration",
    "remote registry",
    "exploiting ntlmv1"
  ],
  "Access": [
    "enumeration of access databases and outlook personal archives",
    "identification of saved credentials",
    "dpapi credential extraction"
  ],
  "Active": [
    "smb enumeration techniques ",
    "group policy preferences groups.xml enumeration and exploitation",
    "identification and exploitation of kerberoastable accounts"
  ],
  "Acute": [
    "windows powershell web access sessions",
    "windows misconfigurations",
    "windows defender bypass",
    "manual active directory enumeration"
  ],
  "Analysis": [
    "ldap injection",
    "dll manipulation",
    "windows api usage",
    "reverse engineering",
    "process inspection"
  ],
  "Antique": [
    "snmp enumeration",
    "network printer abuse",
    "local pivoting/proxy setup",
    "cups administration exploitation"
  ],
  "Arctic": [
    "exploit modification",
    "troubleshooting metasploit modules and http requests"
  ],
  "Ariekei": [
    "identifying containers",
    "enumerating remote networks",
    "advanced pivoting and tunneling techniques",
    "web application firewall evasion"
  ],
  "Arkham": [
    "java deserialization",
    "uac bypass"
  ],
  "Atom": [
    "cve exploitation",
    "custom python script"
  ],
  "Attended": [
    "creating an http-based pseudo-reverse shell",
    "finding uncommon gadgets for rop exploitation",
    "knowledge of the openssh private key format"
  ],
  "Authority": [
    "cracking ansible vaults",
    "enumerating & exploiting ad cs",
    "pass-the-cert attack"
  ],
  "Bank": [
    "identifying vulnerable services",
    "exploiting suid files"
  ],
  "Bastard": [
    "enumerating cms versions",
    "exploit modification",
    "basic windows privilege escalation techniques"
  ],
  "Bastion": [
    "extracting passwords from sam",
    "exploiting mremoteng"
  ],
  "Beep": [
    "web-based fuzzing",
    "identifying known exploits",
    "exploiting local file inclusion vulnerabilities"
  ],
  "Blackfield": [
    "leveraging backup operators group membership",
    "dumping credentials from lsass",
    "anonymous / guest enumeration"
  ],
  "Blocky": [
    "exploiting bad password practices",
    "decompiling jar files",
    "basic local linux enumeration"
  ],
  "Blue": [
    "identifying windows targets using smb",
    "exploit modification "
  ],
  "Bolt": [
    "docker image enumeration",
    "server side template injection",
    "password cracking",
    "passbolt exploitation"
  ],
  "Bounty": [
    "web.config payload creation",
    "identification of missing security patches",
    "exploit selection and execution"
  ],
  "Brainfuck": [
    "enumerating ssl certificates",
    "exploiting wordpress",
    "exploit modification",
    "enumerating mail servers",
    "decoding vigenere ciphers",
    "ssh key brute forcing",
    "rsa decryption techniques"
  ],
  "CTF": [
    "ldap injection",
    "wildcard and symlink abuse"
  ],
  "Cache": [
    "basic sql injection",
    "memcached enumeration",
    "docker abuse"
  ],
  "Calamity": [
    "bypassing process restrictions",
    "bypassing multiple memory protection mechanisms",
    "exploiting binaries in multiple stages"
  ],
  "Carpediem": [
    "using voip clients",
    "decrypting tls-encrypted traffic",
    "container breakout via cve-2022-0492"
  ],
  "Carrier": [
    "snmp enumeration",
    "command injection",
    "bgp hijacking"
  ],
  "Cascade": [
    "tightvnc password extraction",
    "aes encryption",
    "active directory enumeration",
    "active directory recycle bin"
  ],
  "Cerberus": [
    "sandbox breakout concepts",
    "active directory joined linux instance enumeration",
    "adfs abuse via saml attacks"
  ],
  "Charon": [
    "bypassing filtering to achieve sql injection",
    "exploiting php image uploads",
    "exploiting suid files",
    "shell command injection"
  ],
  "Chatterbox": [
    "modifying publicly available exploits",
    "basic powershell reverse shell techniques",
    "enumerating windows registry"
  ],
  "Coder": [
    "reversing windows executables",
    "typescript  source code review",
    "abusing active directory certificate services"
  ],
  "Conceal": [
    "ike configuration"
  ],
  "Craft": [
    "python eval injection",
    "pymysql api",
    "vault ssh"
  ],
  "Cronos": [
    "sql injection",
    "command injection",
    "exploiting cron jobs"
  ],
  "Devel": [
    "identifying vulnerable services",
    "exploiting weak credentials",
    "basic windows privilege escalation techniques"
  ],
  "Driver": [
    "hash capturing",
    "meterpreter exploitation"
  ],
  "Dropzone": [
    "tftp data transfer",
    "exploit modification",
    "discovery of ntfs data streams"
  ],
  "Dyplesher": [
    "password cracking",
    "minecraft plugin creation",
    "amqp",
    "cuberite"
  ],
  "EarlyAccess": [
    "reverse engineering",
    "php filtering",
    "command injection",
    "offline password cracking",
    "linux capabilities"
  ],
  "Enterprise": [
    "identifying docker instances",
    "exploiting wordpress plugins",
    "exploiting buffer overflows"
  ],
  "Escape": [
    "kerberos authentication",
    "esc1 attack",
    "ntlm authentication"
  ],
  "Ethereal": [
    "dns data exfiltration",
    "openssl egress check, reverse shell, digest generation, and file transfer techniques",
    "malicious shortcut testing and creation",
    "malicious msi testing and creation",
    "enumeration and replication of applocker policy"
  ],
  "Europa": [
    "enumerating ssl certificates and apache virtual hosts",
    "exploiting php’s preg_replace function",
    "bypassing restrictive write permissions"
  ],
  "Fatty": [
    "thick client pentesting",
    "path traversal",
    "sql injection",
    "deserialization",
    "tar exploitation"
  ],
  "Feline": [
    "session persistence",
    "unix socket",
    "deserialization"
  ],
  "Flight": [
    "ntlm theft",
    "abusing windows service accounts",
    "defender bypass"
  ],
  "Forest": [
    "asreproasting",
    "enumeration with bloodhound",
    "dcsync attack"
  ],
  "Forge": [
    "data exfiltration using ssrf",
    "ssrf localhost filter bypass",
    "python debugging"
  ],
  "Fortune": [
    "creating https client certificates",
    "nfs exploitation"
  ],
  "FriendZone": [
    "module hijacking"
  ],
  "Fulcrum": [
    "exploiting xml external entities",
    "exploiting file inclusion vulnerabilities",
    "chaining exploits to increase impact",
    "bypassing restrictive outbound network rules",
    "advanced remote enumeration techniques",
    "multiple pivot techniques for linux and windows",
    "multiple powershell tricks and one-liners"
  ],
  "Fuse": [
    "printer enumeration",
    "reset expired passwords",
    "seloaddriver privilege abuse",
    "password spraying"
  ],
  "Ghoul": [
    "zipslip vulnerability",
    "gogs rce",
    "git reflog"
  ],
  "Giddy": [
    "using xp_dirtree to leak the sql server service account netntlm hash",
    "identification of installed programs via windows registry enumeration",
    "reverse shell payload creation"
  ],
  "Gofer": [
    "interact with internal services using a ssrf",
    "verb tampering",
    "exploiting a binary by using a \"use after free\" bug "
  ],
  "GoodGames": [
    "exploiting union-based sql injections",
    "hash cracking weak algorithms",
    "password reuse",
    "exploiting ssti",
    "basics of docker breakouts"
  ],
  "Grandpa": [
    "identifying known vulnerabilities",
    "identifying stable processes",
    "basic windows privilege escalation techniques"
  ],
  "Granny": [
    "identifying known vulnerabilities",
    "identifying stable processes",
    "basic windows privilege escalation techniques"
  ],
  "Haircut": [
    "http-based fuzzing",
    "exploiting curl/command injection"
  ],
  "Hathor": [
    "cms exploitation",
    "dll injection",
    "script signing",
    "kerberos authentication"
  ],
  "Heist": [
    "rid bruteforce",
    "cracking cisco hashes",
    "procdump"
  ],
  "Helpline": [
    "xxe",
    "applocker enumeration",
    "event log enumeration"
  ],
  "Holiday": [
    "bypassing user agent filtering",
    "bypassing xss filtering",
    "obtaining data with stored xss",
    "exploiting nopasswd files",
    "exploiting npm cli"
  ],
  "Intelligence": [
    "adidns abuse",
    "readgmsapassword  abuse",
    "constrained delegation abuse"
  ],
  "Jail": [
    "enumerating nfs shares",
    "exploiting buffer overflows",
    "escaping selinux sandbox",
    "exploiting nopasswd",
    "escaping rvim",
    "generating targeted wordlists",
    "cracking encrypted rar archives",
    "exploiting weak rsa public keys"
  ],
  "Jarmis": [
    "working of jarm signatures",
    "exploiting omigod vulnerability",
    "exploiting server side request forgery ",
    "gopher protocol"
  ],
  "Jerry": [
    "basic script debugging",
    "custom war file payload creation",
    "silenttrinity post-exploitation framework installation and usage "
  ],
  "Joker": [
    "bypassing network restrictions",
    "exploiting nopasswd files",
    "exploiting sudoedit wildcards",
    "exploiting tar wildcards"
  ],
  "LaCasaDePapel": [
    "linux inode knowledge",
    "creating client certificates"
  ],
  "Laboratory": [
    "arbitrary read file",
    "marshal cookie attack",
    "suid exploitation"
  ],
  "Lame": [
    "identifying vulnerable services",
    "exploiting samba"
  ],
  "Laser": [
    "printer exploitation",
    "grpc & protobuf",
    "race conditions",
    "ssh redirection"
  ],
  "Lazy": [
    "padding oracle attack",
    "exploiting suid binaries",
    "using the path environment variable to aid in exploitation"
  ],
  "Legacy": [
    "identifying vulnerable services",
    "exploiting smb"
  ],
  "Lightweight": [
    "passive sniffing",
    "abusing linux capabilities"
  ],
  "Mantis": [
    "enumerating sql server express databases",
    "exploiting domain controllers and kerberos"
  ],
  "Mentor": [
    "pivoting",
    "tunneling",
    "postgresql rce"
  ],
  "MetaTwo": [
    "sql injection",
    "xml external entity injection",
    "password cracking"
  ],
  "Minion": [
    "exploiting server side request forgery",
    "exploiting blind command injection",
    "finding and reading alternate data streams"
  ],
  "Mirai": [
    "identifying an iot device",
    "forensic file recovery"
  ],
  "Mischief": [
    "familiarity with snmp oids",
    "ipv6 decimal to hexadecimal encoding techniques",
    "establishment of ipv6 reverse shell"
  ],
  "Monitored": [
    "nagios exploitation",
    "sql injection",
    "bash exploitation"
  ],
  "Monitors": [
    "local file inclusion",
    "abusing mysql misconfigurations",
    "exploit modification",
    "java deserialization",
    "cap_sys_module docker capability"
  ],
  "Monteverde": [
    "password spraying",
    "using sqlcmd",
    "azure ad connect password extraction"
  ],
  "Multimaster": [
    "sql injection",
    "password cracking",
    "vs code exploitation",
    "reverse engineering",
    "server operators group abuse",
    "sebackup privilege abuse",
    "zerologon exploitation"
  ],
  "Netmon": [
    "cve-2018-9276"
  ],
  "Networked": [
    "file upload bypass",
    "command injection"
  ],
  "Noter": [
    "cookie manipulation",
    "session hijacking"
  ],
  "Object": [
    "jenkins exploitation",
    "ad enumeration",
    "forcechangepassword abuse",
    "genericwrite abuse",
    "writeowner abuse"
  ],
  "October": [
    "exploiting suid files",
    "exploiting buffer overflows",
    "bypassing nx/dep",
    "bypassing aslr"
  ],
  "Office": [
    "joomla web service abuse",
    "wireshark packet filtering",
    "libreoffice registry security",
    "abusing ms-bkrp for password decryption",
    "gpo abuse"
  ],
  "Olympus": [
    "exploiting xdebug",
    "identifying docker instances",
    "cracking wpa handshakes",
    "gathering information through zone transfers",
    "abusing docker permissions"
  ],
  "OnlyForYou": [
    "source code review",
    "bypassing regular expressions",
    "cypher injection",
    "building malicious python packages"
  ],
  "Oouch": [
    "oauth exploitation",
    "dbus",
    "uwsgi protocol"
  ],
  "Optimum": [
    "identifying vulnerable services",
    "identifying known exploits",
    "basic windows privilege escalation techniques"
  ],
  "Outdated": [
    "shadow credentials method",
    "golden ticket attack",
    "navigating active directory"
  ],
  "Oz": [
    "gain familiarity with wfuzz advanced options",
    "accessing file system via sql injection",
    "extraction and cracking of pbkdf2-sha256 hashes",
    "server-side template injection",
    "port forwarding using sshuttle",
    "privilege escalation via portainer authentication bypass"
  ],
  "PC": [
    "interacting with grpc",
    "sqlite  injection",
    "local port forwarding"
  ],
  "Pandora": [
    "snmp enumeration",
    "port forwarding",
    "sql injection",
    "lateral movement",
    "reversing",
    "path variable injection"
  ],
  "PikaTwoo": [
    "apk reversion",
    "bypassing wafs",
    "kubernetes pod breakout",
    "cr8escape"
  ],
  "Pit": [
    "snmp extensions",
    "exploiting cve-2019-12744",
    "basic awareness about possible selinux restrictions"
  ],
  "Player": [
    "vhost enumeration",
    "creating jwt cookies",
    "lfi through ffmpeg"
  ],
  "Poison": [
    "apache log poisoning",
    "tunneling ports over ssh"
  ],
  "Popcorn": [
    "bypassing file upload checks",
    "modifying http requests"
  ],
  "Querier": [
    "excel macros",
    "powerview"
  ],
  "Rabbit": [
    "open office macro modification",
    "payload creation",
    "authorisation bypass",
    "sql injection identification and exploitation",
    "windows services and file system permission enumeration"
  ],
  "RainyDay": [
    "tunneling",
    "flask session cookie crafting",
    "docker/host shared pids",
    "python exploitation for arbitrary code execution",
    "bruteforcing bcrypt hashes"
  ],
  "Ready": [
    "ssrf & crlf attacks",
    "docker escape"
  ],
  "Rebound": [
    "pre-authentication kerberoasting",
    "cross-session relay attack",
    "resource-based constrained delegation ",
    "s4u2self & s4u2proxy"
  ],
  "Reddish": [
    "gaining situational awareness",
    "tunneling",
    "exploitation of default redis configurations",
    "leveraging cron jobs for lateral movement and privilege escalation",
    "rsync wildcard abuse"
  ],
  "Reel": [
    "extraction and use of document metadata in a phishing attack",
    "creation of attacker infrastructure ",
    "identification and exploitation of active directory dacl attack chain"
  ],
  "Reel2": [
    "phishing",
    "password cracking",
    "jea bypass",
    "sticky notes enumeration"
  ],
  "Registry": [
    "docker api",
    "web exploitation",
    "restic exploitation"
  ],
  "Remote": [
    "nfs enumeration",
    "cms exploitation",
    "teamviewer credential gathering",
    "seimpersonate privilege abuse"
  ],
  "Resolute": [
    "dnsadmins abuse"
  ],
  "Return": [
    "network printer abuse",
    "server operators group abuse"
  ],
  "RouterSpace": [
    "using android emulators",
    "command injection",
    "linux privilege escalation"
  ],
  "Sauna": [
    "asreproasting attack",
    "dcsync attack"
  ],
  "Scavenger": [
    "sql injection",
    "reversing rootkits"
  ],
  "Scrambled": [
    "kerberoasting",
    "silver ticket attack",
    "deserialization attacks"
  ],
  "Search": [
    "removing protection from xlsx files",
    "using windows powershell web access",
    "gmsa password retrieval",
    "exploiting misconfigured active directory acls"
  ],
  "Sekhmet": [
    "nodejs deserialization",
    "waf bypass",
    "known plaintext attacks on zipcrypto",
    "constrained language mode and applocker bypass"
  ],
  "ServMon": [
    "exploiting nvms-1000",
    "exploiting nsclient++",
    "ssh password spraying"
  ],
  "Sharp": [
    "reversing .net  applications",
    "exploitation of .net  remoting services",
    "exploitation of wcf  remoting services"
  ],
  "Shibboleth": [
    "ipmi enumeration & exploitation",
    "zabbix exploitation",
    "mysql exploitation"
  ],
  "Silo": [
    "enumerating oracle sids",
    "enumerating oracle credentials",
    "leveraging oracle to upload and execute files"
  ],
  "Sizzle": [
    "stealing hashes",
    "passwordless login",
    "kerberoasting",
    "dcsync"
  ],
  "Smasher2": [
    "exploiting mmap handlers",
    "reversing shared objects"
  ],
  "Sneaky": [
    "basic sql injection",
    "enumerating snmp",
    "exploiting suid files",
    "basic buffer overflow exploitation"
  ],
  "SneakyMailer": [
    "phishing",
    "pypi package exploitation",
    "pip3 exploitation"
  ],
  "Snoopy": [
    "abusing leaked bind9  secret keys to control dns  entries",
    "intercepting ssh  credentials via ssh honeypots",
    "abusing git  symlinks for privilege escalation via sudo",
    "injecting xxe  payloads into dmg  files"
  ],
  "Squashed": [
    "spotting and leveraging nfs misconfigurations",
    "managing users via the linux command line",
    "enumerating and understanding a system running x11"
  ],
  "Stacked": [
    "creating and executing aws lambda functions",
    "exploiting cve-2021-32090",
    "localstack api handler command injection",
    "escalating privileges via docker container creation"
  ],
  "Static": [
    "decompression troubleshooting",
    "multiple server pivoting",
    "configuring routes for vpns",
    "exploiting phuip-fpizdam",
    "php x-debug exploitation",
    "format string attack exploitation"
  ],
  "SteamCloud": [
    "exploiting kubernetes"
  ],
  "StreamIO": [
    "lfi using php wrappers",
    "source code review",
    "detecting and exploiting remote file inclusion",
    "browser saved credentials retrieval and cracking",
    "automatic ldap enumeration for lateral movement",
    "ldap abuse for privilege escalation",
    "laps password exposure"
  ],
  "Support": [
    "connecting to an smb share",
    "quering an ldap server for information",
    "performing a resource based constrained delegation attack"
  ],
  "Talkative": [
    "network enumeration",
    "exploiting capabilities"
  ],
  "Tentacle": [
    "dns enumeration",
    "squid proxy enumeration",
    "opensmtpd exploitation",
    "kerberos"
  ],
  "Tenten": [
    "enumerating wordpress",
    "exploit modification",
    "basic steganography",
    "exploiting nopasswd files"
  ],
  "Timelapse": [
    "public smb share",
    "laps privilege escalation"
  ],
  "Toby": [
    "interacting with malware backdoors",
    "cryptography",
    "pam module authentication"
  ],
  "Toolbox": [
    "leveraging postgresql sql injection for rce",
    "docker toolbox exploitation"
  ],
  "Trick": [
    "dns zone transfer",
    "using sql injection to read system files",
    "exploitation of file permission misconfiguration"
  ],
  "Unbalanced": [
    "blind xpath injection",
    "pi-hole exploitation"
  ],
  "Unobtainium": [
    "electron application reversing",
    "prototype pollution exploitation",
    "kubernetes exploitation"
  ],
  "Waldo": [
    "source code review",
    "rbash escape techniques",
    "linux capabilities enumeration"
  ],
  "Wifinetic": [
    "password reuse",
    "wps brute force attack"
  ],
  "Ypuffy": [
    "crafting custom ldap queries / manually finding the rootdse",
    "enumeration and exploitation of ssh ca authentication configurations"
  ],
  "Zetta": [
    "postgres command execution",
    "fxp & ftp bounce attack"
  ],
  "Zipper": [
    "zabbix api enumeration",
    "exploit modification",
    "zabbix agent command execution",
    "overcoming reverse shell disconnects/timeouts",
    "relative path hijacking"
  ],
  "dynstr": [
    "command injection",
    "dynamic dns exploitation",
    "cp wildcard injection"
  ],
  "pivotapi": [
    "metadata enumeration",
    "abusing unset preauth with kerberos",
    "analyzing executables through memory dumps",
    "dotnet source code decompilation",
    "abusing mssql for remote code execution",
    "extracting keepass database passwords",
    "abusing active directory misconfigurations"
  ]
}


# Colours
COLOR_YELLOW = "\033[93m"
COLOR_GREEN = "\033[92m"
COLOR_END = "\033[0m"


def get_skills(skills_dict):
    all_skills = set()
    for skills in skills_dict.values():
        all_skills.update(skills)
    return sorted(all_skills)

def find_machines_by_skill(skill, skills_dict):
    matching_machines = []
    for machine, skills in skills_dict.items():
        for s in skills:
            if skill in s.lower():
                matching_machines.append((machine, s))
                break
    return matching_machines

def highlight_term(line, term):
    highlighted_line = line.replace(term, f"{COLOR_YELLOW}{term}{COLOR_END}")
    return highlighted_line


def main():
    parser = argparse.ArgumentParser(description="HTB writeup skills learned query tool.")
    
    parser.add_argument('skill', type=str, nargs='?', help="The skill to search for")
    
    argcomplete.autocomplete(parser)
    args = parser.parse_args()

    if args.skill:
        skill = args.skill.lower()
        machines = find_machines_by_skill(skill, skills_dict)
        
        if machines:
            print(f"\nMachine\t\tSkill")
            print(f"--------\t------")
            for machine, full_skill in machines:
                if len(machine) > 7:
                    print(f"\n{COLOR_GREEN}{machine}{COLOR_END}\t{highlight_term(full_skill, skill)}")
                else:
                    print(f"\n{COLOR_GREEN}{machine}{COLOR_END}\t\t{highlight_term(full_skill, skill)}")
        else:
            print(f"No machine found with the skill '{skill}'")

if __name__ == "__main__":
    main()
