package detection

import "regexp"

// compileBashPatterns returns compiled patterns for dangerous shell commands.
func compileBashPatterns() []Pattern {
	return []Pattern{
		{
			Name:        "credential_exfil_pipe",
			Severity:    "critical",
			Description: "Credential file read piped to network tool (exfiltration)",
			Category:    "threat",
			Regex:       regexp.MustCompile(`(cat|head|tail)\s+.*(\.env|\.ssh/|\.aws/|credentials|secrets|tokens?)\b.*\|\s*(curl|wget|nc|ncat)`),
			TriggerGroups: [][]string{
				[]string{"cat", "head", "tail"},
				[]string{".env", ".ssh/", ".aws/", "credential", "secret", "token"},
				[]string{"curl", "wget", "nc"},
			},
		},
		{
			Name:        "credential_exfil_subshell",
			Severity:    "critical",
			Description: "Network tool with credential file read via subshell (exfiltration)",
			Category:    "threat",
			Regex:       regexp.MustCompile("(curl|wget).*(\\$\\(cat|`cat).*(\\.(env|ssh|aws)|credentials|secrets|token)"),
			TriggerGroups: [][]string{
				[]string{"curl", "wget"},
				[]string{"$(cat", "`cat"},
			},
		},
		{
			Name:        "reverse_shell",
			Severity:    "critical",
			Description: "Reverse shell attempt detected",
			Category:    "threat",
			Regex:       regexp.MustCompile(`(bash\s+-i\s+>&\s*/dev/tcp|nc\s+.*-e\s+/bin/(sh|bash)|ncat\s+.*--exec|python[23]?\s+-c\s+.*socket.*connect|perl\s+-e\s+.*socket.*exec|ruby\s+-rsocket\s+-e)`),
			Triggers:    []string{"/dev/tcp", "-e /bin/", "--exec", "-rsocket", "socket.socket", "socket.connect", "import socket"},
		},
		{
			Name:        "reverse_shell_encoded",
			Severity:    "critical",
			Description: "Base64-encoded reverse shell attempt",
			Category:    "threat",
			Regex:       regexp.MustCompile(`(echo|printf)\s+[A-Za-z0-9+/=]+\s*\|\s*(base64\s+-d|openssl\s+base64\s+-d)\s*\|\s*(bash|sh|zsh|python|perl|ruby)`),
			TriggerGroups: [][]string{
				[]string{"echo ", "printf "},
				[]string{"base64"},
			},
		},
		{
			Name:        "firewall_disable",
			Severity:    "critical",
			Description: "Firewall disable command detected",
			Category:    "threat",
			Regex:       regexp.MustCompile(`(ufw\s+disable|iptables\s+-f|iptables\s+--flush|pfctl\s+-d|systemctl\s+(stop|disable)\s+(ufw|firewalld|iptables))`),
			Triggers:    []string{"ufw", "iptables", "pfctl", "firewalld"},
		},
		{
			Name:        "selinux_disable",
			Severity:    "high",
			Description: "Security enforcement (SELinux/AppArmor) disable detected",
			Category:    "threat",
			Regex:       regexp.MustCompile(`(setenforce\s+0|echo\s+0\s*>\s*/sys/fs/selinux/enforce|systemctl\s+(stop|disable)\s+apparmor|aa-teardown)`),
			Triggers:    []string{"setenforce", "selinux", "apparmor", "aa-teardown"},
		},
		{
			Name:        "antivirus_disable",
			Severity:    "high",
			Description: "Antivirus/endpoint protection disable detected",
			Category:    "threat",
			Regex:       regexp.MustCompile(`(systemctl\s+(stop|disable)\s+(clamd|crowdstrike|falcon-sensor|sentinel|cylance|symantec|mcafee)|launchctl\s+unload.*(endpoint|security|protection))`),
			Triggers:    []string{"clamd", "crowdstrike", "falcon-sensor", "sentinel", "cylance", "symantec", "mcafee", "launchctl"},
		},
		{
			Name:        "recursive_delete_root",
			Severity:    "critical",
			Description: "Destructive recursive delete targeting critical paths",
			Category:    "threat",
			Regex:       regexp.MustCompile(`rm\s+(-rf|-fr|--no-preserve-root)\s+(/\s|/\*|/$|~/|/home|/etc|/usr|/var|/system)`),
			Triggers:    []string{"rm -rf", "rm -fr", "--no-preserve-root"},
		},
		{
			Name:        "history_tampering",
			Severity:    "high",
			Description: "Shell history clearing or tampering detected",
			Category:    "threat",
			Regex:       regexp.MustCompile(`(history\s+-c|>\s*~/\.(bash_history|zsh_history)|shred\s+.*history|rm\s+.*\.(bash_history|zsh_history)|unset\s+histfile|export\s+histsize=0)`),
			Triggers:    []string{"history -c", "bash_history", "zsh_history", "histfile", "histsize", "shred"},
		},
		{
			Name:           "ssh_key_exfil",
			Severity:       "critical",
			Description:    "SSH private key access combined with network transfer",
			Category:       "threat",
			Regex:          regexp.MustCompile(`(cat|head|tail|cp|scp|base64)\s+.*(id_rsa|id_ed25519|id_ecdsa|\.pem|\.key)\b`),
			SecondaryRegex: regexp.MustCompile(`(curl|wget|nc|ssh|scp|rsync)\s`),
			TertiaryRegex:  regexp.MustCompile(`[;&|]`),
			Triggers:       []string{"id_rsa", "id_ed25519", "id_ecdsa", ".pem", ".key"},
		},
		{
			Name:        "cryptominer",
			Severity:    "critical",
			Description: "Cryptocurrency miner or mining pool reference detected",
			Category:    "threat",
			Regex:       regexp.MustCompile(`(xmrig|cpuminer|minerd|cgminer|bfgminer|stratum\+tcp|cryptonight|monero.*pool)`),
			Triggers:    []string{"xmrig", "cpuminer", "minerd", "cgminer", "bfgminer", "stratum+tcp", "cryptonight", "monero"},
		},
		{
			Name:        "dns_exfil",
			Severity:    "high",
			Description: "DNS-based data exfiltration pattern detected",
			Category:    "threat",
			Regex:       regexp.MustCompile(`(dig|nslookup|host)\s+.*\$\(|(base64|xxd|od).*\|\s*(dig|nslookup|host)`),
			TriggerGroups: [][]string{
				[]string{"dig ", "nslookup", "host "},
				[]string{"$(", "base64", "xxd", " od "},
			},
		},
		{
			Name:        "suid_manipulation",
			Severity:    "high",
			Description: "SUID/SGID bit manipulation detected (privilege escalation)",
			Category:    "threat",
			Regex:       regexp.MustCompile(`chmod\s+[ug]\+s\s`),
			Triggers:    []string{"chmod"},
		},
		{
			Name:        "suspicious_install",
			Severity:    "medium",
			Description: "Package install from URL source (potential supply chain attack)",
			Category:    "threat",
			Regex:       regexp.MustCompile(`(pip\s+install|npm\s+install|gem\s+install)\s+(https?://|git\+|git://)`),
			TriggerGroups: [][]string{
				[]string{"pip install", "npm install", "gem install"},
				[]string{"http", "git+", "git://"},
			},
		},
	}
}

// compilePromptPatterns returns compiled patterns for prompt injection attacks.
func compilePromptPatterns() []Pattern {
	return []Pattern{
		{
			Name:        "prompt_injection_override",
			Severity:    "high",
			Description: "Prompt injection: attempt to override prior instructions",
			Category:    "threat",
			Regex:       regexp.MustCompile(`(ignore|disregard|forget|override)\s+((all|any|the|your|my|these|those|of)\s+){0,3}(previous|prior|above|earlier)\s+((system|safety)\s+)?(instructions?|rules?|guidelines?|constraints?)`),
			Triggers:    []string{"ignore", "disregard", "forget", "override"},
		},
		{
			Name:        "prompt_injection_persona",
			Severity:    "high",
			Description: "Prompt injection: persona/identity override attempt",
			Category:    "threat",
			Regex:       regexp.MustCompile(`(you are now|from now on you are|your new identity is|act as if you have no restrictions|pretend (you have|there are) no (rules|restrictions|limits))`),
			Triggers:    []string{"you are now", "from now on you are", "new identity", "act as if", "pretend "},
		},
		{
			Name:        "prompt_injection_jailbreak",
			Severity:    "critical",
			Description: "Prompt injection: jailbreak attempt detected",
			Category:    "threat",
			Regex:       regexp.MustCompile(`(jailbreak|dan\s*mode|do anything now|evil\s*mode|uncensored\s*mode|developer\s*mode|god\s*mode)`),
			Triggers:    []string{"jailbreak", "dan mode", "danmode", "do anything now", "evil mode", "uncensored", "developer mode", "god mode"},
		},
		{
			Name:        "exfil_instruction",
			Severity:    "critical",
			Description: "Instruction to exfiltrate data to external endpoint",
			Category:    "threat",
			Regex:       regexp.MustCompile(`(send|post|upload|exfiltrate|forward|transmit)\s+(all|the|my|this|every)\s+(the\s+)?(data|files?|credentials?|secrets?|keys?|tokens?|code|contents?)\s+to\s+(https?://|an?\s+(external|remote))`),
			TriggerGroups: [][]string{
				[]string{"send", "post", "upload", "exfiltrate", "forward", "transmit"},
				[]string{"data", "file", "credential", "secret", "key", "token", "code", "content"},
				[]string{"http", "external", "remote"},
			},
		},
		{
			Name:        "credential_request",
			Severity:    "high",
			Description: "Request to reveal or dump credentials/secrets",
			Category:    "threat",
			Regex:       regexp.MustCompile(`(show|list|output|reveal|dump|print|display|read)\s+(all\s+)?(my\s+)?(api[_ ]?keys?|tokens?|credentials?|secrets?|passwords?|private[_ ]keys?|\.env)`),
			TriggerGroups: [][]string{
				[]string{"show", "list", "output", "reveal", "dump", "print", "display", "read"},
				[]string{"api key", "api_key", "apikey", "token", "credential", "secret", "password", "private key", "private_key", ".env"},
			},
		},
		{
			Name:        "security_disable_request",
			Severity:    "high",
			Description: "Request to disable security controls",
			Category:    "threat",
			Regex:       regexp.MustCompile(`(disable|turn off|remove|bypass|skip)\s+(the\s+)?(firewall|security|antivirus|sandbox|shield|protection|hook|monitoring|logging|audit)`),
			TriggerGroups: [][]string{
				[]string{"disable", "turn off", "remove", "bypass", "skip"},
				[]string{"firewall", "security", "antivirus", "sandbox", "shield", "protection", "hook", "monitoring", "logging", "audit"},
			},
		},
	}
}

// compileWebPatterns returns compiled patterns for suspicious web/URL activity.
func compileWebPatterns() []Pattern {
	return []Pattern{
		{
			Name:        "exfil_endpoint",
			Severity:    "high",
			Description: "Known data exfiltration endpoint detected",
			Category:    "threat",
			Regex:       regexp.MustCompile(`(requestbin\.com|pipedream\.net|webhook\.site|hookbin\.com|requestcatcher\.com|beeceptor\.com|mockbin\.org|ngrok\.io|ngrok-free\.app|burpcollaborator\.net|interact\.sh|canarytokens\.com)`),
			Triggers:    []string{"requestbin", "pipedream", "webhook.site", "hookbin", "requestcatcher", "beeceptor", "mockbin", "ngrok", "burpcollaborator", "interact.sh", "canarytokens"},
		},
		{
			Name:        "raw_ip_fetch",
			Severity:    "medium",
			Description: "HTTP request to raw IP address (potential C2 or exfiltration)",
			Category:    "threat",
			Regex:       regexp.MustCompile(`https?://(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)`),
			Triggers:    []string{"://"},
		},
	}
}
