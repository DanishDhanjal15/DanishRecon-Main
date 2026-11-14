class RecommendationEngine:
    """
    Core engine to process scan findings, prioritize vulnerabilities,
    generate compliance reports, and output hardened configuration blueprints.
    """
    def __init__(self):
        # Precise service-specific recommendations as requested by the user
        self.specific_recs = {
            "ftp":     "CRITICAL: Disable FTP entirely. Replace with SFTP/SCP. Block port 21 at perimeter. If needed, enforce TLS (FTPS) with auth.",
            "telnet":  "CRITICAL: Disable Telnet immediately. Use SSH with key-based auth only. Telnet transmits all data in cleartext.",
            "ssh":     "HIGH: Disable password auth; enforce key-based. Restrict SSH to trusted IPs via firewall. Enable MFA. Audit authorized_keys.",
            "http":    "HIGH: Force HTTPS redirect (301). Implement HSTS. Deploy WAF. Enable CSP headers. Input validation against XSS/SQLi.",
            "https":   "MEDIUM: Enforce TLS 1.2+, disable TLS 1.0/1.1. Use HSTS with preloading. Rotate certificates. Audit cipher suites.",
            "http-alt":"HIGH: Disable AJP connector (server.xml). Use strong admin credentials. Restrict management interface to localhost.",
            "mysql":   "CRITICAL: Bind MySQL to 127.0.0.1. Remove anonymous user. Change root password. Enable SSL. Apply principle of least privilege.",
            "rdp":     "CRITICAL: Patch BlueKeep (KB4499175). Enable NLA. Restrict RDP via VPN only. Enforce MFA. Implement account lockout.",
            "smb":     "CRITICAL: Apply MS17-010 patches. Disable SMBv1. Block 445 at internet boundary. Disable null sessions. Enable SMB signing.",
            "smtp":    "MEDIUM: Disable open relay. Configure SPF/DKIM/DMARC. Limit VRFY/EXPN commands. Enable TLS for SMTP.",
            "snmp":    "HIGH: Change default community strings. Use SNMPv3 with auth/encryption. Restrict SNMP to management hosts only.",
        }
        
        # Generic recommendations
        self.generic_recs = [
            "◉ Implement network segmentation and micro-segmentation (zero-trust architecture).",
            "◉ Enable comprehensive logging and SIEM integration (Splunk/ELK/Wazuh).",
            "◉ Deploy EDR/XDR on all endpoints (CrowdStrike/SentinelOne/Defender).",
            "◉ Enforce principle of least privilege across all accounts and services.",
            "◉ Implement automated patch management with SLA: Critical <24h, High <7d.",
            "◉ Conduct regular penetration testing (quarterly) and vulnerability assessments.",
            "◉ Implement multi-factor authentication on all external-facing services.",
            "◉ Establish incident response plan with tabletop exercises.",
            "◉ Regular security awareness training for all staff."
        ]

    def generate_recommendations(self, vuln_data):
        """
        Maps raw vulnerability categories and services to prioritized recommendations and remediation SLAs.
        """
        recommendations = []
        processed_keys = set()
        
        # Mapping templates for mapped vulnerability types
        type_mappings = {
            'xss': {
                'vulnerability': 'Cross-Site Scripting (XSS)',
                'severity': 'HIGH',
                'action': self.specific_recs.get('http', 'Force HTTPS redirect, deploy WAF, enable CSP, input validation.'),
                'sla': 'Remediate within 7 days'
            },
            'sql_injection': {
                'vulnerability': 'SQL Injection (SQLi)',
                'severity': 'CRITICAL',
                'action': 'Enforce parameterized queries or prepared statements (via ORM or PDO) for all database transactions. Never concatenate raw user input into database commands.',
                'sla': 'Remediate within 24 hours'
            },
            'idor': {
                'vulnerability': 'Insecure Direct Object Reference (IDOR)',
                'severity': 'HIGH',
                'action': 'Implement robust server-side authentication and granular authorization checks. Always verify user permissions before accessing or editing records.',
                'sla': 'Remediate within 7 days'
            },
            'weak_authentication': {
                'vulnerability': 'Weak Authentication / Session Management',
                'severity': 'CRITICAL',
                'action': 'Enforce strong password complexity rules, multi-factor authentication (MFA), account lockouts after consecutive failed logins, and secure session management.',
                'sla': 'Remediate within 24 hours'
            },
            'missing_security_headers': {
                'vulnerability': 'Missing HTTP Security Headers',
                'severity': 'MEDIUM',
                'action': 'Configure web server (Nginx/Apache) to return standard security headers: Content-Security-Policy, Strict-Transport-Security (HSTS), X-Frame-Options, and X-Content-Type-Options.',
                'sla': 'Remediate within 30 days'
            },
            'weak_cryptography': {
                'vulnerability': 'Weak Cryptographic Configuration / Cipher Suites',
                'severity': 'HIGH',
                'action': self.specific_recs.get('https', 'Enforce TLS 1.2+, disable TLS 1.0/1.1, audit cipher suites.'),
                'sla': 'Remediate within 7 days'
            }
        }

        # First, process based on mapped types
        for item in vuln_data:
            vtype = item.get('type')
            title = item.get('title', '').lower()
            
            # 1. Match specific type categories
            if vtype in type_mappings and vtype not in processed_keys:
                processed_keys.add(vtype)
                template = type_mappings[vtype]
                recommendations.append({
                    'vulnerability': template['vulnerability'],
                    'severity': template['severity'],
                    'action': template['action'],
                    'sla': template['sla'],
                    'original_finding': title
                })

            # 2. Check for service-specific triggers in title (e.g. "ftp", "ssh", "mysql")
            for svc, rec_text in self.specific_recs.items():
                if svc in title and svc not in processed_keys:
                    processed_keys.add(svc)
                    severity = "CRITICAL" if "CRITICAL" in rec_text else "HIGH" if "HIGH" in rec_text else "MEDIUM"
                    clean_rec = rec_text.split(": ", 1)[-1]
                    recommendations.append({
                        'vulnerability': f"{svc.upper()} Security Hardening",
                        'severity': severity,
                        'action': clean_rec,
                        'sla': 'Remediate within 24 hours' if severity == 'CRITICAL' else 'Remediate within 7 days',
                        'original_finding': title
                    })
        
        # If no specific recommendations are mapped, add generic fallback
        if not recommendations and vuln_data:
            recommendations.append({
                'vulnerability': 'General Vulnerability Remediation',
                'severity': 'MEDIUM',
                'action': 'Review scan details, apply patches, and check system authorization controls.',
                'sla': 'Remediate within 14 days',
                'original_finding': vuln_data[0].get('title', '')
            })

        # Append generic recommendations as items to return
        # (Though UI mainly consumes recommendations list, adding them ensures completeness)
        for gen in self.generic_recs:
            recommendations.append({
                'vulnerability': 'Generic Security Control',
                'severity': 'LOW',
                'action': gen,
                'sla': 'Ongoing operational best practice',
                'original_finding': 'Best Practice'
            })

        # Sort recommendations: CRITICAL -> HIGH -> MEDIUM -> LOW
        severity_rank = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        recommendations.sort(key=lambda r: severity_rank.get(r['severity'], 4))

        return {'recommendations': recommendations}

    def generate_nginx_hardened_config(self):
        """
        Generates a hardened, production-ready Nginx configuration block.
        """
        return """# Hardened Nginx configuration generated by DanishRecon
server {
    listen 443 ssl http2;
    server_name _;

    # SSL protocols and hardened ciphers (Disables TLS 1.0, 1.1)
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384';

    # Security Headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

    # Mitigate buffer overflow / DDoS attempts
    client_body_buffer_size 10K;
    client_header_buffer_size 1k;
    client_max_body_size 8m;
    large_client_header_buffers 2 1k;

    # Prevent access to dotfiles (.git, .env, etc.)
    location ~ /\\.(?!well-known) {
        deny all;
        access_log off;
        log_not_found off;
    }
}
"""

    def generate_apache_hardened_config(self):
        """
        Generates a hardened, production-ready Apache configuration block.
        """
        return """# Hardened Apache configuration generated by DanishRecon

# SSL Hardening - Enforces TLS 1.2+ only
<IfModule mod_ssl.c>
    SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
    SSLHonorCipherOrder on
    SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
</IfModule>

# Security Headers Configuration
<IfModule mod_headers.c>
    Header set X-Frame-Options "SAMEORIGIN"
    Header set X-Content-Type-Options "nosniff"
    Header set X-XSS-Protection "1; mode=block"
    Header set Referrer-Policy "no-referrer-when-downgrade"
    Header set Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'"
    Header set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
</IfModule>

# Disable Directory Browsing
Options -Indexes

# Prevent access to sensitive dotfiles / configurations
RedirectMatch 404 /\\.(git|ht|env|conf)
"""

    def generate_waf_rules(self):
        """
        Generates a ModSecurity-compatible Web Application Firewall (WAF) rule set.
        """
        return """# ModSecurity WAF rules generated by DanishRecon
SecRuleEngine On
SecRequestBodyAccess On
SecResponseBodyAccess On

# Block SQL Injection (SQLi) patterns in arguments
SecRule ARGS "@rx (?i)(union\\s+select|select\\s+.*\\s+from|insert\\s+into|update\\s+.*\\s+set|delete\\s+from)" \\
    "id:100001,phase:2,deny,status:403,msg:'SQL Injection Attempt Blocked'"

# Block Cross-Site Scripting (XSS) patterns in arguments
SecRule ARGS "@rx (?i)(<script|javascript:|onerror=|onload=|alert\\()" \\
    "id:100002,phase:2,deny,status:403,msg:'Cross-Site Scripting (XSS) Blocked'"

# Block Path Traversal (IDOR / Local File Inclusion)
SecRule ARGS "@rx (?i)(\\.\\./\\.\\./|\\.\\.\\\\\\.\\.\\\\|/etc/passwd|/windows/win\\.ini)" \\
    "id:100003,phase:2,deny,status:403,msg:'Path Traversal Attempt Blocked'"

# Block HTTP Protocol Violations / Corrupt payloads
SecRule REQBODY_ERROR "!@eq 0" \\
    "id:100004,phase:1,deny,status:400,msg:'Failed to parse request body'"
"""

    def generate_compliance_report(self, recommendations):
        """
        Maps the list of active recommendations to compliance standards.
        """
        has_critical = any(r.get('severity') == 'CRITICAL' for r in recommendations)
        has_high = any(r.get('severity') == 'HIGH' for r in recommendations)
        has_crypto = any('Cryptographic' in r.get('vulnerability', '') or 'https' in str(r.get('action')).lower() for r in recommendations)
        has_auth = any('Authentication' in r.get('vulnerability', '') or 'auth' in str(r.get('action')).lower() for r in recommendations)

        # Build PCI-DSS status
        if has_critical or has_high:
            pci_status = "Non-Compliant (Critical/High injection or access vulnerabilities detected) - Action required"
        else:
            pci_status = "Compliant - Target satisfies firewall, input validation, and system audit requirements"

        # Build HIPAA status
        if has_crypto or has_auth:
            hipaa_status = "Non-Compliant - Encryption (Transit/Rest) or session controls failed security rules"
        else:
            hipaa_status = "Compliant - Transmission security and access control policies met"

        # Build NIST CSF status
        if recommendations:
            nist_status = "Action required - Vulnerability scanning verification gaps and technical control improvements identified"
        else:
            nist_status = "Compliant - Controls align with NIST CSF ID.RA and PR.PT standards"

        # Build ISO 27001 status
        if recommendations:
            iso_status = "Action required - Cryptographic controls (A.10.1) and system vulnerability management (A.12.6) gaps found"
        else:
            iso_status = "Compliant - Systems align with ISO/IEC 27001 control guidelines"

        return {
            'PCI-DSS': {'status': pci_status},
            'HIPAA': {'status': hipaa_status},
            'NIST CSF': {'status': nist_status},
            'ISO 27001': {'status': iso_status}
        }

def generate_all_recommendations(vuln_data):
    """
    Helper module function.
    """
    engine = RecommendationEngine()
    return engine.generate_recommendations(vuln_data)
