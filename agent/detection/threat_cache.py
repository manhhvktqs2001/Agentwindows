class ThreatCache:
    """Cache threat intelligence cho agent (hash, IP, domain, ...)"""
    def __init__(self):
        self.hashes = set()
        self.ips = set()
        self.domains = set()

    def load(self, threat_list):
        for t in threat_list:
            ttype = t.get('threat_type')
            tval = t.get('threat_value')
            if ttype == 'Hash':
                self.hashes.add(tval)
            elif ttype == 'IP':
                self.ips.add(tval)
            elif ttype == 'Domain':
                self.domains.add(tval)

    def check_hash(self, h):
        return h in self.hashes
    def check_ip(self, ip):
        return ip in self.ips
    def check_domain(self, d):
        return d in self.domains
