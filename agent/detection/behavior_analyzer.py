from .local_rules import LocalRules

class BehaviorAnalyzer:
    """Phân tích hành vi dựa trên event và local rules"""
    def __init__(self, rules=None):
        self.rules = rules or LocalRules.load_rules()

    def analyze(self, event):
        """Phân tích một event, trả về list alert nếu phát hiện"""
        alerts = []
        for rule in self.rules:
            if rule.match(event):
                alerts.append(rule.generate_alert(event))
        return alerts
