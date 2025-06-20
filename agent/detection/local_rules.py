class LocalRule:
    """Định nghĩa một rule phát hiện local"""
    def __init__(self, name, condition, alert_info):
        self.name = name
        self.condition = condition  # Hàm nhận event, trả về True/False
        self.alert_info = alert_info  # Dict thông tin alert

    def match(self, event):
        return self.condition(event)

    def generate_alert(self, event):
        alert = self.alert_info.copy()
        alert['event'] = event
        return alert

class LocalRules:
    """Quản lý danh sách rule local"""
    @staticmethod
    def load_rules():
        # TODO: Load rule từ file/config, tạm hardcode 1 rule mẫu
        def suspicious_powershell(event):
            return event.event_type == 'Process' and event.process_name and 'powershell' in event.process_name.lower() and '-enc' in (event.command_line or '').lower()
        rule1 = LocalRule(
            name='Suspicious PowerShell Encoded',
            condition=suspicious_powershell,
            alert_info={
                'title': 'Suspicious PowerShell Encoded Command',
                'severity': 'Medium',
                'description': 'PowerShell executed with encoded command',
            }
        )
        return [rule1]
