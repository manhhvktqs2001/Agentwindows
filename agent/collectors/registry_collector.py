from ..schemas.events import EventData
from datetime import datetime

class RegistryCollector:
    """Thu thập sự kiện registry cho agent Windows (khung cơ bản)"""
    def __init__(self):
        pass

    def collect(self):
        # TODO: Cần hook hoặc polling registry để lấy event thực tế
        # Trả về list EventData (giả lập mẫu)
        events = []
        # Ví dụ event mẫu
        # event = EventData(
        #     event_type='Registry',
        #     event_action='Create',
        #     event_timestamp=datetime.utcnow(),
        #     registry_key='HKEY_LOCAL_MACHINE\\Software\\Test',
        #     registry_value_name='TestValue',
        #     registry_value_data='123',
        #     registry_operation='Create'
        # )
        # events.append(event)
        return events
