import psutil

class ProcessUtils:
    @staticmethod
    def list_processes():
        return [p.info for p in psutil.process_iter(['pid', 'name', 'exe', 'username'])]

    @staticmethod
    def kill_process(pid):
        try:
            p = psutil.Process(pid)
            p.terminate()
            return True
        except Exception:
            return False
