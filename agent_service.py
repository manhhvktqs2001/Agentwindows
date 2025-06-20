# agent_service.py
"""
EDR Agent Windows Service
Implements the agent as a Windows service for automatic startup and management
"""

import sys
import os
import asyncio
import logging
import win32serviceutil
import win32service
import win32event
import servicemanager
from pathlib import Path

# Add agent path
agent_path = Path(__file__).parent
sys.path.insert(0, str(agent_path))

from main import EDRAgent

class EDRAgentService(win32serviceutil.ServiceFramework):
    """EDR Agent Windows Service"""
    
    _svc_name_ = "EDRSecurityAgent"
    _svc_display_name_ = "EDR Security Agent"
    _svc_description_ = "Endpoint Detection and Response Security Monitoring Agent"
    
    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.agent = None
        self.loop = None
        
        # Setup logging for service
        self._setup_service_logging()
    
    def _setup_service_logging(self):
        """Setup logging for Windows service"""
        try:
            log_dir = Path(__file__).parent / 'logs'
            log_dir.mkdir(parents=True, exist_ok=True)
            
            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
                handlers=[
                    logging.FileHandler(log_dir / 'edr_agent_service.log', encoding='utf-8'),
                    logging.StreamHandler()
                ]
            )
            
            self.logger = logging.getLogger('EDRAgentService')
            self.logger.info("🛡️ EDR Agent Service logging initialized")
            
        except Exception as e:
            print(f"❌ Failed to setup logging: {e}")
            servicemanager.LogErrorMsg(f"Failed to setup logging: {e}")

    def SvcStop(self):
        """Stop the service"""
        try:
            self.logger.info("🛑 Service stop requested")
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            
            # Signal stop event
            win32event.SetEvent(self.hWaitStop)
            
            # Stop the agent
            if self.agent and self.loop:
                asyncio.run_coroutine_threadsafe(self.agent.stop(), self.loop)
            
            self.logger.info("✅ Service stopped")
            
        except Exception as e:
            self.logger.error(f"❌ Service stop error: {e}")
            servicemanager.LogErrorMsg(f"Service stop error: {e}")
    
    def SvcDoRun(self):
        """Main service execution"""
        try:
            servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                                servicemanager.PYS_SERVICE_STARTED,
                                (self._svc_name_, ''))
            
            self.logger.info("🚀 Starting EDR Agent Service")
            
            # Run the main service loop
            self._run_agent_service()
            
        except Exception as e:
            self.logger.error(f"❌ Service execution error: {e}")
            servicemanager.LogErrorMsg(f"Service execution error: {e}")
    
    def _run_agent_service(self):
        """Run the agent in service mode"""
        try:
            # Create new event loop for the service
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            
            # Create and initialize agent
            self.agent = EDRAgent()
            
            # Run the agent
            self.loop.run_until_complete(self._service_main())
            
        except Exception as e:
            self.logger.error(f"❌ Agent service execution failed: {e}")
            raise
        finally:
            if self.loop:
                self.loop.close()
    
    async def _service_main(self):
        """Main service execution with agent"""
        try:
            # Initialize agent
            if not await self.agent.initialize():
                raise Exception("Agent initialization failed")
            
            self.logger.info("✅ Agent initialized successfully")
            
            # Start agent
            await self.agent.start()
            
            self.logger.info("✅ Agent started successfully")
            
            # Wait for stop signal
            await self._wait_for_stop_signal()
            
        except Exception as e:
            self.logger.error(f"❌ Service main execution failed: {e}")
            raise
    
    async def _wait_for_stop_signal(self):
        """Wait for service stop signal"""
        try:
            while True:
                # Check if stop event is signaled
                result = win32event.WaitForSingleObject(self.hWaitStop, 1000)  # 1 second timeout
                
                if result == win32event.WAIT_OBJECT_0:
                    # Stop signal received
                    self.logger.info("📡 Stop signal received")
                    break
                elif result == win32event.WAIT_TIMEOUT:
                    # Timeout - continue waiting
                    continue
                else:
                    # Other result - break
                    break
                
                # Small delay to prevent busy waiting
                await asyncio.sleep(0.1)
                
        except Exception as e:
            self.logger.error(f"❌ Error while waiting for stop signal: {e}")

def install_service():
    """Install the EDR Agent service"""
    try:
        print("📦 Installing EDR Agent Service...")
        
        # Install service
        win32serviceutil.InstallService(
            EDRAgentService._svc_reg_class_,
            EDRAgentService._svc_name_,
            EDRAgentService._svc_display_name_,
            description=EDRAgentService._svc_description_,
            startType=win32service.SERVICE_AUTO_START
        )
        
        print("✅ EDR Agent Service installed successfully")
        print(f"   Service Name: {EDRAgentService._svc_name_}")
        print(f"   Display Name: {EDRAgentService._svc_display_name_}")
        print("   Start Type: Automatic")
        print("")
        print("💡 Use 'net start EDRSecurityAgent' to start the service")
        
    except Exception as e:
        print(f"❌ Service installation failed: {e}")
        return False
    
    return True

def uninstall_service():
    """Uninstall the EDR Agent service"""
    try:
        print("🗑️ Uninstalling EDR Agent Service...")
        
        # Stop service if running
        try:
            win32serviceutil.StopService(EDRAgentService._svc_name_)
            print("🛑 Service stopped")
        except:
            pass
        
        # Remove service
        win32serviceutil.RemoveService(EDRAgentService._svc_name_)
        
        print("✅ EDR Agent Service uninstalled successfully")
        
    except Exception as e:
        print(f"❌ Service uninstallation failed: {e}")
        return False
    
    return True

def start_service():
    """Start the EDR Agent service"""
    try:
        print("🚀 Starting EDR Agent Service...")
        win32serviceutil.StartService(EDRAgentService._svc_name_)
        print("✅ EDR Agent Service started successfully")
        
    except Exception as e:
        print(f"❌ Failed to start service: {e}")
        return False
    
    return True

def stop_service():
    """Stop the EDR Agent service"""
    try:
        print("🛑 Stopping EDR Agent Service...")
        win32serviceutil.StopService(EDRAgentService._svc_name_)
        print("✅ EDR Agent Service stopped successfully")
        
    except Exception as e:
        print(f"❌ Failed to stop service: {e}")
        return False
    
    return True

def service_status():
    """Get service status"""
    try:
        status = win32serviceutil.QueryServiceStatus(EDRAgentService._svc_name_)[1]
        
        status_map = {
            win32service.SERVICE_STOPPED: "Stopped",
            win32service.SERVICE_START_PENDING: "Starting",
            win32service.SERVICE_STOP_PENDING: "Stopping",
            win32service.SERVICE_RUNNING: "Running",
            win32service.SERVICE_CONTINUE_PENDING: "Continue Pending",
            win32service.SERVICE_PAUSE_PENDING: "Pause Pending",
            win32service.SERVICE_PAUSED: "Paused"
        }
        
        status_text = status_map.get(status, f"Unknown ({status})")
        print(f"📊 EDR Agent Service Status: {status_text}")
        
        return status
        
    except Exception as e:
        print(f"❌ Failed to get service status: {e}")
        return None

def main():
    """Main entry point for service management"""
    if len(sys.argv) == 1:
        # Run as service
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(EDRAgentService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        # Handle command line arguments
        command = sys.argv[1].lower()
        
        if command == 'install':
            install_service()
        elif command == 'uninstall':
            uninstall_service()
        elif command == 'start':
            start_service()
        elif command == 'stop':
            stop_service()
        elif command == 'restart':
            stop_service()
            start_service()
        elif command == 'status':
            service_status()
        elif command == 'debug':
            # Run in debug mode (not as service)
            print("🔧 Running EDR Agent in debug mode...")
            print("   (Press Ctrl+C to stop)")
            
            try:
                agent = EDRAgent()
                asyncio.run(agent.initialize())
                asyncio.run(agent.start())
            except KeyboardInterrupt:
                print("\n🛑 Debug mode stopped by user")
            except Exception as e:
                print(f"❌ Debug mode failed: {e}")
        else:
            print("EDR Security Agent Service Manager")
            print("="*40)
            print("Usage: python agent_service.py [command]")
            print("")
            print("Commands:")
            print("  install   - Install the service")
            print("  uninstall - Uninstall the service")
            print("  start     - Start the service")
            print("  stop      - Stop the service")
            print("  restart   - Restart the service")
            print("  status    - Show service status")
            print("  debug     - Run in debug mode (not as service)")
            print("")
            print("Examples:")
            print("  python agent_service.py install")
            print("  python agent_service.py start")
            print("  python agent_service.py debug")

if __name__ == '__main__':
    # Check if running on Windows
    if sys.platform != 'win32':
        print("❌ This service is designed for Windows only")
        sys.exit(1)
    
    try:
        main()
    except KeyboardInterrupt:
        print("\n🛑 Operation cancelled by user")
    except Exception as e:
        print(f"❌ Service manager error: {e}")
        sys.exit(1)