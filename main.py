#!/usr/bin/env python3
"""
Enhanced EDR Agent - Main Entry Point - FIXED VERSION
Agent với khả năng thu thập dữ liệu liên tục và gửi cho server
"""

import asyncio
import logging
import signal
import sys
import time
import os
import ctypes
import subprocess
from pathlib import Path

def is_admin():
    """Check if running with administrator privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def fix_imports():
    """Fix import issues by setting up proper Python path"""
    try:
        # Get current directory
        current_dir = Path(__file__).parent.absolute()
        
        # Add current directory to Python path
        if str(current_dir) not in sys.path:
            sys.path.insert(0, str(current_dir))
        
        # Add agent directory to Python path
        agent_dir = current_dir / 'agent'
        if str(agent_dir) not in sys.path:
            sys.path.insert(0, str(agent_dir))
        
        return True
        
    except Exception as e:
        print(f"❌ Failed to fix imports: {e}")
        return False

# Check admin privileges and warn if not admin
if is_admin():
    print("=" * 60)
    print("✅ EDR Agent - Running with Administrator Privileges")
    print("=" * 60)
    print("Enhanced monitoring capabilities enabled:")
    print("  - Process monitoring with elevated access")
    print("  - Network connection monitoring")
    print("  - File system monitoring")
    print("  - Registry monitoring")
    print("  - Authentication monitoring")
    print("  - System event monitoring")
    print("=" * 60)
else:
    print("=" * 60)
    print("⚠️  WARNING: EDR Agent is NOT running with Administrator Privileges")
    print("=" * 60)
    print("Limited monitoring capabilities:")
    print("  - Some system monitoring may be restricted")
    print("  - Registry monitoring may not work")
    print("  - Some process details may be limited")
    print("=" * 60)
    print("💡 To run with full privileges:")
    print("   1. Right-click on Command Prompt/PowerShell")
    print("   2. Select 'Run as administrator'")
    print("   3. Navigate to this directory")
    print("   4. Run: python main.py")
    print("=" * 60)
    print("Press ENTER to continue with limited privileges, or Ctrl+C to exit...")
    try:
        input()
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)

# Fix imports
if not fix_imports():
    print("Failed to configure import paths")
    sys.exit(1)

# Add current directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

try:
    from agent.core.config_manager import ConfigManager
except Exception as e:
    print(f"❌ ConfigManager import failed: {e}")
    sys.exit(1)

try:
    from agent.core.agent_manager import AgentManager
except Exception as e:
    print(f"❌ AgentManager import failed: {e}")
    sys.exit(1)

# Configure enhanced logging
def setup_logging():
    """Setup enhanced logging configuration"""
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    # Create logs directory if it doesn't exist
    log_dir = Path(__file__).parent / 'logs'
    log_dir.mkdir(exist_ok=True)
    
    # Configure logging with UTF-8 encoding
    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        handlers=[
            logging.FileHandler(log_dir / 'enhanced_agent.log', encoding='utf-8'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    # Set specific log levels for noisy modules
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)
    logging.getLogger('asyncio').setLevel(logging.WARNING)

class EnhancedEDRAgent:
    """Enhanced EDR Agent with continuous monitoring capabilities - FIXED"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.agent_manager = None
        self.config_manager = None
        self.is_running = False
        self.start_time = None
        
        # Performance tracking
        self.performance_stats = {
            'start_time': None,
            'events_collected': 0,
            'events_sent': 0,
            'alerts_received': 0,
            'uptime': 0
        }
    
    async def initialize(self):
        """Initialize enhanced EDR agent"""
        try:
            self.logger.info("Initializing Enhanced EDR Agent...")
            self.logger.info("=" * 60)
            
            # Confirm admin privileges
            if is_admin():
                self.logger.info("Running with Administrator privileges - Full monitoring enabled")
            else:
                self.logger.warning("Running without Administrator privileges - Limited monitoring")
            
            # Setup configuration
            self.config_manager = ConfigManager()
            await self.config_manager.load_config()
            
            # Initialize agent manager
            self.agent_manager = AgentManager(self.config_manager)
            await self.agent_manager.initialize()
            
            self.logger.info("Enhanced EDR Agent initialized successfully")
            self.logger.info("=" * 60)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Enhanced EDR Agent: {e}")
            return False
    
    async def start(self):
        """Start enhanced EDR agent"""
        try:
            self.logger.info("🚀 Starting Enhanced EDR Agent...")
            self.is_running = True
            self.start_time = time.time()
            
            # Start agent manager
            await self.agent_manager.start()
            
            # Start monitoring loops
            asyncio.create_task(self._performance_monitoring_loop())
            asyncio.create_task(self._statistics_logging_loop())
            
            self.logger.info("✅ Enhanced EDR Agent started successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Failed to start agent: {e}")
            return False
    
    async def stop(self):
        """Stop enhanced EDR agent gracefully"""
        try:
            self.logger.info("Stopping Enhanced EDR Agent...")
            
            # Set running state
            self.is_running = False
            
            # Stop agent manager
            if self.agent_manager:
                await self.agent_manager.stop()
            
            # Calculate final statistics
            if self.start_time:
                uptime = time.time() - self.start_time
                self.performance_stats['uptime'] = uptime
                
                self.logger.info("Final Performance Statistics:")
                self.logger.info(f"   Total Uptime: {uptime:.1f} seconds ({uptime/3600:.2f} hours)")
                self.logger.info(f"   Events Collected: {self.performance_stats['events_collected']}")
                self.logger.info(f"   Events Sent: {self.performance_stats['events_sent']}")
                self.logger.info(f"   Alerts Received: {self.performance_stats['alerts_received']}")
                
                if uptime > 0:
                    events_per_second = self.performance_stats['events_collected'] / uptime
                    self.logger.info(f"   Average Events/Second: {events_per_second:.2f}")
            
            self.logger.info("Enhanced EDR Agent stopped successfully")
            self.logger.info("=" * 60)
            
        except Exception as e:
            self.logger.error(f"Error stopping Enhanced EDR Agent: {e}")
    
    async def _performance_monitoring_loop(self):
        """Monitor agent performance continuously"""
        try:
            while self.is_running:
                try:
                    # Get current statistics
                    if self.agent_manager and self.agent_manager.event_processor:
                        stats = self.agent_manager.event_processor.get_stats()
                        
                        # Update performance stats
                        self.performance_stats['events_collected'] = stats.get('events_collected', 0)
                        self.performance_stats['events_sent'] = stats.get('events_sent', 0)
                        self.performance_stats['alerts_received'] = stats.get('alerts_received', 0)
                        
                        # Check for performance issues
                        processing_rate = stats.get('processing_rate', 0)
                        if processing_rate < 1.0:  # Less than 1 event per second
                            self.logger.debug(f"Low processing rate: {processing_rate:.2f} events/sec")
                    
                    await asyncio.sleep(30)  # Check every 30 seconds
                    
                except Exception as e:
                    self.logger.error(f"Performance monitoring error: {e}")
                    await asyncio.sleep(30)
                    
        except Exception as e:
            self.logger.error(f"Performance monitoring loop failed: {e}")
    
    async def _statistics_logging_loop(self):
        """Log agent statistics periodically"""
        try:
            while self.is_running:
                try:
                    # Calculate uptime
                    if self.start_time:
                        uptime = time.time() - self.start_time
                        self.performance_stats['uptime'] = uptime
                    
                    # Log statistics every 5 minutes
                    if int(time.time()) % 300 == 0:  # Every 5 minutes
                        self.logger.info("Enhanced Agent Statistics:")
                        self.logger.info(f"   Uptime: {uptime:.1f} seconds")
                        self.logger.info(f"   Events Collected: {self.performance_stats['events_collected']}")
                        self.logger.info(f"   Events Sent: {self.performance_stats['events_sent']}")
                        self.logger.info(f"   Alerts Received: {self.performance_stats['alerts_received']}")
                        
                        if self.agent_manager:
                            agent_stats = self.agent_manager.get_status()
                            self.logger.info(f"   Agent Status: Running")
                            self.logger.info(f"   Agent ID: {agent_stats.get('agent_id', 'Unknown')}")
                        
                        self.logger.info("-" * 40)
                    
                    await asyncio.sleep(60)  # Check every minute
                    
                except Exception as e:
                    self.logger.error(f"Statistics logging error: {e}")
                    await asyncio.sleep(60)
                    
        except Exception as e:
            self.logger.error(f"Statistics logging loop failed: {e}")
    
    def signal_handler(self, signum, frame):
        """Handle interrupt signals"""
        print(f"\n🛑 Received signal {signum}, stopping agent gracefully...")
        self.logger.info(f"Received signal {signum}, stopping agent gracefully...")
        self.is_running = False

async def main():
    """Main function to run the agent"""
    
    # Setup logging
    setup_logging()
    
    # Create agent instance
    agent = EnhancedEDRAgent()
    
    # Set up signal handlers
    signal.signal(signal.SIGINT, agent.signal_handler)
    signal.signal(signal.SIGTERM, agent.signal_handler)
    
    try:
        print("🔧 Initializing Enhanced EDR Agent...")
        
        # Initialize agent
        if not await agent.initialize():
            print("❌ Agent initialization failed")
            return
        
        print("🚀 Starting Enhanced EDR Agent...")
        
        # Start agent
        if not await agent.start():
            print("❌ Agent start failed")
            return
        
        print("\n" + "=" * 60)
        print("🚀 Enhanced EDR Agent is now running!")
        print("📊 Monitoring system activities continuously...")
        print("🔔 Press Ctrl+C to stop the program")
        print("=" * 60)
        
        # Keep running until interrupted
        while agent.is_running:
            try:
                await asyncio.sleep(1)
            except KeyboardInterrupt:
                print("\n🛑 Received Ctrl+C, stopping agent gracefully...")
                agent.is_running = False
                break
            
    except KeyboardInterrupt:
        print("\n🛑 Received interrupt signal, stopping agent...")
        agent.is_running = False
    except Exception as e:
        print(f"\n❌ CRITICAL ERROR: {e}")
        print("=" * 60)
        print("🔍 ERROR DETAILS:")
        import traceback
        traceback.print_exc()
        print("=" * 60)
        print("💡 TROUBLESHOOTING:")
        print("1. Check if all dependencies are installed correctly")
        print("2. Verify agent configuration files")
        print("3. Check Windows permissions")
        print("4. Review logs in logs/enhanced_agent.log")
        print("=" * 60)
        
        # Wait for user input before exiting
        try:
            input("\nPress ENTER to exit...")
        except:
            pass
            
    finally:
        try:
            print("\n🔄 Stopping agent and cleaning up...")
            await agent.stop()
            print("\n✅ Agent stopped successfully!")
            print("=" * 60)
        except Exception as e:
            print(f"\n❌ Error during shutdown: {e}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    try:
        print("=" * 60)
        print("🔧 EDR Agent Starting...")
        print("=" * 60)
        
        # Run the agent
        asyncio.run(main())
        
    except Exception as e:
        print(f"\n❌ FATAL ERROR: {e}")
        print("=" * 60)
        print("🔍 FATAL ERROR DETAILS:")
        import traceback
        traceback.print_exc()
        print("=" * 60)
        print("💡 TROUBLESHOOTING:")
        print("1. Make sure all dependencies are installed: pip install -r requirements.txt")
        print("2. Check if Python path is correct")
        print("3. Verify agent files are not corrupted")
        print("4. Check Windows Event Viewer for system errors")
        print("5. Review logs in logs/enhanced_agent.log")
        print("=" * 60)
        
        # Wait for user input before exiting
        try:
            input("\nPress ENTER to exit...")
        except:
            pass