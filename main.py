#!/usr/bin/env python3
"""
Enhanced EDR Agent - Main Entry Point
Agent với khả năng thu thập dữ liệu liên tục và gửi cho server
"""

import asyncio
import logging
import signal
import sys
import time
import os
import ctypes
from pathlib import Path

def is_admin():
    """Check if running with administrator privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    """Re-run the script with administrator privileges"""
    try:
        if not is_admin():
            print("=" * 60)
            print("EDR Agent requires administrator privileges to monitor system activities.")
            print("Requesting elevation...")
            print("=" * 60)
            
            # Get the current script path
            script_path = os.path.abspath(__file__)
            
            # Re-run with admin privileges
            ctypes.windll.shell32.ShellExecuteW(
                None, 
                "runas", 
                sys.executable, 
                f'"{script_path}"', 
                None, 
                1
            )
            sys.exit(0)
    except Exception as e:
        print(f"Failed to elevate privileges: {e}")
        print("Please run this script as Administrator manually.")
        sys.exit(1)

def setup_imports():
    """Setup import paths"""
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
        print(f"❌ Failed to setup imports: {e}")
        return False

# Check and request admin privileges
print("🔒 Checking admin privileges...")
run_as_admin()

# Confirm admin privileges
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
    print("❌ ERROR: Failed to obtain administrator privileges!")
    print("EDR Agent requires admin rights for full monitoring capabilities.")
    input("Press Enter to exit...")
    sys.exit(1)

# Setup imports
print("🔧 Setting up import paths...")
if not setup_imports():
    print("❌ Failed to setup import paths")
    input("Press Enter to exit...")
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
    """Enhanced EDR Agent with continuous monitoring capabilities"""
    
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
            self.logger.info("🚀 Initializing Enhanced EDR Agent...")
            self.logger.info("=" * 60)
            
            # Confirm admin privileges
            if is_admin():
                self.logger.info("✅ Running with Administrator privileges - Full monitoring enabled")
            else:
                self.logger.warning("⚠️ Running without Administrator privileges - Limited monitoring")
            
            # Import required modules
            from agent.core.config_manager import ConfigManager
            from agent.core.agent_manager import AgentManager
            
            # Setup configuration
            self.logger.info("📋 Creating configuration manager...")
            self.config_manager = ConfigManager()
            
            self.logger.info("📋 Loading configuration...")
            await self.config_manager.load_config()
            
            # Initialize agent manager
            self.logger.info("🎯 Creating agent manager...")
            self.agent_manager = AgentManager(self.config_manager)
            
            self.logger.info("🎯 Initializing agent manager...")
            await self.agent_manager.initialize()
            
            self.logger.info("✅ Enhanced EDR Agent initialized successfully")
            self.logger.info("=" * 60)
            
        except ImportError as e:
            self.logger.error(f"❌ Import error during initialization: {e}")
            raise
        except Exception as e:
            self.logger.error(f"❌ Failed to initialize Enhanced EDR Agent: {e}")
            raise
    
    async def start(self):
        """Start enhanced EDR agent with continuous monitoring"""
        try:
            self.logger.info("🚀 Starting Enhanced EDR Agent with continuous monitoring...")
            self.logger.info("📊 Monitoring: Process, Network, System, File, Registry, Authentication")
            self.logger.info("⚡ Enhanced polling intervals for real-time data collection")
            self.logger.info("🔔 Security notifications enabled")
            self.logger.info("=" * 60)
            
            # Start agent
            await self.agent_manager.start()
            
            # Set running state
            self.is_running = True
            self.start_time = time.time()
            self.performance_stats['start_time'] = self.start_time
            
            self.logger.info("✅ Enhanced EDR Agent started successfully")
            self.logger.info("🔄 Continuous monitoring active - Press Ctrl+C to stop")
            self.logger.info("=" * 60)
            
            # Start performance monitoring
            asyncio.create_task(self._performance_monitoring_loop())
            
            # Start statistics logging
            asyncio.create_task(self._statistics_logging_loop())
            
        except Exception as e:
            self.logger.error(f"❌ Failed to start Enhanced EDR Agent: {e}")
            raise
    
    async def stop(self):
        """Stop enhanced EDR agent gracefully"""
        try:
            self.logger.info("🛑 Stopping Enhanced EDR Agent...")
            
            # Set running state
            self.is_running = False
            
            # Stop agent manager
            if self.agent_manager:
                await self.agent_manager.stop()
            
            # Calculate final statistics
            if self.start_time:
                uptime = time.time() - self.start_time
                self.performance_stats['uptime'] = uptime
                
                self.logger.info("📊 Final Performance Statistics:")
                self.logger.info(f"   ⏱️ Total Uptime: {uptime:.1f} seconds ({uptime/3600:.2f} hours)")
                self.logger.info(f"   📥 Events Collected: {self.performance_stats['events_collected']}")
                self.logger.info(f"   📤 Events Sent: {self.performance_stats['events_sent']}")
                self.logger.info(f"   🚨 Alerts Received: {self.performance_stats['alerts_received']}")
                
                if uptime > 0:
                    events_per_second = self.performance_stats['events_collected'] / uptime
                    self.logger.info(f"   📈 Average Events/Second: {events_per_second:.2f}")
            
            self.logger.info("✅ Enhanced EDR Agent stopped successfully")
            self.logger.info("=" * 60)
            
        except Exception as e:
            self.logger.error(f"❌ Error stopping Enhanced EDR Agent: {e}")
    
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
                        queue_utilization = stats.get('queue_utilization', 0)
                        if queue_utilization > 0.8:  # 80% full
                            self.logger.warning(f"⚠️ Event queue utilization high: {queue_utilization:.1%}")
                        
                        processing_rate = stats.get('processing_rate', 0)
                        if processing_rate < 1.0:  # Less than 1 event per second
                            self.logger.warning(f"⚠️ Low processing rate: {processing_rate:.2f} events/sec")
                    
                    await asyncio.sleep(30)  # Check every 30 seconds
                    
                except Exception as e:
                    self.logger.error(f"❌ Performance monitoring error: {e}")
                    await asyncio.sleep(30)
                    
        except Exception as e:
            self.logger.error(f"❌ Performance monitoring loop failed: {e}")
    
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
                        self.logger.info("📊 Enhanced Agent Statistics:")
                        self.logger.info(f"   ⏱️ Uptime: {uptime:.1f} seconds")
                        self.logger.info(f"   📥 Events Collected: {self.performance_stats['events_collected']}")
                        self.logger.info(f"   📤 Events Sent: {self.performance_stats['events_sent']}")
                        self.logger.info(f"   🚨 Alerts Received: {self.performance_stats['alerts_received']}")
                        
                        if self.agent_manager:
                            agent_stats = self.agent_manager.get_status()
                            self.logger.info(f"   🎯 Agent Status: {agent_stats.get('is_monitoring', 'Unknown')}")
                            self.logger.info(f"   🆔 Agent ID: {agent_stats.get('agent_id', 'Unknown')}")
                        
                        self.logger.info("-" * 40)
                    
                    await asyncio.sleep(60)  # Check every minute
                    
                except Exception as e:
                    self.logger.error(f"❌ Statistics logging error: {e}")
                    await asyncio.sleep(60)
                    
        except Exception as e:
            self.logger.error(f"❌ Statistics logging loop failed: {e}")
    
    def signal_handler(self, signum, frame):
        """Handle interrupt signals"""
        self.logger.info(f"🛑 Received signal {signum}, stopping agent...")
        asyncio.create_task(self.stop())

async def main():
    """Main function to run the agent"""
    # Setup logging first
    setup_logging()
    logger = logging.getLogger(__name__)
    logger.info("📝 Logging setup completed")
    
    # Create agent instance
    logger.info("🎯 Creating agent instance...")
    agent = EnhancedEDRAgent()
    
    # Set up signal handlers
    signal.signal(signal.SIGINT, agent.signal_handler)
    signal.signal(signal.SIGTERM, agent.signal_handler)
    logger.info("🔧 Signal handlers configured")
    
    try:
        # Initialize agent
        logger.info("🚀 Initializing agent...")
        await agent.initialize()
        
        # Start agent
        logger.info("▶️ Starting agent...")
        await agent.start()
        
        # Keep running until interrupted
        logger.info("🔄 Agent running - monitoring system activities...")
        while agent.is_running:
            await asyncio.sleep(1)
            
    except KeyboardInterrupt:
        logger.info("🛑 Received interrupt signal, stopping agent...")
    except Exception as e:
        logger.error(f"❌ Agent error: {e}", exc_info=True)
    finally:
        await agent.stop()

if __name__ == "__main__":
    try:
        print("🚀 Starting Enhanced EDR Agent...")
        print("=" * 60)
        
        # Run the agent
        asyncio.run(main())
        
    except KeyboardInterrupt:
        print("\n🛑 Agent stopped by user")
    except Exception as e:
        print(f"❌ Failed to run agent: {e}")
        print("=" * 60)
        print("🔧 Troubleshooting:")
        print("1. Make sure all dependencies are installed: pip install -r requirements.txt")
        print("2. Check if Python path is correct")
        print("3. Verify agent files are not corrupted")
        print("4. Run with 'python main.py' from the agent directory")
        print("5. Check Windows Event Viewer for system errors")
        print("=" * 60)
        input("Press Enter to exit...")