# main.py - EDR Windows Agent Main Entry Point (PRODUCTION READY)
"""
EDR Security Agent for Windows
Complete Windows endpoint security monitoring agent compatible with EDR Server
Features: Process monitoring, File system monitoring, Network monitoring, Registry monitoring
"""

import sys
import os
import asyncio
import logging
import signal
import time
import ctypes
from pathlib import Path
from typing import Optional

# Add agent directory to path
agent_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(agent_dir))

from agent.core.agent_manager import AgentManager
from agent.core.config_manager import ConfigManager
from agent.utils.logging_utils import setup_logging

class EDRAgent:
    """Main EDR Agent class for Windows"""
    
    def __init__(self):
        self.agent_manager: Optional[AgentManager] = None
        self.config_manager: Optional[ConfigManager] = None
        self.logger = None
        self.shutdown_event = asyncio.Event()
        self.is_running = False
        
    async def initialize(self):
        """Initialize agent components"""
        try:
            # Setup logging first
            self.logger = setup_logging()
            self.logger.info("🛡️ EDR Windows Agent starting...")
            
            # Initialize configuration
            self.config_manager = ConfigManager()
            await self.config_manager.load_config()
            self.logger.info("✅ Configuration loaded")
            
            # Initialize agent manager
            self.agent_manager = AgentManager(self.config_manager)
            await self.agent_manager.initialize()
            self.logger.info("✅ Agent manager initialized")
            
            # Setup signal handlers
            self._setup_signal_handlers()
            
            self.logger.info("✅ EDR Windows Agent initialized successfully")
            return True
            
        except Exception as e:
            if self.logger:
                self.logger.error(f"❌ Agent initialization failed: {e}")
            else:
                print(f"❌ Agent initialization failed: {e}")
            return False
    
    async def start(self):
        """Start the agent"""
        try:
            if not self.agent_manager:
                raise Exception("Agent not initialized")
            
            self.is_running = True
            self.logger.info("🚀 Starting EDR Windows Agent...")
            
            # Start agent manager
            await self.agent_manager.start()
            self.logger.info("✅ EDR Windows Agent started successfully")
            
            # Print status
            self._print_agent_status()
            
            # Main event loop
            await self._main_loop()
            
        except Exception as e:
            self.logger.error(f"❌ Agent start failed: {e}")
            raise
    
    async def _main_loop(self):
        """Main agent event loop"""
        self.logger.info("🔄 Agent main loop started")
        
        try:
            while self.is_running and not self.shutdown_event.is_set():
                # Check agent health
                if self.agent_manager:
                    await self.agent_manager.health_check()
                
                # Wait for shutdown signal or interval
                try:
                    await asyncio.wait_for(
                        self.shutdown_event.wait(), 
                        timeout=30.0  # 30 second check interval
                    )
                    break  # Shutdown signal received
                except asyncio.TimeoutError:
                    continue  # Normal timeout, continue loop
                    
        except Exception as e:
            self.logger.error(f"❌ Main loop error: {e}")
        finally:
            self.logger.info("🔄 Main loop stopped")
    
    async def stop(self):
        """Stop the agent gracefully"""
        if hasattr(self, 'logger') and self.logger:
            self.logger.info("🛑 Stopping EDR Windows Agent...")
        self.is_running = False
        self.shutdown_event.set()
        
        if self.agent_manager:
            await self.agent_manager.stop()
        
        if hasattr(self, 'logger') and self.logger:
            self.logger.info("✅ EDR Windows Agent stopped")
    
    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        def signal_handler(signum, frame):
            self.logger.info(f"📡 Received signal {signum}")
            asyncio.create_task(self.stop())
        
        try:
            signal.signal(signal.SIGINT, signal_handler)
            signal.signal(signal.SIGTERM, signal_handler)
        except Exception as e:
            self.logger.warning(f"⚠️ Signal handler setup failed: {e}")
    
    def _print_agent_status(self):
        """Print agent status information"""
        try:
            config = self.config_manager.get_config()
            server_config = config.get('server', {})
            agent_config = config.get('agent', {})
            
            print(f"""
════════════════════════════════════════════════════════════════
🛡️  EDR WINDOWS AGENT - {agent_config.get('version', '1.0.0')}
════════════════════════════════════════════════════════════════
📊 Status: RUNNING
🌐 Server: {server_config.get('host', 'localhost')}:{server_config.get('port', 5000)}
💓 Heartbeat: {agent_config.get('heartbeat_interval', 30)}s
📦 Batch Size: {agent_config.get('event_batch_size', 100)} events
🔧 Monitoring: {'✅ ENABLED' if config.get('collection', {}).get('enabled', True) else '❌ DISABLED'}

📡 Collectors Active:
   • Process Monitor: {'✅' if config.get('collection', {}).get('collect_processes', True) else '❌'}
   • File Monitor: {'✅' if config.get('collection', {}).get('collect_files', True) else '❌'}
   • Network Monitor: {'✅' if config.get('collection', {}).get('collect_network', True) else '❌'}
   • Registry Monitor: {'✅' if config.get('collection', {}).get('collect_registry', True) else '❌'}
   • Authentication Monitor: {'✅' if config.get('collection', {}).get('collect_authentication', True) else '❌'}

🔐 Security: {'✅ ACTIVE' if config.get('security', {}).get('anti_tamper_enabled', True) else '❌ DISABLED'}
════════════════════════════════════════════════════════════════
Press Ctrl+C to stop the agent
""")
            
        except Exception as e:
            self.logger.error(f"❌ Status print failed: {e}")

def is_admin():
    """Check if running with administrator privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def check_python_version():
    """Check Python version compatibility"""
    if sys.version_info < (3, 8):
        print("❌ Python 3.8 or higher is required")
        print(f"   Current version: {sys.version}")
        return False
    return True

def check_windows_version():
    """Check Windows version compatibility"""
    try:
        import platform
        version = platform.release()
        if version in ['7', '8', '8.1', '10', '11']:
            return True
        else:
            print(f"⚠️ Untested Windows version: {version}")
            return True
    except:
        return True

async def main():
    """Main entry point"""
    # Set console title
    try:
        os.system('title EDR Windows Security Agent')
    except:
        pass
    
    # Check prerequisites
    if not check_python_version():
        sys.exit(1)
    
    if not check_windows_version():
        print("⚠️ Continuing on unsupported Windows version...")
    
    # Check administrator privileges
    if not is_admin():
        print("⚠️ Administrator privileges recommended for full functionality")
        print("   Some monitoring features may be limited")
        
        # Provide better guidance
        print("\n💡 To run with administrator privileges:")
        print("1. Use the admin script: python run_as_admin.py")
        print("2. Or manually: Right-click PowerShell → 'Run as administrator'")
        print("3. Then run: python main.py")
        print()
        
        # Ask user if they want to continue
        try:
            response = input("Continue with limited privileges? (y/N): ").strip().lower()
            if response not in ['y', 'yes']:
                print("🛑 Exiting...")
                sys.exit(0)
        except KeyboardInterrupt:
            print("\n🛑 Exiting...")
            sys.exit(0)
        
        print("   Continuing with limited privileges...")
        time.sleep(2)
    
    # Create and run agent
    agent = EDRAgent()
    
    try:
        # Initialize agent
        if not await agent.initialize():
            print("❌ Agent initialization failed")
            sys.exit(1)
        
        # Start agent
        await agent.start()
        
    except KeyboardInterrupt:
        print("\n🛑 Shutdown requested by user")
    except Exception as e:
        print(f"❌ Agent failed: {e}")
        if hasattr(agent, 'logger') and agent.logger:
            agent.logger.error(f"💥 Critical failure: {e}")
        sys.exit(1)
    finally:
        try:
            await agent.stop()
        except:
            pass
        print("👋 EDR Windows Agent stopped")

if __name__ == "__main__":
    # Handle Windows event loop policy
    if sys.platform.startswith('win'):
        try:
            # Use ProactorEventLoop for better Windows compatibility
            asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
        except:
            pass
    
    # Run agent
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n🛑 Agent interrupted")
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1)