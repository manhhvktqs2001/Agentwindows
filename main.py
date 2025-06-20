# main.py - EDR Agent Main Entry Point
"""
EDR Security Agent
Windows endpoint security monitoring agent
"""

import sys
import os
import asyncio
import logging
import signal
import time
from pathlib import Path
from typing import Optional

# Add agent directory to path
agent_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(agent_dir))

from agent.core.agent_manager import AgentManager
from agent.core.config_manager import ConfigManager
from agent.utils.logging_utils import setup_logging

class EDRAgent:
    """Main EDR Agent class"""
    
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
            self.logger.info("🛡️ EDR Agent starting...")
            
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
            
            self.logger.info("✅ EDR Agent initialized successfully")
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
            self.logger.info("🚀 Starting EDR Agent...")
            
            # Start agent manager
            await self.agent_manager.start()
            self.logger.info("✅ EDR Agent started successfully")
            
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
        self.logger.info("🛑 Stopping EDR Agent...")
        self.is_running = False
        self.shutdown_event.set()
        
        if self.agent_manager:
            await self.agent_manager.stop()
        
        self.logger.info("✅ EDR Agent stopped")
    
    def _setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        def signal_handler(signum, frame):
            self.logger.info(f"📡 Received signal {signum}")
            asyncio.create_task(self.stop())
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

async def main():
    """Main entry point"""
    agent = EDRAgent()
    
    try:
        # Initialize agent
        if not await agent.initialize():
            sys.exit(1)
        
        # Start agent
        await agent.start()
        
    except KeyboardInterrupt:
        print("\n🛑 Shutdown requested by user")
    except Exception as e:
        print(f"❌ Agent failed: {e}")
        sys.exit(1)
    finally:
        await agent.stop()

if __name__ == "__main__":
    # Set console title
    if sys.platform.startswith('win'):
        try:
            os.system('title EDR Security Agent')
        except:
            pass
    
    # Run agent
    asyncio.run(main())