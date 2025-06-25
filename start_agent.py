#!/usr/bin/env python3
"""
Start EDR Agent - Simple script to start the agent manually
"""

import asyncio
import logging
import sys
import time
from pathlib import Path

# Add the agent directory to Python path
current_dir = Path(__file__).parent.absolute()
agent_dir = current_dir / 'agent'
if str(agent_dir) not in sys.path:
    sys.path.insert(0, str(agent_dir))

def setup_logging():
    """Setup logging for the agent"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout)
        ]
    )

async def start_agent():
    """Start the EDR agent"""
    logger = logging.getLogger(__name__)
    logger.info("🚀 Starting EDR Agent...")
    
    try:
        # Import the agent
        from main import EnhancedEDRAgent
        
        # Create agent instance
        agent = EnhancedEDRAgent()
        
        # Initialize agent
        logger.info("🔄 Initializing agent...")
        await agent.initialize()
        
        # Start agent
        logger.info("🔄 Starting agent...")
        await agent.start()
        
        logger.info("✅ Agent started successfully!")
        logger.info("📱 Monitoring: Process, Network, System, File, Registry, Authentication")
        logger.info("🔔 Process events should now appear in the logs")
        logger.info("=" * 60)
        
        # Keep the agent running
        try:
            while True:
                await asyncio.sleep(10)
                logger.info("🔄 Agent running - monitoring system activities...")
        except KeyboardInterrupt:
            logger.info("🛑 Stopping agent...")
        
        # Stop agent
        await agent.stop()
        logger.info("✅ Agent stopped")
        
    except Exception as e:
        logger.error(f"❌ Failed to start agent: {e}")
        import traceback
        logger.error(f"🔍 Full error details:\n{traceback.format_exc()}")
        return False
    
    return True

async def main():
    """Main function"""
    setup_logging()
    logger = logging.getLogger(__name__)
    
    logger.info("🚀 EDR Agent Starter")
    logger.info("=" * 50)
    
    success = await start_agent()
    
    if success:
        logger.info("✅ Agent completed successfully")
    else:
        logger.error("❌ Agent failed to start")
        sys.exit(1)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n🛑 Agent stopped by user")
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        sys.exit(1) 