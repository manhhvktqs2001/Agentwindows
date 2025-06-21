#!/usr/bin/env python3
"""
Run as Administrator Script
Properly restarts the EDR Windows Agent with administrator privileges
"""

import os
import sys
import subprocess
import ctypes
import platform
from pathlib import Path

def is_admin():
    """Check if running with administrator privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    """Restart the script with administrator privileges"""
    try:
        if platform.system().lower() != 'windows':
            print("⚠️ This script is designed for Windows systems")
            return False
            
        if is_admin():
            print("✅ Already running with administrator privileges")
            return True
            
        # Get the current script path
        script_path = os.path.abspath(__file__)
        main_script = os.path.join(os.path.dirname(script_path), 'main.py')
        
        if not os.path.exists(main_script):
            print(f"❌ Main script not found: {main_script}")
            return False
        
        print("🔄 Restarting with administrator privileges...")
        
        # Use ShellExecute to run with admin privileges
        result = ctypes.windll.shell32.ShellExecuteW(
            None, 
            "runas", 
            sys.executable, 
            f'"{main_script}"', 
            None, 
            1
        )
        
        if result > 32:
            print("✅ Administrator privileges requested successfully")
            return True
        else:
            print(f"❌ Failed to get administrator privileges (Error: {result})")
            return False
            
    except Exception as e:
        print(f"❌ Error requesting administrator privileges: {e}")
        return False

def create_admin_batch():
    """Create a batch file to run as administrator"""
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        batch_path = os.path.join(current_dir, 'run_agent_admin.bat')
        main_script = os.path.join(current_dir, 'main.py')
        
        batch_content = f'''@echo off
chcp 65001 >nul
echo 🛡️ EDR Windows Agent - Administrator Mode
echo ===========================================
echo.

echo 🔍 Checking administrator privileges...
net session >nul 2>&1
if %errorLevel% == 0 (
    echo ✅ Running with administrator privileges
) else (
    echo ❌ Not running with administrator privileges
    echo 🔄 Requesting administrator privileges...
    powershell -Command "Start-Process cmd -ArgumentList '/c cd /d \"{current_dir}\" && python \"{main_script}\"' -Verb RunAs"
    exit /b
)

echo.
echo 🚀 Starting EDR Windows Agent...
python "{main_script}"

echo.
echo 👋 Agent stopped
pause
'''
        
        with open(batch_path, 'w', encoding='utf-8') as f:
            f.write(batch_content)
        
        print(f"✅ Created admin batch file: {batch_path}")
        return batch_path
        
    except Exception as e:
        print(f"❌ Failed to create batch file: {e}")
        return None

def create_powershell_script():
    """Create a PowerShell script to run as administrator"""
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        ps_path = os.path.join(current_dir, 'run_agent_admin.ps1')
        main_script = os.path.join(current_dir, 'main.py')
        
        ps_content = f'''# EDR Windows Agent - Administrator PowerShell Script
Write-Host "🛡️ EDR Windows Agent - Administrator Mode" -ForegroundColor Green
Write-Host "===========================================" -ForegroundColor Green
Write-Host ""

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

if ($isAdmin) {{
    Write-Host "✅ Running with administrator privileges" -ForegroundColor Green
    Write-Host ""
    Write-Host "🚀 Starting EDR Windows Agent..." -ForegroundColor Yellow
    
    # Change to agent directory
    Set-Location "{current_dir}"
    
    # Run the agent
    python "{main_script}"
}} else {{
    Write-Host "❌ Not running with administrator privileges" -ForegroundColor Red
    Write-Host "🔄 Requesting administrator privileges..." -ForegroundColor Yellow
    
    # Restart with admin privileges
    Start-Process powershell -ArgumentList "-File `"$PSCommandPath`"" -Verb RunAs
}}

Write-Host ""
Write-Host "👋 Agent stopped" -ForegroundColor Cyan
Read-Host "Press Enter to exit"
'''
        
        with open(ps_path, 'w', encoding='utf-8') as f:
            f.write(ps_content)
        
        print(f"✅ Created PowerShell script: {ps_path}")
        return ps_path
        
    except Exception as e:
        print(f"❌ Failed to create PowerShell script: {e}")
        return None

def main():
    """Main function"""
    print("🛡️ EDR Windows Agent - Administrator Privileges Helper")
    print("=" * 55)
    
    if platform.system().lower() != 'windows':
        print("⚠️ This script is designed for Windows systems")
        print("On other platforms, run: python main.py")
        return
    
    print("🔍 Checking current privileges...")
    
    if is_admin():
        print("✅ Already running with administrator privileges")
        print("🚀 Starting agent directly...")
        
        # Run the main agent
        main_script = os.path.join(os.path.dirname(__file__), 'main.py')
        if os.path.exists(main_script):
            os.system(f'python "{main_script}"')
        else:
            print(f"❌ Main script not found: {main_script}")
    else:
        print("❌ Not running with administrator privileges")
        print("")
        print("💡 Choose an option:")
        print("1. Create and run batch file (recommended)")
        print("2. Create and run PowerShell script")
        print("3. Try direct elevation")
        print("4. Manual instructions")
        print("")
        
        choice = input("Enter your choice (1-4): ").strip()
        
        if choice == "1":
            batch_path = create_admin_batch()
            if batch_path:
                print(f"🔄 Running batch file: {batch_path}")
                os.system(f'"{batch_path}"')
        
        elif choice == "2":
            ps_path = create_powershell_script()
            if ps_path:
                print(f"🔄 Running PowerShell script: {ps_path}")
                os.system(f'powershell -ExecutionPolicy Bypass -File "{ps_path}"')
        
        elif choice == "3":
            if run_as_admin():
                print("✅ Administrator privileges obtained")
            else:
                print("❌ Failed to get administrator privileges")
                print("💡 Try option 1 or 2 instead")
        
        elif choice == "4":
            print_manual_instructions()
        
        else:
            print("❌ Invalid choice")
            print_manual_instructions()

def print_manual_instructions():
    """Print manual instructions for running as administrator"""
    print("\n📋 Manual Instructions:")
    print("=" * 30)
    print("1. Right-click on PowerShell or Command Prompt")
    print("2. Select 'Run as administrator'")
    print("3. Navigate to agent directory:")
    print(f"   cd {os.path.dirname(os.path.abspath(__file__))}")
    print("4. Run the agent:")
    print("   python main.py")
    print("")
    print("💡 Alternative methods:")
    print("- Double-click run_agent_admin.bat (if created)")
    print("- Right-click run_agent_admin.ps1 and 'Run as administrator'")
    print("- Use Windows Task Scheduler to run with admin privileges")

if __name__ == "__main__":
    main() 