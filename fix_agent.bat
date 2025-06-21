@echo off
chcp 65001 >nul
echo 🚀 EDR Windows Agent - Fix Script
echo ====================================
echo.

echo 📋 Running comprehensive fix script...
python fix_all.py

echo.
echo 🎯 Fix script completed!
echo.
echo 💡 Next steps:
echo    1. If all tests passed, run: python main.py
echo    2. If some tests failed, check the output above
echo    3. For administrator privileges, right-click PowerShell and "Run as administrator"
echo.
pause 