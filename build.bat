@echo off
echo ========================================================
echo       BUILDING SECURITY MONITOR v3.0 STANDALONE
echo ========================================================
echo.
echo Installing requirements (just in case)...
pip install -r requirements.txt
echo.
echo Compiling Python code to standalone EXE...
echo - Using --onefile to pack everything into a single EXE
echo - Using --noconsole to hide the terminal window
echo - Using --uac-admin to request Administrator privileges automatically
echo.

pyinstaller --noconfirm --onefile --noconsole --uac-admin --name SecurityMonitor main.py

echo.
echo ========================================================
echo BUILD COMPLETE!
echo You can find your standalone app at: dist\SecurityMonitor.exe
echo ========================================================
pause
