@echo off
REM Builds dist\ISPView.exe (single file, asks for Administrator on launch)
pip install -r requirements.txt pyinstaller || exit /b 1
python -m PyInstaller --noconfirm --onefile --windowed --uac-admin --name ISPView ^
  --exclude-module numpy --exclude-module pandas --exclude-module matplotlib ^
  --exclude-module scipy --exclude-module PIL --exclude-module IPython ^
  isp_view.py
echo.
echo Done: dist\ISPView.exe
