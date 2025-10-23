@echo off
REM KerberosScanner - Script de compilation
REM Ayi NEDJIMI Consultants - https://www.ayinedjimi-consultants.fr

echo Compilation de KerberosScanner...
cl /EHsc /nologo /W4 /MD /O2 /DUNICODE /D_UNICODE KerberosScanner.cpp /link wevtapi.lib comctl32.lib user32.lib gdi32.lib shell32.lib comdlg32.lib

if errorlevel 1 (
    echo Erreur de compilation!
    pause
    exit /b 1
)

echo Compilation reussie: KerberosScanner.exe
pause
