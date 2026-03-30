@echo off
:: ArCHie Analyzer — run as: archie [flags]
:: To use from anywhere, add this folder to your PATH:
::   setx PATH "%PATH%;C:\Automations Stuff\ArCHie_Analyzer"
python "%~dp0analyzer.py" %*
