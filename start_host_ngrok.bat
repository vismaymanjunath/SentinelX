@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0start_host_ngrok.ps1" %*
