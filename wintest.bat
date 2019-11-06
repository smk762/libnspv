start "" nspv.exe %CHAIN%
start "" /WAIT python.exe -m pytest rpctest\test_nspv.py
