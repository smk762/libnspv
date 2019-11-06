start "" nspv.exe %CHAIN%
start "" /B /wait python.exe -m pytest rpctest\test_nspv.py
