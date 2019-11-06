rem Open TCP Port 12986 inbound and outbound
netsh advfirewall firewall add rule name="NSPV TCP Port 12986" dir=in action=allow protocol=TCP localport=12986
netsh advfirewall firewall add rule name="NSPV TCP Port 12986" dir=out action=allow protocol=TCP localport=12986
start "" nspv.exe %CHAIN%
timeout 6
start "" /B /wait python.exe -m pytest rpctest\test_nspv.py -s
