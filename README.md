# CNS-2022-HappyCryptoFriend

## Connect adb via wifi in WSL
1. Connect under the same wifi ( to prevent firewall )
2. In windows, connect to device and setup tcp connection `adb tcpip 5555`
3. Search IP address of device. (狀態資訊.)
4. In wsl, `adb connect IP:5555`

## Check Network State
+ `netstat -tupln`: list up the used port.
+ `adb`: Use `netstat -tupln | grep adb` to find adb efficiently. Default port is 5037.

## Virtual Env
+ Create: `python3 -m venv ./venv`
+ Activate: `source ./venv/bin/activate`

## PacketSniffer
+ This needs root permission but `scapy` is not under the default lib path of root.
+ The first 3 line is to add packages of venv when executed by root.
  ```python
  import sys
  sys.path.append('../venv/lib/python3.8/site-packages')
  print(sys.path)
  ```
