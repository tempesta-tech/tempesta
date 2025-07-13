# SystemCheck

The script checks the minimum hardware requirements, verifies the operating system configuration, activates NetConsole,
and sends logs about the collected configuration.

# Requirements
 - Python >= 3.10

# How to
```bash
./system_verification.py --help
./system_verification.py --netconsole-host=192.168.0.100 --netconsole-network-interface=eth0 --troubleshooting-mac=00:00:00:00:00:00
```

# Options
| name                           | short | description                                                             |
|--------------------------------|-------|-------------------------------------------------------------------------|
| --troubleshooting-host         | -th | Tempesta Troubeshooting Server host, example (192.168.0.101)            | 
| --troubleshooting-port         | -tp | Tempesta Troubeshooting Server port, example (5555)                     |
| --troubleshooting-mac          | -tm | Tempesta Troubeshooting Server Mac Address, example (aa:bb:cc:dd:ee:ff) |
| --netconsole-host              | -nh | Netconsole host, example (192.168.0.100)                                |
| --netconsole-port              | -np | Netconsole port, example (5555)                                         |
| --netconsole-network-interface | -nni | Netconsole network interface, example (eth0)                            |

