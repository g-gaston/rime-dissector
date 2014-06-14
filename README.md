rime-dissector
==============

Wireshark dissector for Rime protocol

How to Use
==========

Run the script indicating the RDC and the rime layer.
It will run wireshark with the selected dissector loaded.
Sudo password is needed

Rdc supported: NullRDC (nullrdc), ContikiMAC (cmac)
Rime layers supported: abc, ibc, uc, ruc

Example for reliable unicast under ContikiMAC
    `./wireshark-rime.bash cmac ruc`
