#!/bin/bash

if [ ! -d /usr/share/wireshark/lua-dissectors ]
then
    sudo mkdir /usr/share/wireshark/lua-dissectors
fi

if [ ! -d /usr/share/wireshark/lua-dissectors/rime ]
then
    sudo mkdir /usr/share/wireshark/lua-dissectors/rime
fi

if [ ! -f /usr/share/wireshark/lua-dissectors/rime/rime-$1-$2.lua ]
then
    sudo cp -i lua-files/rime-$1-$2.lua /usr/share/wireshark/lua-dissectors/rime/
else
    sudo sed -i '$d' /usr/share/wireshark/init.lua
fi

cp -f /usr/share/wireshark/init.lua .
echo 'dofile("/usr/share/wireshark/lua-dissectors/rime/rime'-$1-$2.'lua")' >> init.lua
sudo cp -f init.lua /usr/share/wireshark/

wireshark

sudo rm /usr/share/wireshark/lua-dissectors/rime/rime-$1-$2.lua
sudo sed -i '$d' /usr/share/wireshark/init.lua




