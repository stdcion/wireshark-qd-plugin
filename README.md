## About

Lua plugin for Wireshark for parsing QD protocol.

## Requirements

Wireshark >= 3.6.2, <= 4.0.12 

## Installation

Copy files (qd_proto.lua and qd_proto folder) to Wireshark *Lua Plugins* folder.
Location *Lua Plugins* folder you can find out in Help->About Wireshark->Folders
(on macOS Wireshark->About Wireshark->Folders) Its may be *"Global Lua Plugin"*
or *"Personal Lua Plugin"* (the user's personal folder is preferred, because it
does not require administrator rights).

![About Wireshark](doc/img/wireshark_about.png?raw=true)

### Verifying the plugin

Start Wireshark, there should be no error messages related to any plugins, now
select (as before) Help, then About Wireshark, instead of clicking the Folders
Tab, select the Plugins Tab.

![Plugin](doc/img/wireshark_plugin.png?raw=true)

## Note

To reassemble of out-of-order TCP segments, the TCP protocol preference
“Reassemble out-of-order segments” (currently disabled by default). If this
setting is not enabled, QD packets may not be recognized in the event of errors
at the TCP layer. You can enable this setting in
Edit->Preferences->Protocols->TCP.

![Reassemble TCP](doc/img/wireshark_reassemble_tcp.png?raw=true)

## How to use

Press right button on the packet and select "Decode As...". In the window that
opens, select value for TCP port and Current protocol QD, press OK.

![Decode As...](doc/img/wireshark_decode_as.png?raw=true)

The plugin has some settings that are available by pressing the right button on
packet. Warning, if you use "Decode As...", you cannot change "TCP port" or flag
"Enabled" in plugin settings, Wireshark will overwrite these changes (other
settings will be available), but this way to easier and fast then open
Edit->Preferences->Protocols->QD and set TCP-port.

![Plugins preference](doc/img/wireshark_plugin_settings.png?raw=true)
