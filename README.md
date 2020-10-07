# HandShakePacket Falsifier

A script to falsify the hostname and the port data in the Minecraft HandShake packet

It works like a tcp connection forwarder

First, it will try to detect the potential HandShake packet during the connection. Once detected, it will use custom address to replace the original address in the packet. After that, it will close the detection part and just works as a normal connection forwarder

## Usage

Fill the config file, and then use `python HandShakePacketFalsifier.py` to start. Python3 is needed

Config file (config.json):

```json
{
	"listen": {
		"hostname": "127.0.0.1",
		"port": 10000
	},
	"target": {
		"hostname": "my.mc.server",
		"port": 20000
	},
	"fake": {
		"hostname": "fake.server.address",
		"port": 25565
	}
}
```

`listen` is the address the script will blind and listen for connection. Let Minecraft clients connect to this address

`target` is the address of the destination server

`fake` is the address you want to customize inside the HandShake packet

For the example config file, client will connects to `127.0.0.1:10000`, and the script will forward the connection to `my.mc.server:20000`, and the address inside the HandShake packet will be modified to `fake.server.address:25565`
