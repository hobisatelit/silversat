# silversat
python script to decode SSDV image from SilverSat cube sat (IL2P protocol). Work flawless with audio recording or audio stream, like from satnogs observation, SDR , local WAV/OGG file, etc. Auto detect image id, sender and frame id. automatic convert .bin into jpeg image.

```
./silver.py -h
usage: silver.py [-h] [--host HOST] [--port PORT] [-v]

Dire Wolf KISS TCP → SSDV (195 bytes after IL2P) → sorted .bin files

options:
  -h, --help     show this help message and exit
  --host HOST    Dire Wolf host
  --port PORT    Dire Wolf KISS TCP port
  -v, --verbose  Print hex of each received SSDV candidate + parsing details
```

## requirements
latest direwolf - https://github.com/wb2osz/direwolf/

ssdv - https://github.com/fsphil/ssdv

## how to run?

```
git clone https://github.com/hobisatelit/silversat.git

cd silversat

chmod 755 silver.py
```

Open three terminal

on **first terminal** run Direwolf KISS server

``direwolf -c direwolf.conf``

on **second terminal** run

``./silver.py``

on **third terminal** run
```
sudo apt install pavucontrol
pavucontrol
```

look at Recording tab, you will see direwolf app there, please change capture to MONITOR mode.

and the last step is
**play the audio, for example from satnogs observation**

example: 
https://network.satnogs.org/observations/13203004/


**click video below to see how it work:**


[![Watch the video](https://community.libre.space/uploads/default/original/2X/6/6d9f4a8bac89f307586580bef9c10266ff8a0d2a.jpeg)](https://community.libre.space/uploads/default/original/2X/0/0b4a32b5b2ada28dba0adb2529923f2bc5090fe1.mp4)
