# pwnagotchya
Simple tool for fuzzing the pwnagotchi "friend" protocol

![It's Alive!](testfriend.png)

## Usage
* -i to specify interface in monitor mode
* -t to use a test file hardcoded to testfriend.json
* -d to get some debug info on screen

`sudo python3 pwnagotchya.py -i wlan1 -d -t`

## Requirements
Scapy. Python3.
I'm using an Alfa card on a RPi 4. Something you can put in monitor mode.

## TODO
Lots of todos in the code. I'll forget to list them here at some point.
- [x] working PoC
- [ ] polishing
