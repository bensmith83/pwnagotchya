# -*- coding:utf-8 -*-

import argparse
import json
from scapy.all import *

TAG_LEN_MAX = 255

def main():
    # set command line options
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--iface", dest="iface", help="monitor mode wifi interface to broadcast on", default="en0")
    parser.add_argument("-t", "--test", dest="test", help="send test friend from testfriend.json", action='store_true')
    args = parser.parse_args()
    conf.iface = args.iface

    data_arr = []

    if args.test:
        path = './testfriend.json'
        with open(path) as json_file:
            data = json.load(json_file)
            sendLength = len(data)

            # break data into chunks each packet can handle
            if sendLength > TAG_LEN_MAX:
                chop = ChopData(data, TAG_LEN_MAX)
                for piece in chop:
                    data_arr.append(piece)
            else:
                data_arr.append(data)
            while 1:
                SendFriend(data_arr)

    else:
        while 1:
            time.sleep(1) #send one per second?

            data = FuzzPwnFriend(GLOBAL_VALID)
            sendLength = len(data)

            # break data into chunks each packet can handle

            if sendLength > TAG_LEN_MAX:
                chop = ChopData(data, TAG_LEN_MAX)
                for piece in chop:
                    data_arr.append(piece)
            else:
                data_arr.append(data)
            SendFriend(data_arr)

#TODO: move globals somewhere configurable
GLOBAL_VALID=True

def FuzzPwnFriend(valid):
    policy = {}
    policy.update({"advertise": FuzzAdvertise(GLOBAL_VALID)})
    policy.update({"ap_ttl": FuzzApTtl(GLOBAL_VALID)})
    policy.update({"associate": FuzzAssociate(GLOBAL_VALID)})
    policy.update({"bond_encounters_factor": FuzzBondEncountersFactor(GLOBAL_VALID)})
    policy.update({"bored_num_epochs": FuzzBoredNumEpochs(GLOBAL_VALID)})
    policy.update({"channels": FuzzChannels(GLOBAL_VALID)})
    policy.update({"deauth": FuzzDeauth(GLOBAL_VALID)})
    policy.update({"excited_num_epochs": FuzzExcitedNumEpochs(GLOBAL_VALID)})
    policy.update({"hop_recon_time": FuzzHopReconTime(GLOBAL_VALID)})
    policy.update({"max_inactive_scale": FuzzMaxInactiveScale(GLOBAL_VALID)})
    policy.update({"max_interactions": FuzzMaxInteractions(GLOBAL_VALID)})
    policy.update({"max_misses_for_recon": FuzzMaxMissesForRecon(GLOBAL_VALID)})
    policy.update({"min_recon_time": FuzzMinReconTime(GLOBAL_VALID)})
    policy.update({"min_rssi": FuzzMinReconTime(GLOBAL_VALID)})
    policy.update({"recon_inactive_multiplier": FuzzReconInactiveMultiplier(GLOBAL_VALID)})
    policy.update({"recon_time": FuzzReconTime(GLOBAL_VALID)})
    policy.update({"sad_num_epochs": FuzzSadNumEpochs(GLOBAL_VALID)})
    policy.update({"sta_ttl": FuzzStaTtl(GLOBAL_VALID)})
    friend_req = {}
    friend_req.update({"epoch": FuzzEpoch(GLOBAL_VALID)})
    friend_req.update({"face":FuzzFace(GLOBAL_VALID)})
    friend_req.update({"grid_version":FuzzGridVersion(GLOBAL_VALID)})
    friend_req.update({"identity":FuzzIdentity(GLOBAL_VALID)})
    friend_req.update({"name":FuzzName(GLOBAL_VALID)})
    friend_req.update({"policy":policy})
    friend_req.update({"pwnd_run":FuzzPwndRun(GLOBAL_VALID)})
    friend_req.update({"pwnd_tot":FuzzPwndTot(GLOBAL_VALID)})
    friend_req.update({"session_id":FuzzSessionId(GLOBAL_VALID)})
    friend_req.update({"timestamp":FuzzTimestamp(GLOBAL_VALID)})
    friend_req.update({"uptime":FuzzUptime(GLOBAL_VALID)})
    friend_req.update({"version":FuzzVersion(GLOBAL_VALID)})
    return json.dumps(friend_req)

#    IDWhisperPayload      layers.Dot11InformationElementID = 222
#    IDWhisperCompression  layers.Dot11InformationElementID = 223
#    IDWhisperIdentity     layers.Dot11InformationElementID = 224
#    IDWhisperSignature    layers.Dot11InformationElementID = 225
#    IDWhisperStreamHeader layers.Dot11InformationElementID = 226


def SendFriend(payload):
    #build packet
    frame=RadioTap()/\
        Dot11(addr1="ff:ff:ff:ff:ff:ff",addr2="de:ad:be:ef:de:ad",addr3="de:ad:be:ef:de:ad",)/\
        Dot11Beacon(cap="ESS")
    for piece in payload:
        frame = frame/\
        Dot11Elt(ID=222, info=piece)
    sendp(frame, verbose=1)

def ChopData(data, size):
    # chops a string into an array of size sized blocks
    return [data[i:i+size] for i in range(0, len(data), size)]


#TODO: move helper functions to a library

RAND_SHORT_STRING_LEN = 255
RAND_LONG_STRING_LEN = 1024

#TODO: some fuzz functions determine validity and some Get functions do.

def FuzzAdvertise(valid):
    #name
    #advertise
    #value
    #"true",
    if (valid):
        return True
    else:
        return GetRandBool()
        # or GetRandString(0,RAND_SHORT_STRING_LEN)

def FuzzApTtl(valid):
    #name
    #ap_ttl
    #value
    #420,
    if (valid):
        return GetRandInt(0,600)
    else:
        return GetRandInt(0,99999999)

def FuzzAssociate(valid):
    #name
    #associate
    #value
    #"true",
    if (valid):
        return True
    else:
        return GetRandBool()
        # or GetRandString(0,RAND_SHORT_STRING_LEN)

def FuzzBondEncountersFactor(valid):
    #name
    #bond_encounters_factor
    #value
    #20000,
    if (valid):
        return GetRandInt(10000,60000)
    else:
        return GetRandInt(0,99999999)

def FuzzBoredNumEpochs(valid):
    #name
    #bored_num_epochs
    #value
    #8,
    if (valid):
        return GetRandInt(0,100)
    else:
        return GetRandInt(0,99999999)

def FuzzChannels(valid):
    #name
    #channels
    #value
    #[1, 2, 3, 5, 8, 9, 10],
    if valid:
        return GetRandChannelSet(valid=True)
    else:
        return GetRandChannelSet(valid=False)

def FuzzDeauth(valid):
    #name
    #deauth
    #value
    #"true",
    if (valid):
        return True
    else:
        return GetRandBool()
        # or GetRandString(0,RAND_SHORT_STRING_LEN)

def FuzzExcitedNumEpochs(valid):
    #name
    #excited_num_epochs
    #value
    #25,
    if (valid):
        return GetRandInt(0,200)
    else:
        return GetRandInt(0,99999999)

def FuzzHopReconTime(valid):
    #name
    #hop_recon_time
    #value
    #26,
    if (valid):
        return GetRandInt(0,100)
    else:
        return GetRandInt(0,99999999)

def FuzzMaxInactiveScale(valid):
    #name
    #max_inactive_scale
    #value
    #10,
    if (valid):
        return GetRandInt(0,100)
    else:
        return GetRandInt(0,99999999)

def FuzzMaxInteractions(valid):
    #name
    #max_interactions
    #value
    #23,
    if (valid):
        return GetRandInt(0,100)
    else:
        return GetRandInt(0,99999999)

def FuzzMaxMissesForRecon(valid):
    #name
    #max_misses_for_recon
    #value
    #4,
    if (valid):
        return GetRandInt(0,100)
    else:
        return GetRandInt(0,99999999)

def FuzzMinReconTime(valid):
    #name
    #min_recon_time
    #value
    #21,
    if (valid):
        return GetRandInt(0,100)
    else:
        return GetRandInt(0,99999999)

def FuzzMinRssi(valid):
    #name
    #min_rssi
    #value
    #-68,
    if (valid):
        return GetRandInt(-200, 0)
    else:
        return GetRandInt(-99999999,99999999)

def FuzzReconInactiveMultiplier(valid):
    #name
    #recon_inactive_multiplier
    #value
    #1,
    if (valid):
        return GetRandInt(0,100)
    else:
        return GetRandInt(0,99999999)

def FuzzReconTime(valid):
    #name
    #recon_time
    #value
    #30,
    if (valid):
        return GetRandInt(0,100)
    else:
        return GetRandInt(0,99999999)

def FuzzSadNumEpochs(valid):
    #name
    #sad_num_epochs
    #value
    #22,
    if (valid):
        return GetRandInt(0,100)
    else:
        return GetRandInt(0,99999999)

def FuzzStaTtl(valid):
    #name
    #sta_ttl
    #value
    #163}
    if (valid):
        return GetRandInt(0,600)
    else:
        return GetRandInt(0,99999999)

def FuzzEpoch(valid):
    #name
    #epoch
    #value
    #4,
    if (valid):
        return GetRandInt(0,100)
    else:
        return GetRandInt(0,99999999)

def FuzzFace(valid):
    #name
    #face
    #value
    #"( â_â)",
    if valid:
        return GetRandFace()
    else:
        return GetRandString(0, RAND_SHORT_STRING_LEN)

def FuzzGridVersion(valid):
    #name
    #grid_version
    #value
    #"1.10.1",
    if valid:
        return GetRandVerString()
    else:
        return GetRandString(0, RAND_SHORT_STRING_LEN)

def FuzzIdentity(valid):
    #name
    #identity
    #value
    #"05c310097605f4587c2829748a683eb147453da121d4ae8910c884f108e18a0e",
    if valid:
        return GetRandString(64, 64)
    else:
        return GetRandString(4, RAND_LONG_STRING_LEN)

def FuzzName(valid):
    #name
    #name
    #value
    #"marko",
    if valid:
        return GetRandDictString(4, RAND_SHORT_STRING_LEN)
        #GetRandString(4, RAND_SHORT_STRING_LEN)
    else:
        return GetRandString(4, RAND_LONG_STRING_LEN)

def FuzzPwndRun(valid):
    #name
    #pwnd_run
    #value
    #3,
    if (valid):
        return GetRandInt(0,100)
    else:
        return GetRandInt(0,99999999)

def FuzzPwndTot(valid):
    #name
    #pwnd_tot
    #value
    #54,
    if (valid):
        return GetRandInt(0,1000)
    else:
        return GetRandInt(0,99999999)

def FuzzSessionId(valid):
    #name
    #session_id
    #value
    #"be:2f:20:07:d0:7a",
    if valid:
        return GetRandMACString()
    else:
        return GetRandString(0, RAND_SHORT_STRING_LEN)

def FuzzTimestamp(valid):
    #name
    #timestamp
    #value
    #1562850051,
    if valid:
        return GetTimestamp(valid=True)
    else:
        return GetTimestamp(valid=false)


def FuzzUptime(valid):
    #name
    #uptime
    #value
    #2606,
    if valid:
        return GetRandInt(0,10000)
    else:
        return GetRandInt(0,99999999)

def FuzzVersion(valid):
    #name
    #version
    #value
    #"1.1.1"
    if valid:
        return GetRandVerString()
    else:
        return GetRandString(0, RAND_SHORT_STRING_LEN)


import random

def GetRandBool():
    return random.choice(['true', 'false'])

def GetRandInt(low, high):
    return random.randint(low,high)

def GetRandChannelSet(valid=True):
    if valid:
        return [1, 2, 3, 5, 8, 9, 10]
    else:
        #TODO: generate random array
        return [1, 2, 3, 5, 8, 9, 10]

def GetRandFace():
    #TODO: get list of valid faces
    return "( â_â)"

def GetRandString(min, max):
    #TODO: generate random strings better
    return "A" * random.randint(min, max)

def GetRandVerString():
    #TODO: generate better random versions
    return random.choice(['1.1.1', '1.10.1'])

def GetRandDictString(min, max):
    #TODO: return better name list
    #TODO: munge names somehow
    return random.choice(['barry', 'sasha', 'vladimir', 'antonia', 'jackson', 'jada'])

def GetRandMACString():
    #TODO: use scapy func to generate random mac
    # or do something different
    return random.choice(['AA:BB:CC:DD:EE:FF', 'BB:CC:DD:EE:FF:AA', 'CC:DD:EE:FF:AA:BB'])

def GetTimestamp(valid):
    if valid:
        #TODO: return current epoch time
        return 1562850002
    else:
        #TODO: return random int OR random string
        return 1562850002


if __name__ == "__main__":
    main()
