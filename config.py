import argparse

dataset = "CICIDS2017"

parser = argparse.ArgumentParser(description="Preprocess Data")

parser.add_argument(
    "--pcapPath",
    default="../Datas/" + dataset + "/PCAP/",
    help="path to pcap file or pcap dir",
)
parser.add_argument(
    "--rawDataPath",
    default="../Datas/" + dataset + "/raw data/",
    # default="../Datas/",
    help="path to raw data dir",
)
parser.add_argument(
    "--unusedDataPath",
    default="../Datas/" + dataset + "/unused data/",
    help="path to unused data dir",
)
parser.add_argument(
    "--attackFile",
    default="./AttackInfo.xml",
    # default=None,
    help="path to attackInfo file",
)


flowTimeout = 120000000
activityTimeout = 5000000
tcpOutOfOrder = 65535


PathError = "Error Code = 00, There is no Such File or Folder."
AttackInfoLack = "Error Code = 01, The Attack Information File is Missing."
PcapHeaderError = "Error Code = 02, This is not a Pcap File."
LinkLayerError = "Error Code = 03, The Ethernet Protocol is not used at the Link Layer."


if dataset == "CICIDS2017":
    CleanList = {
        "Benign": [980, 106556264],
        "SSH Brute Force": [866, 1000000],
        "DoS Slowloris": [654, 1000000],
        "DoS Slowhttptest": [1548, 1000000],
        "DoS Hulk": [2758, 1000000],
        "DoS GoldenEye": [654, 1000000],
        "Web Attack Brute Force": [1826, 1000000],
        "Web Attack XSS": [614, 1000000],
        "Infiltration": [1402, 100000000],
        "Port Scan": [0, 4797],
    }
elif dataset == "CICIDS2018":
    CleanList = {
        "Benign": [1024, 100000000],
        "Botnet": [476, 1000000],
        "DoS Slowhttptest": [0, 0],
        "DoS Slowloris": [294, 1000000],
        "FTP Brute Force": [0, 0],
        "SSH Brute Force": [184, 1000000],
        "Web Attack Brute Force": [468, 1000000],
        "Web Attack Sql Injection": [468, 1000000],
        "Web Attack XSS": [468, 1000000],
    }
