import os
import time

index = 0
# rule = '"tcp.stream eq ' + str(index) + '"'
# srcPath = "C:\\test.pcap"
# dstPath = "C:\\test\\" + str(index) + ".pcap"
# cmd = "tshark -2 -R " + rule + " -r " + srcPath + " -w " + dstPath
# print(cmd)
# os.system(cmd)
st = time.time()
while True:
    rule = '"tcp.stream eq ' + str(index) + '"'
    srcPath = "D:\\Graduation\\Datas\\CICIDS2017\\PCAP\\Friday\\Friday.pcap"
    dstPath = "D:\\test\\" + str(index) + ".pcap"
    cmd = "tshark -2 -R " + rule + " -r " + srcPath + " -w " + dstPath
    print(cmd)
    os.system(cmd)
    index += 1
    if index > 10:
        break
et = time.time()
print(et - st, "\n")
