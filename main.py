import os
import time
import shutil
from datetime import datetime

import config
from PacketReader import PacketReader
from FlowGenerator import FlowGenerator, OutputInfo
from AttackInfo import AttackInfo
from Clean import clean


def process(pcapFile, outputInfo, attackIndex, attackFile=None):
    print("\nProcessing ", os.path.basename(pcapFile))

    # 判断是否有攻击信息
    if attackFile is not None:
        attackInfo = AttackInfo(attackIndex, attackFile)
    else:
        attackInfo = None

    # 初始化PCAP数据包读取类
    packetReader = PacketReader(pcapFile)

    # 初始化会话流重组类
    flowGenerator = FlowGenerator(
        config.flowTimeout,
        config.activityTimeout,
        config.tcpOutOfOrder,
        outputInfo,
        attackInfo,
    )

    # 读取第一个数据包
    [basicPacket, packetBytes] = packetReader.nextPacket()

    # 循环读取数据包,直到结束
    while basicPacket is not None:
        # 处理数据包,将其添加到相应会话流中
        flowGenerator.processPacket(basicPacket, packetBytes)
        # 读取下一个数据包
        [basicPacket, packetBytes] = packetReader.nextPacket()

    # 结束所有会话流
    flowGenerator.clearFlows()

    print("dump data to pcap")

    flowGenerator.dumpDataToPcap(packetReader.getPcapHeader(), pcapFile)


def processDir(pcapPath, outputInfo, attackFile):
    # 获取路径下的所有文件(夹)名称
    fileORdir = os.listdir(pcapPath)
    # 遍历所有文件
    for fd in fileORdir:
        path = os.path.join(pcapPath, fd)
        # 如果是文件夹
        if os.path.isdir(path):
            processDir(path, outputInfo, attackFile)
        # 如果是文件
        elif os.path.isfile(path):
            attackIndex = os.path.basename(pcapPath)
            process(path, outputInfo, attackIndex, attackFile)
        # 若都不是, 则报错
        else:
            print(config.PathError)


if __name__ == "__main__":
    # 记录开始时间
    st = time.time()
    # 打印时间
    print(datetime.now())

    # 获取参数
    args = config.parser.parse_args()

    # 如果结果输出文件夹存在则删除重建
    # if os.path.exists(args.rawDataPath) == True:
    #     print("Deleting Old Result...")
    #     shutil.rmtree(args.rawDataPath)
    # os.mkdir(args.rawDataPath)

    # 创建文件输出类
    outputInfo = OutputInfo(args.rawDataPath)

    # 如果是文件夹
    if os.path.isdir(args.pcapPath):
        processDir(args.pcapPath, outputInfo, args.attackFile)
    # 如果是文件
    elif os.path.isfile(args.pcapPath):
        attackIndex = os.path.basename(args.pcapPath)
        process(args.pcapPath, outputInfo, attackIndex, args.attackFile)
    # 若都不是, 则报错
    else:
        print(config.PathError)

    # 记录结束时间
    et = time.time()
    # 打印时间
    print(datetime.now())
    # 输出总耗时
    print(et - st, "\n")

    # 清洗数据
    clean(args)
    print(datetime.now())
