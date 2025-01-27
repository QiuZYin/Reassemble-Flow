import os
from datetime import datetime

from BasicPacketInfo import BasicPacketInfo
from BasicFlow import BasicFlow
from AttackInfo import AttackInfo


class OutputInfo:
    def __init__(self, outputPath):
        self.info = {}
        self.outputPath = outputPath

    def check(self, label):
        if label not in self.info:
            newpath = label + str(0)
            self.info[label] = [0, 0, newpath]
            os.mkdir(self.outputPath + newpath)

    def getPath(self, label):
        self.info[label][1] += 1
        if self.info[label][1] > 200000:
            self.info[label][0] += 1
            self.info[label][1] = 1
            newPath = label + str(self.info[label][0])
            self.info[label][2] = newPath
            os.mkdir(self.outputPath + newPath)

        return self.info[label][2]


class FlowGenerator:
    """重组会话流"""

    def __init__(
        self,
        flowTimeout: int,
        activityTimeout: int,
        tcpOutOfOrder: int,
        outputInfo: OutputInfo,
        attackInfo: AttackInfo,
    ):
        """
        初始化流重组器

        Parameters
        ----------
        None

        Returns
        -------
        None

        """
        # 当前正在重组的会话流
        self.currentFlows: dict[str, BasicFlow] = {}
        # 已经重组好的会话流
        self.finishedFlows: list[BasicFlow] = []
        # 流超时
        self.flowTimeout = flowTimeout
        # 活动超时
        self.activityTimeout = activityTimeout
        # TCP序列号失序阈值
        self.tcpOutOfOrder = tcpOutOfOrder
        # 输出信息
        self.outputInfo = outputInfo
        # 攻击标注信息
        self.attackInfo = attackInfo

    def processPacket(self, packet: BasicPacketInfo, packetBytes: bytes):
        """
        首先根据五元组信息查找是否有相应的会话流
        若有则判断该数据包是否属于该会话流,属于则加入
        不属于则将已有的会话流结束,并使用该数据包开启一个新流
        若没有则使用该数据包开启一个新流

        Parameters
        ----------
        packet : BasicPacketInfo
            基本数据包信息

        packetBytes : bytes
            pacpPacket数据包字节流

        Returns
        -------
        None

        """

        # 数据包正向流ID
        pktFwdFlowId = packet.getFwdFlowId()
        # 数据包反向流ID
        pktBwdFlowId = packet.getBwdFlowId()
        # 当前流ID
        flowID = None

        # 判断流ID在当前重组流字典中,若存在则获取对应流和流ID
        if pktFwdFlowId in self.currentFlows:
            flowID = pktFwdFlowId
        elif pktBwdFlowId in self.currentFlows:
            flowID = pktBwdFlowId

        # 若都不在重组流字典中
        if flowID is None:
            # 则新建会话流
            flow = BasicFlow(packet=packet, packetBytes=packetBytes)
            self.currentFlows[pktFwdFlowId] = flow
        else:
            # 获取相应的流
            flow = self.currentFlows[flowID]

            # 判断该数据包是否属于该会话流, 以及是否需要更新Seq和Ack
            [same, flag] = self.isSameFlow(packet, flow)

            if same:
                # 若属于,则将该数据包加入到该会话流中
                flow.addPacket(packet=packet, flag=flag, packetBytes=packetBytes)
            else:  # 否则结束该会话流
                # 将其加入到已完成流列表中
                self.finishedFlows.append(flow)
                # 将流ID从重组流字典中删除
                self.currentFlows.pop(flowID)
                # 使用该数据包新建一个会话流
                flow = BasicFlow(packet=packet, packetBytes=packetBytes)
                self.currentFlows[pktFwdFlowId] = flow

    def clearFlows(self):
        """
        当前已经处理完所有数据包,将重组流字典中
        剩余的所有会话流加入到已完成流列表中

        Parameters
        ----------
        None

        Returns
        -------
        None

        """
        # 遍历所有剩余的会话流
        for flow in self.currentFlows.values():
            # 加入到已完成流列表中
            self.finishedFlows.append(flow)
        # 清空字典
        self.currentFlows.clear()

    def isSameFlow(self, packet: BasicPacketInfo, flow: BasicFlow):
        """
        对于UDP包, 根据数据包间隔时间进行判断是否属于同一流
        对于TCP包, 根据 序列号,确认号,数据包间隔时间,SYN标志 这四个信息
        判断数据包是否属于该会话流, 以及是否需要更新流的序列号和确认号

        Parameters
        ----------
        packet : BasicPacketInfo
            基本数据包信息

        flow : BasicFlow
            基本会话流

        Returns
        -------
        same : bool
            数据包是否属于该会话流

        flag : bool
            是否需要更新流的序列号和确认号

        """
        # same表示数据包是否属于该会话流
        same = False
        # flag表示是否需要更新流的序列号和确认号
        flag = False

        # 数据包时间戳
        pktTS = packet.getTimeStamp()
        # 该会话流最后一个数据包的时间戳
        flowTS = flow.getFlowEndTime()

        # 如果是UDP
        if packet.getProtocol() == 17:
            # 根据数据包间隔时间进行判断是否属于同一流
            if pktTS - flowTS < self.flowTimeout:
                same = True
        else:  # 否则为TCP
            # 数据包序列号
            pktSeq = packet.getSeq()
            # 数据包确认号
            pktAck = packet.getAck()
            # 数据包是否含有SYN标志
            pktSYN = packet.hasFlagSYN()

            # 若是正向数据包
            if packet.getSrcIP() == flow.getSrcIP():
                # 流当前方向数据包的序列号
                flowCurSeq = flow.getFwdSeq()
                # 流另一方向数据包的确认号
                flowOppAck = flow.getBwdAck()
                # 流当前方向下一个数据包的序列号
                flowCurNxtSeq = flow.getFwdNxtSeq()
                # 流另一方向下一个数据包的序列号
                flowOppNxtSeq = flow.getBwdNxtSeq()
            else:  # 否则是反向数据包(获取方式和上面类似,只不过方向不同)
                flowCurSeq = flow.getBwdSeq()
                flowOppAck = flow.getFwdAck()
                flowCurNxtSeq = flow.getBwdNxtSeq()
                flowOppNxtSeq = flow.getFwdNxtSeq()

            if pktSYN == True:
                # 若当前方向的Seq为-1,则表明这是该方向的第一个数据包
                if flowCurSeq == -1 or flowCurSeq == pktSeq:
                    # 以上四种属于最理想的情况,需要更新Seq和Ack
                    same = True
                    flag = True
            else:
                if (
                    # 若当前方向的Seq为-1,则表明这是该方向的第一个数据包
                    flowCurSeq == -1
                    # 数据包Seq == 流对向数据包Ack (即当前数据包的Seq是对方所期望的)
                    or pktSeq == flowOppAck
                    # 数据包Seq == 流当前方向下一个数据包Seq(未收到该数据包时)
                    # (即 当前方向连续发送多个数据包,此时对向Ack尚未更新,会出现对应不上的情况,
                    # 因此只能根据每个数据包的负载长度,维护当前方向Seq)
                    or pktSeq == flowCurNxtSeq
                    # 数据包Ack == 流另一方向下一个数据包Seq
                    # 如出现数据包重传或者数据包达到顺序与发送顺序不一致等情况时,
                    # 上面两个等式可能都不匹配,此时可以根据当前方向Ack与对向下一个Seq进行匹配
                    or pktAck == flowOppNxtSeq
                ):
                    # 以上四种属于最理想的情况,需要更新Seq和Ack
                    same = True
                    flag = True
                elif (
                    # 数据包Seq == 流当前方向数据包Seq(未收到该数据包时)
                    # 对应于出现了数据包重传现象
                    pktSeq == flowCurSeq
                    # 数据包Seq == 流另一方向数据包Ack - 1
                    # 数据包Seq == 流当前方向下一个数据包Seq - 1
                    # 这两种情况对应于 TCP Keep-Alive 机制
                    or pktSeq == flowOppAck - 1
                    or pktSeq == flowCurNxtSeq - 1
                ):
                    # 以上三种属于正常情况,但是不需要更新Seq和Ack
                    same = True
                elif (
                    # 如果Seq出现失序,但范围没有超过tcpOutOfOrder,
                    # 并且数据包的间隔时间在activityTimeout之内,
                    # 并且该数据包不含有SYN标志,则仍然认为该数据包属于该会话流
                    abs(pktSeq - flowCurSeq) < self.tcpOutOfOrder
                    and pktTS - flowTS < self.activityTimeout
                    and pktSYN == False
                ):
                    # 该情况属于不正常情况,不需要更新其Seq和Ack(更新也没有影响)
                    same = True
                elif (
                    # 如果Seq出现失序范围超过tcpOutOfOrder,
                    # 但是数据包的间隔时间在flowTimeout之内,
                    # 并且该数据包不含有SYN标志,则仍然认为该数据包属于该会话流
                    pktTS - flowTS < self.flowTimeout
                    and pktSYN == False
                    # 注 flowTimeout > activityTimeout
                    # 该情况的每个条件范围都包含上一情况的每个条件
                ):
                    # 该情况属于非常不正常情况,不更新Seq和Ack(这些数据包可以直接丢弃)
                    same = True

        return [same, flag]

    def dumpDataToPcap(self, pcapHeader: bytes, pcapFile):
        """
        将数据导出为PCAP文件

        Parameters
        ----------
        outputPath : str
            结果保存路径

        pcapHeader : bytes
            pcapHeader字节流

        Returns
        -------
        None

        """

        # 是否有攻击信息
        if self.attackInfo is not None:
            labelName = self.attackInfo.getLabelName()
        else:
            labelName = ["Unknown"]

        # 每个类别会话流的个数
        labelCnt = {}

        # 遍历所有类别
        for ln in labelName:
            # 检查文件夹, 若不存在则创建
            self.outputInfo.check(ln)
            labelCnt[ln] = 0

        # 如果有攻击信息
        if self.attackInfo is not None:
            # 给每条会话流添加类别标签
            for flow in self.finishedFlows:
                label = self.attackInfo.getLabel(
                    srcIP=flow.getSrcIP(),
                    dstIP=flow.getDstIP(),
                    startTS=flow.getFlowStartTime(),
                    endTS=flow.getFlowEndTime(),
                )
                flow.setLabel(label)

        # 遍历所有会话流
        for flow in self.finishedFlows:
            # 获取部分信息
            label = flow.getLabel()
            flowID = flow.getFlowID()
            startTS = str(flow.getFlowStartTime())

            # 类别数量加一
            labelCnt[label] += 1

            labelPath = self.outputInfo.getPath(label)

            # 生成路径
            filename = os.path.join(self.outputInfo.outputPath, labelPath)
            filename = filename + "/" + startTS + "-" + flowID + ".pcap"

            # 获取pcapPacket字节流列表
            packets = flow.getBytesData()

            # 写入到文件
            with open(filename, "wb") as outputFile:
                outputFile.write(pcapHeader)
                for pkt in packets:
                    outputFile.write(pkt)

        # 输出每一类会话流的个数
        for key, value in labelCnt.items():
            print("Label:", key, "\t\tNumber:", value)

        # 重定向到指定文件
        with open("log.txt", "a") as file:
            print(datetime.now(), pcapFile, file=file)
            for key, value in labelCnt.items():
                print("Label:", key, "\t\tNumber:", value, file=file)
            print(file=file)
