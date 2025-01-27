from BasicPacketInfo import BasicPacketInfo


class SeqAck:
    """序列号和确认号"""

    def __init__(self) -> None:
        """
        初始化序列号和确认号

        Parameters
        ----------
        None

        Returns
        -------
        None

        """
        # 正向数据包的序列号
        self.fwdSeq = -1
        # 正向数据包的下一个序列号
        self.fwdNxtSeq = -1
        # 正向数据包的确认号
        self.fwdAck = -1
        # 反向数据包的序列号
        self.bwdSeq = -1
        # 反向数据包的下一个序列号
        self.bwdNxtSeq = -1
        # 反向数据包的确认号
        self.bwdAck = -1

    def update(self, direction: bool, packet: BasicPacketInfo) -> None:
        """
        更新序列号和确认号

        Parameters
        ----------
        direction : bool
            数据包方向

        packet : BasicPacketInfo
            基本数据包信息

        Returns
        -------
        None

        """

        seq = packet.getSeq()  # 数据包序列号
        ack = packet.getAck()  # 数据包确认号
        pld = packet.getPayloadBytes()  # 数据包负载字节数
        syn = packet.hasFlagSYN()  # 数据包是否含有SYN标志
        fin = packet.hasFlagFIN()  # 数据包是否含有FIN标志

        if direction:  # 如果是正向
            self.fwdSeq = seq
            self.fwdNxtSeq = seq + pld + int(syn) + int(fin)
            self.fwdAck = ack
        else:  # 如果是反向
            self.bwdSeq = seq
            self.bwdNxtSeq = seq + pld + int(syn) + int(fin)
            self.bwdAck = ack


class BasicFlow:
    """基本会话流格式"""

    def __init__(self, packet: BasicPacketInfo, packetBytes: bytes) -> None:
        """
        初始化会话流信息

        Parameters
        ----------
        packet : BasicPacketInfo
            首个数据包信息

        packetBytes : bytes
            基本数据包信息

        Returns
        -------
        None

        """

        """流标识信息"""
        # 流ID
        self.flowId = None
        """流基本信息"""
        # 源IP地址
        self.srcIP = packet.getSrcIP()
        # 源端口
        self.srcPort = packet.getSrcPort()
        # 目的IP地址
        self.dstIP = packet.getDstIP()
        # 目的端口
        self.dstPort = packet.getDstPort()
        # 传输层协议(TCP:6 UDP:17)
        self.protocol = packet.getProtocol()
        # 设置流ID
        self.flowId = packet.getFwdFlowId()
        """流时间信息"""
        # 流开始时间戳(us)
        self.flowStartTS = packet.getTimeStamp()
        # 流结束时间戳(us)
        self.flowEndTS = packet.getTimeStamp()
        """序列号和确认号"""
        # 维护Seq和Ack 确保是同一会话流
        self.sequence = SeqAck()
        self.sequence.update(True, packet)
        """字节流数据"""
        self.bytesData = [packetBytes]
        """流标签信息"""
        self.label = "Unknown"

    def addPacket(self, packet: BasicPacketInfo, flag: bool, packetBytes: bytes):
        """
        向会话流中添加数据包

        Parameters
        ----------
        packet : BasicPacketInfo
            基本数据包信息

        flag : bool
            是否要更新序列号和确认号

        Returns
        -------
        None

        """

        # 更新流结束时间
        self.flowEndTS = packet.getTimeStamp()

        # 如果需要更新序列号和确认号
        if flag:
            # 如果是正向流
            if self.srcIP == packet.getSrcIP():
                self.sequence.update(True, packet)
            else:  # 否则是反向流
                self.sequence.update(False, packet)

        # 更新字节流数据
        self.bytesData.append(packetBytes)

    def getSrcIP(self) -> str:
        return self.srcIP

    def getDstIP(self) -> str:
        return self.dstIP

    def getFlowID(self) -> str:
        return self.flowId

    def getFwdSeq(self) -> int:
        return self.sequence.fwdSeq

    def getBwdSeq(self) -> int:
        return self.sequence.bwdSeq

    def getFwdNxtSeq(self) -> int:
        return self.sequence.fwdNxtSeq

    def getBwdNxtSeq(self) -> int:
        return self.sequence.bwdNxtSeq

    def getFwdAck(self) -> int:
        return self.sequence.fwdAck

    def getBwdAck(self) -> int:
        return self.sequence.bwdAck

    def getFlowStartTime(self) -> int:
        return self.flowStartTS

    def getFlowEndTime(self) -> int:
        return self.flowEndTS

    def getBytesData(self) -> list:
        return self.bytesData

    def setLabel(self, label) -> None:
        self.label = label

    def getLabel(self) -> str:
        return self.label
