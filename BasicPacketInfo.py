class BasicPacketInfo:
    """数据包的统一格式"""

    def __init__(
        self,
        timeStamp,
        srcIP,
        dstIP,
        srcPort,
        dstPort,
        protocol,
        sequence,
        acknowledgment,
        flags,
        payloadBytes,
    ) -> None:
        # 时间戳
        self.timeStamp = timeStamp
        # 源IP地址
        self.srcIP = srcIP
        # 目的IP地址
        self.dstIP = dstIP
        # 源端口
        self.srcPort = srcPort
        # 目的端口
        self.dstPort = dstPort
        # 传输层协议(TCP:6 UDP:17)
        self.protocol = protocol
        # 序列号
        self.sequence = sequence
        # 确认号
        self.acknowledgment = acknowledgment
        # 控制位
        self.flags = flags
        # 传输层负载长度
        self.payloadBytes = payloadBytes

        # 数据包所属流编号
        self.fwdFlowId = self.generateFlowId(True)
        self.bwdFlowId = self.generateFlowId(False)

    def generateFlowId(self, duration: bool) -> str:
        """
        生成数据包的流ID

        Parameters
        ----------
        duration : bool
            方向, True为正向, False为反向

        Returns
        -------
        flowId : str
            流ID(foramtter: srcIP-srcPort-dstIP-dstPort-protocol)

        """
        if duration:
            flowId = (
                self.srcIP
                + "-"
                + str(self.srcPort)
                + "-"
                + self.dstIP
                + "-"
                + str(self.dstPort)
                + "-"
                + str(self.protocol)
            )
        else:
            flowId = (
                self.dstIP
                + "-"
                + str(self.dstPort)
                + "-"
                + self.srcIP
                + "-"
                + str(self.srcPort)
                + "-"
                + str(self.protocol)
            )
        return flowId

    def getTimeStamp(self) -> int:
        return self.timeStamp

    def getSrcIP(self) -> str:
        return self.srcIP

    def getDstIP(self) -> str:
        return self.dstIP

    def getSrcPort(self) -> int:
        return self.srcPort

    def getDstPort(self) -> int:
        return self.dstPort

    def getProtocol(self) -> int:
        return self.protocol

    def getSeq(self) -> int:
        return self.sequence

    def getAck(self) -> int:
        return self.acknowledgment

    def hasFlagFIN(self) -> bool:
        return self.flags & 1

    def hasFlagSYN(self) -> bool:
        return (self.flags >> 1) & 1

    def getPayloadBytes(self) -> int:
        return self.payloadBytes

    def getFwdFlowId(self) -> str:
        return self.fwdFlowId

    def getBwdFlowId(self) -> str:
        return self.bwdFlowId
