import sys
import struct

from BasicPacketInfo import BasicPacketInfo
import config

"""
    struct.unpack用法
    H--integer 2个字节
    I--integer 4个字节
    符号 > 表示以大端模式(Big-Endian)读取字节,
    即 高位字节 排放在 内存的低地址端,低位字节 排放在 内存的高地址端
    符号 < 表示以小端模式(Little-Endian)读取字节,
    即 高位字节 排放在 内存的高地址端,低位字节 排放在 内存的低地址端
    符号 ! 表示以网络字节序(Network Byte Order), 正常为大端序
    例如内存中由低到高存放了两个字节 0x12 0x34,
    大端模式下其值为 4*1+3*16+2*256+1*4096=4660
    小端模式下其值为 2*1+1*16+4*256+3*4096=13330
"""
"""
    数据帧的以太网层协议长度为14个字节,位于数据帧的第0到13个字节
    目的MAC地址: 0-5   源MAC地址: 6-11   类型: 12-13
    IPv4: 0x0800  ARP: 0x0806  IPV6: 0x86DD

    IP协议首部固定部分长度为20个字节
    版本: 4位   首部长度: 4位  服务类型: 8位   总长度: 16位(首部和数据之和的长度)
    标识: 16位  标志: 3位      片偏移: 13位    生存时间: 8位
    上层协议: 8位(ICMP-1, TCP-6, UDP-17) 头部校验和: 16位
    源IP地址: 32位            目的IP地址: 32位

    TCP协议首部固定部分长度为20个字节
    源端口: 16位   目的端口: 16位   序列号: 32位   确认号: 32位
    数据偏移: 4位   保留: 6位   标志: URG ACK PSH RST SYN FIN 6位
    窗口: 16位   检验和: 16位   紧急指针: 16位
    可选字段: 长度不定, 但必须是4个字节的整数倍, 最多40字节

    UDP协议首部长度为8个字节
    源端口: 16位        目的端口: 16位
    数据包长度: 16位    校验和: 16位
"""


class PcapHeader:
    """pcap文件头信息"""

    def __init__(self, pcapheader: bytes) -> None:
        """
        初始化pcap文件头信息

        Parameters
        ----------
        pcapheader : bytes
            pcap文件前24个字节

        Returns
        -------
        None

        """
        # pcap文件头占24字节, 如果小于24则报错
        if len(pcapheader) < 24:
            print(config.PcapHeaderError)
            sys.exit(1)

        # 保存数据内容
        self.bytesData = pcapheader
        # 识别文件和字节顺序, 0xa1b2c3d4 表示是大端模式, 0xd4c3b2a1 表示是小端模式
        # 注意: 这里的大小端仅仅指 Pcap 文件的 Global Header 和 Packet Header
        # 而与 Packet Data 里的内容无关, Packet Data 里捕获的数据包都是符合网络字节序的
        # 而网络字节序就是大端模式
        self.Magic = pcapheader[0:4]
        # 当前文件的主版本号, 一般为 0x0200
        self.Major = pcapheader[4:6]
        # 当前文件的次版本号, 一般为 0x0400
        self.Minor = pcapheader[6:8]
        # 当地的标准事件, 如果用的是 GMT 则全零, 一般全零
        self.ThisZone = pcapheader[8:12]
        # 时间戳的精度, 一般为全零
        self.SigFigs = pcapheader[12:16]
        # 最大的存储长度, 设置所抓获的数据包的最大长度, 如果所有数据包都要抓获, 将值设置为65535
        self.SnapLen = pcapheader[16:20]
        # 链路类型, 一般为1，即以太网
        self.LinkType = pcapheader[20:24]

        # 设置转换模式, > 表示以大端模式转换, < 表示以小端模式转换, I 表示integer, 占4个字节
        if self.Magic == b"\xa1\xb2\xc3\xd4":
            self.TypeI = ">I"
        elif self.Magic == b"\xd4\xc3\xb2\xa1":
            self.TypeI = "<I"
        else:  # 如果上述两个都不满足, 表明这不是一个PCAP文件, 报错
            print(config.PcapHeaderError)
            sys.exit(1)

        # 解析 最大的存储长度 和 链路类型
        self.snapLen = struct.unpack(self.TypeI, self.SnapLen)[0]
        self.linkType = struct.unpack(self.TypeI, self.LinkType)[0]

        if self.linkType != 1:
            print(config.LinkLayerError)
            sys.exit(1)


class PacketReader:
    """从PCAP文件读取数据包, 并生成BasicPacketInfo格式的数据"""

    def __init__(self, filename: str) -> None:
        """
        初始化数据包读取器

        Parameters
        ----------
        filename : str
            pcap文件名

        Returns
        -------
        None

        """
        # 以二进制格式打开文件
        openFile = open(filename, "rb")
        # 读取PCAP文件中的所有数据
        self.pcapData = openFile.read()
        # 关闭文件
        openFile.close()

        # 解析pcap包头信息
        self.pcapheader = PcapHeader(self.pcapData[0:24])

        # Global Header 和 Packet Header 部分的字节序
        self.headTypeI = self.pcapheader.TypeI

        # Packet Data 部分的字节序为网络字节序, 即大端模式
        self.pktTypeI = "!I"
        self.pktTypeH = "!H"

        # PCAP文件的长度
        self.pcapLen = len(self.pcapData)
        # 当前指针指向PCAP文件中的字节位置
        self.pcapPtr = 24

        # 调试信息
        self.cnt = 0

    def nextPacket(self):
        """
        读取下一个数据包

        Parameters
        ----------
        None

        Returns
        -------
        packetInfo : BasicPacketInfo
            基本数据包信息

        pcapPacket : bytes
            pcap数据包字节流

        """

        # 数据包内容
        packetInfo = None
        # 数据包头字节数据
        packetHeader = b""
        # 数据包字节数据
        packetData = b""

        while self.pcapPtr + 16 < self.pcapLen and packetInfo is None:
            self.cnt += 1
            if self.cnt % 10000000 == 0:
                print("process packet number:", self.cnt)

            # 捕获数据包的时间戳高位,精确到秒
            timeHigh = self.pcapData[self.pcapPtr : self.pcapPtr + 4]
            timeHigh = struct.unpack(self.headTypeI, timeHigh)[0]

            # 捕获数据包的时间戳低位,精确到微秒(1s=10^6us)
            timeLow = self.pcapData[self.pcapPtr + 4 : self.pcapPtr + 8]
            timeLow = struct.unpack(self.headTypeI, timeLow)[0]

            # 时间戳(us)
            timeStamp = 1000000 * timeHigh + timeLow

            # 捕获的数据包的长度, 用于计算下一个数据包的位置
            caplen = self.pcapData[self.pcapPtr + 8 : self.pcapPtr + 12]
            caplen = struct.unpack(self.headTypeI, caplen)[0]

            # 实际的数据包的长度
            # actlen = self.pcapData[self.pcapPtr + 12 : self.pcapPtr + 16]
            # actlen = struct.unpack(self.headTypeI, actlen)[0]

            # 数据包头
            packetHeader = self.pcapData[self.pcapPtr : self.pcapPtr + 16]
            # 指针向后移动 16 位
            self.pcapPtr += 16

            # 链路层数据帧
            packetData = self.pcapData[self.pcapPtr : self.pcapPtr + caplen]
            # 指针向后移动 caplen 位
            self.pcapPtr += caplen

            if len(packetData) < 54:
                continue

            # 如果是TCP包, 则对其进行解析
            if packetData[12:14] == b"\x08\x00" and packetData[23] == 6:
                # 解析数据包信息
                packetInfo = self.getPacketInfo(timeStamp, packetData)

        return [packetInfo, packetHeader + packetData]

    def getPacketInfo(self, timeStamp: int, packetData: bytes):
        """
        获取数据包信息

        Parameters
        ----------
        timeStamp : int
            数据包时间戳

        packetData : bytes
            链路层数据帧

        Returns
        -------
        packetInfo : BasicPacketInfo
            基本数据包信息

        """
        # IP数据包首部长度
        ipHeadLen = (packetData[14] & 0x0F) << 2
        # IP数据包长度
        ipLen = struct.unpack(self.pktTypeH, packetData[16:18])[0]
        pktLen = len(packetData)
        if pktLen < 54:
            return None
        # 传输层协议(TCP:6 UDP:17)
        protocol = packetData[23]
        # 源IP地址
        srcIP = ".".join([str(i) for i in packetData[26:30]])
        # 目的IP地址
        dstIP = ".".join([str(i) for i in packetData[30:34]])
        # TCP首部
        tcpHeader = packetData[14 + ipHeadLen : 34 + ipHeadLen]
        # 源端口
        srcPort = struct.unpack(self.pktTypeH, tcpHeader[0:2])[0]
        # 目的端口
        dstPort = struct.unpack(self.pktTypeH, tcpHeader[2:4])[0]
        # 序列号
        sequence = struct.unpack(self.pktTypeI, tcpHeader[4:8])[0]
        # 确认号
        acknowledgment = struct.unpack(self.pktTypeI, tcpHeader[8:12])[0]
        # TCP控制位
        flags = tcpHeader[13]
        # TCP数据包头长度
        tcpHeadLen = (tcpHeader[12] & 0xF0) >> 2
        # 负载长度
        payloadBytes = ipLen - ipHeadLen - tcpHeadLen

        # 生成基本数据包信息
        packetInfo = BasicPacketInfo(
            timeStamp=timeStamp,
            srcIP=srcIP,
            dstIP=dstIP,
            srcPort=srcPort,
            dstPort=dstPort,
            protocol=protocol,
            sequence=sequence,
            acknowledgment=acknowledgment,
            flags=flags,
            payloadBytes=payloadBytes,
        )

        return packetInfo

    def getPcapHeader(self):
        """
        返回PcapHeader字节流信息

        Parameters
        ----------
        None

        Returns
        -------
        pcapheader : bytes
            PcapHeader字节流信息

        """
        return self.pcapheader.bytesData
