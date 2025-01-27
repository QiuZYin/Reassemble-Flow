import os
import sys
import xml.etree.ElementTree as ET

import config


class AttackInfo:
    """网络流量攻击信息"""

    def __init__(self, attackIndex: str, xmlFile: str) -> None:
        """
        初始化攻击信息

        Parameters
        ----------
        pcapFile : str
            pcap文件路径

        xmlFile : str
            攻击信息文件路径, XML格式

        Returns
        -------
        None

        """
        self.attackIndex = attackIndex  # 获取pcap文件名称
        self.xmlTree = ET.parse(xmlFile)  # 解析XML文件
        self.labels = []  # 攻击类别名称
        self.srcIPs = []
        self.dstIPs = []
        self.startTSs = []
        self.endTSs = []
        # 生成攻击信息
        self.trans()

    def trans(self) -> None:
        """
        从XML里抽取攻击信息

        Parameters
        ----------
        None

        Returns
        -------
        None

        """
        root = self.xmlTree.getroot()
        target = None

        # 根据pcap文件名找到对应的攻击信息
        for child in root:
            if child.attrib == {"name": self.attackIndex}:
                target = child
                break

        # 如果没找到, 输出错误信息, 程序退出
        if target is None:
            print(config.AttackInfoLack)
            sys.exit(1)

        # 遍历所有攻击信息并保存
        for child in target:
            self.labels.append(child.find("name").text)
            self.srcIPs.append(child.find("srcip").text)
            self.dstIPs.append(child.find("dstip").text)
            self.startTSs.append(int(child.find("start").text) * 1000000)
            self.endTSs.append(int(child.find("end").text) * 1000000)

        self.length = len(self.labels)

    def getLabel(self, srcIP: str, dstIP: str, startTS: int, endTS: int) -> str:
        """
        根据四元组获取当前会话流的类别信息

        Parameters
        ----------
        srcIP : str
            源IP地址

        dstIP : str
            目的IP地址

        startTS : int
            流开始时间(us)

        endTS : int
            流结束时间(us)

        Returns
        -------
        label : str
            流类别

        """
        label = "Benign"  # 默认良性

        for i in range(self.length):
            # 攻击信息时间全包含流时间
            # self.startTSs[i] <= startTS and endTS < self.endTSs[i]
            # 攻击信息时间和流时间有交集
            if (self.startTSs[i] <= endTS and startTS < self.endTSs[i]) and (
                (self.srcIPs[i] == srcIP and self.dstIPs[i] == dstIP)
                or (self.srcIPs[i] == dstIP and self.dstIPs[i] == srcIP)
            ):
                label = self.labels[i]
                break

        return label

    def getLabelName(self) -> set:
        """
        获取类别集合

        Parameters
        ----------
        None

        Returns
        -------
        labelName : set
            流类别集合

        """
        labelName = set(self.labels)
        labelName.add("Benign")
        return labelName
