#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <pcap.h>
#include <Winsock2.h>
#include <tchar.h>
#include <time.h>
#include <iostream>
#include <vector>
#include <sstream>
#include <bitset>
#include <map>
using namespace std;
BOOL LoadNpcapDlls()
{
    _TCHAR npcap_dir[512];
    UINT len;
    len = GetSystemDirectory(npcap_dir, 480);
    /*
    * 调用 GetSystemDirectory 函数获取系统目录路径，并将其存储在 npcap_dir 中。
    * 函数的第二个参数 480 表示 npcap_dir 变量的最大大小为 480。
    */
    if (!len) {
        fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
        return FALSE;
    }
    _tcscat_s(npcap_dir, 512, _T("\\Npcap"));
    /*
    * 使用 _tcscat_s 函数将 \Npcap 字符串追加到 npcap_dir 变量末尾，形成完整的 Npcap 安装目录路径。
    */
    if (SetDllDirectory(npcap_dir) == 0) {
        fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
        return FALSE;
    }
    /*
    * 调用 SetDllDirectory 函数设置 DLL 的搜索路径为 npcap_dir，使得程序可以找到并加载该目录下的 DLL 文件。如果函数返回值为 0，则说明设置失败，打印错误信息并返回 FALSE。
    */
    return TRUE;
}

#pragma pack(1)

//6字节的MAC地址
typedef struct MACAddress {
    u_char bytes[6];
}MACAddress;

//4字节的IP地址
typedef struct IPAddress {
    u_char bytes[4];
}IPAddress;
bool operator<(const IPAddress& lhs, const IPAddress& rhs) {
    for (int i = 0; i < 4; ++i) {
        if (lhs.bytes[i] < rhs.bytes[i]) {
            return true;
        }
        else if (lhs.bytes[i] > rhs.bytes[i]) {
            return false;
        }
        // 如果相等，继续比较下一个字节
    }
    return false;  // 如果所有字节都相等，则认为相等
}
bool operator==(const IPAddress& lhs, const IPAddress& rhs) {
    for (int i = 0; i < 4; ++i) {
        if (lhs.bytes[i] != rhs.bytes[i]) {
            return false;  // 如果存在不相等的字节，返回 false
        }
    }
    return true;  // 如果所有字节都相等，返回 true
}
bool operator!=(const IPAddress& lhs, const IPAddress& rhs) {
    return !(lhs == rhs);  // 利用相等运算符来定义不相等运算符
}

//FrameHeader
typedef struct FrameHeader {
    MACAddress dest_mac_address;
    MACAddress source_mac_address;
    WORD type;
}FrameHeader;

//ARPHeader
typedef struct ARPFrame {
    FrameHeader frame_header;
    WORD hardware_type;
    WORD protocol_type;
    BYTE h_len;
    BYTE p_len;
    WORD operation;
    MACAddress source_mac;
    IPAddress source_ip;
    MACAddress dest_mac;
    IPAddress dest_ip;
}APRFrame;

//IPHeader
typedef struct IPHeader {
    u_char  ver_ihl;//版本（4bits）和包头长度（4bits）
    u_char  tos;//服务类型
    u_short tlen;//总长度
    u_short identification;//标识
    u_short flags_fo;//标志和片偏移
    u_char  ttl;//生存周期
    u_char  proto;//协议
    u_short crc;//头部校验和
    IPAddress  source_addr;//源IP地址
    IPAddress  dest_addr;//目的IP地址
    u_int  op_pad;//选择+填充
}IPHeader;

#pragma pack()

void printErrorMsg(string msg) {
    printf("[ERROR!] %s \n", msg.c_str());
}

void setARP(ARPFrame* arp, MACAddress source_mac, IPAddress source_ip, IPAddress dest_ip) {
    // 设置目的地址为广播地址
    for (int i = 0; i < 6; i++) {
        arp->frame_header.dest_mac_address.bytes[i] = 0xFF;
    }

    //设置本机网卡的MAC地址
    for (int i = 0; i < 6; i++) {
        arp->frame_header.source_mac_address.bytes[i] = source_ip.bytes[i];
    }

    //设置帧类型为0x0806
    arp->frame_header.type = htons(0x0806);

    //设置硬件类型为以太网
    arp->hardware_type = htons(0x0001);

    //设置协议类型为IP
    arp->protocol_type = htons(0x0800);

    //设置硬件地址长度为6
    arp->h_len = 6;

    //设置协议地址长度为4
    arp->p_len = 4;

    //设置操作为ARP请求
    arp->operation = htons(0x0001);

    //设置本机网卡的MAC地址
    for (int i = 0; i < 6; i++) {
        arp->source_mac.bytes[i] = source_mac.bytes[i];
    }

    //设置本机网卡的IP地址
    for (int i = 0; i < 4; i++) {
        arp->source_ip.bytes[i] = source_ip.bytes[i];
    }

    //设置目的MAC地址为0
    for (int i = 0; i < 6; i++) {
        arp->dest_mac.bytes[i] = 0x00;
    }

    //设置请求的IP地址
    for (int i = 0; i < 4; i++) {
        arp->dest_ip.bytes[i] = dest_ip.bytes[i];
    }
}

class RoutingEntry {
    string dest_ip;
    string mask;
    string next_hop;
public:
    RoutingEntry(string dest_ip = "", string mask = "", string next_hop = "") {
        this->dest_ip = dest_ip;
        this->mask = mask;
        this->next_hop = next_hop;
    }
    string getDestIP() {
        return this->dest_ip;
    }
    string getMask() {
        return this->mask;
    }
    string getNextHop() {
        return this->next_hop;
    }
};

string ipToBinary(string ip) {
    stringstream ss(ip);
    string token;
    string binaryIP = "";

    while (getline(ss, token, '.')) {
        int octet = stoi(token);
        binaryIP += bitset<8>(octet).to_string();
    }

    return binaryIP;
}

bool isIPMatch(string ip, string entry_ip, string entry_mask) {
    string ip_binary = ipToBinary(ip);
    string entry_ip_binary = ipToBinary(entry_ip);
    string entry_mask_binary = ipToBinary(entry_mask);

    for (int i = 0; i < (int)entry_mask_binary.size(); i++) {
        if (entry_mask_binary[i] == '1' && ip_binary[i] != entry_ip_binary[i]) {
            return false;
        }
    }
    return true;
}
string ip2net(string ip, string mask) {
    string ip_bin = ipToBinary(ip);
    string mask_bin = ipToBinary(mask);
    string net_bin = "";

    for (int i = 0; i < (int)mask_bin.size(); i++) {
        if (mask_bin[i] == '1') {
            net_bin += ip_bin[i];
        }
        else {
            net_bin += '0';
        }
    }

    string net = "";

    for (int i = 0; i < 4; i++) {
        string s = "";
        for (int j = 0; j < 8; j++) {
            s += net_bin[i * 8 + j];
        }
        long int num = strtol(s.c_str(), NULL, 2);
        char ssc[10];
        string ss = _itoa(num, ssc, 10);
        net += ss;
        if (i != 3) net += ".";
    }

    return net;
}

class RoutingTable {
    vector<RoutingEntry*> entries;

public:
    RoutingTable() {}
    void insertEntry(string dest_ip, string mask, string next_hop) {
        this->entries.push_back(new RoutingEntry(dest_ip, mask, next_hop));
    }
    bool selectHop(string ip, string* next_hop, string* mask) {
        for (int i = 0; i < (int)this->entries.size(); i++) {
            string entry_ip = this->entries[i]->getDestIP();
            string entry_mask = this->entries[i]->getMask();
            if (isIPMatch(ip, entry_ip, entry_mask)) {
                *next_hop = this->entries[i]->getNextHop();
                *mask = this->entries[i]->getMask();
                return true;
            }
        }
        printErrorMsg("next hop not found!");
        return false;
    }
    bool removeEntryByIndex(int index) {
        if ((int)this->entries.size() <= index) return false;
        this->entries.erase(entries.begin() + index);
        return true;
    }
    void clearEntries() {
        this->entries.clear();
    }
    void printEntries() {
        printf("当前的路由表：\n");
        for (int i = 0; i < (int)this->entries.size(); i++) {
            printf("(index = %d)  %s  %s  %s\n", i, this->entries[i]->getDestIP().c_str(), this->entries[i]->getMask().c_str(), this->entries[i]->getNextHop().c_str());

        }
        if (this->entries.size() == 0) {
            printf("(empty)\n");
        }
    }
};


void printPktInfo(const struct pcap_pkthdr* pkt_header, const u_char* pkt_data) {
    // 打印时间戳和数据包长度
    printf("***********************数据包内容begin****************************\n\n");
    printf("时间戳: %ld.%06ld, 数据包长度: %d 字节\n",
        pkt_header->ts.tv_sec, pkt_header->ts.tv_usec, pkt_header->len);

    
    //打印报头信息
    FrameHeader* frame_header = (FrameHeader*)pkt_data;
    IPHeader* ip_header = (IPHeader*)(pkt_data + 14);
    printf("源IP地址：%d.%d.%d.%d -> 目的IP地址：%d.%d.%d.%d\n",
        ip_header->source_addr.bytes[0],
        ip_header->source_addr.bytes[1],
        ip_header->source_addr.bytes[2],
        ip_header->source_addr.bytes[3],

        ip_header->dest_addr.bytes[0],
        ip_header->dest_addr.bytes[1],
        ip_header->dest_addr.bytes[2],
        ip_header->dest_addr.bytes[3]
    );

    printf("源MAC地址：%02x-%02x-%02x-%02x-%02x-%02x ->目的MAC地址：%02x-%02x-%02x-%02x-%02x-%02x\n",
        frame_header->source_mac_address.bytes[0],
        frame_header->source_mac_address.bytes[1],
        frame_header->source_mac_address.bytes[2],
        frame_header->source_mac_address.bytes[3],
        frame_header->source_mac_address.bytes[4],
        frame_header->source_mac_address.bytes[5],

        frame_header->dest_mac_address.bytes[0],
        frame_header->dest_mac_address.bytes[1],
        frame_header->dest_mac_address.bytes[2],
        frame_header->dest_mac_address.bytes[3],
        frame_header->dest_mac_address.bytes[4],
        frame_header->dest_mac_address.bytes[5]
    );
    

    //打印前16个字节的数据包内容
    printf("数据包内容:\n");
    for (int i = 0; i < 48 && i < pkt_header->len; ++i) {
        printf("%02X ", pkt_data[i]);
    }
    printf("\n***********************数据包内容end****************************\n");
    printf("\n\n");
}
string ip2string(IPAddress ip) {
    string ip_str = "";
    for (int i = 0; i < 4; i++) {
        ip_str += to_string(ip.bytes[i]);
        if (i != 3) ip_str += ".";
    }
    return ip_str;
}
string mac2string(MACAddress mac) {
    string mac_str = "";
    for (int i = 0; i < 6; i++) {
        mac_str += to_string(mac.bytes[i]);
        if (i != 5) mac_str += "-";
    }
    return mac_str;
}
MACAddress* string2mac(string mac) {
    MACAddress* result = new MACAddress;
    std::istringstream ss(mac);
    int byte;

    for (int i = 0; i < 6; ++i) {
        if (i > 0) {
            char separator;
            ss >> separator; // 读取分隔符
        }
        ss >> std::hex >> byte; // 以十六进制读取字节
        result->bytes[i] = static_cast<u_char>(byte);
    }

    return result;
}
IPAddress* string2ip(const std::string& ipStr) {
    IPAddress* ipAddress = new IPAddress;

    // 使用 stringstream 将字符串按照 '.' 分割
    stringstream ss(ipStr);
    string token;
    vector<int> octets;

    while (std::getline(ss, token, '.')) {
        octets.push_back(std::stoi(token));
    }

    // 将分割得到的整数值存储到 IPAddress 结构体中
    for (size_t i = 0; i < min(octets.size(), sizeof(ipAddress->bytes)); ++i) {
        ipAddress->bytes[i] = static_cast<u_char>(octets[i]);
    }

    return ipAddress;
}
string mask_int_to_str(uint32_t mask) {
    // 将32位整数分成四个8位的部分
    int octets[4];
    octets[0] = (mask >> 24) & 0xFF;
    octets[1] = (mask >> 16) & 0xFF;
    octets[2] = (mask >> 8) & 0xFF;
    octets[3] = mask & 0xFF;

    // 使用字符串流来构建字符串
    std::stringstream ss;
    ss << octets[3] << "." << octets[2] << "." << octets[1] << "." << octets[0];

    // 返回字符串
    return ss.str();
}
bool send_getARP(map<IPAddress, MACAddress>* map, pcap_t* my_dev_handle, MACAddress source_mac, IPAddress source_ip, IPAddress dest_ip) {
    //参数：源MAC，源IP，目的IP

    printf("发送ARP——源MAC：%s, 源IP：%s，目的IP：%s\n", mac2string(source_mac).c_str(), ip2string(source_ip).c_str(), ip2string(dest_ip).c_str());


    ARPFrame arp_frame;

    setARP(&arp_frame, source_mac, source_ip, dest_ip);
    pcap_sendpacket(my_dev_handle, (u_char*)&arp_frame, sizeof(arp_frame));
    struct pcap_pkthdr* pkt_header_arp;
    const u_char* pkt_data_arp;
    while (true) {
        int rtn = pcap_next_ex(my_dev_handle, &pkt_header_arp, &pkt_data_arp);
        bool match = true;
        if (rtn == -1) {
            printErrorMsg("捕获数据包时发生错误！");
            return false;
        }
        else if (rtn == 0) {
            printErrorMsg("没有捕获到数据包！");
            //return false;
            continue;
        }
        else {
            ARPFrame* arp_frame = (ARPFrame*)pkt_data_arp;
            for (int i = 0; i < 4; i++) {
                if (arp_frame->dest_ip.bytes[i] != source_ip.bytes[i]) {
                    //printErrorMsg("捕获到的数据包的目的IP不匹配！");
                    match = false;
                }
                if (arp_frame->source_ip.bytes[i] != dest_ip.bytes[i]) {
                    //printErrorMsg("捕获到的数据包的源IP不匹配！");
                    match = false;
                }
                if (!match) break;
            }
            if (!match) continue;

            printf("IP地址与MAC地址的对应关系如下：\n");
            printf("IP地址：%d.%d.%d.%d <==> MAC地址： %02x-%02x-%02x-%02x-%02x-%02x\n",
                arp_frame->source_ip.bytes[0],
                arp_frame->source_ip.bytes[1],
                arp_frame->source_ip.bytes[2],
                arp_frame->source_ip.bytes[3],

                arp_frame->source_mac.bytes[0],
                arp_frame->source_mac.bytes[1],
                arp_frame->source_mac.bytes[2],
                arp_frame->source_mac.bytes[3],
                arp_frame->source_mac.bytes[4],
                arp_frame->source_mac.bytes[5]
            );
            map->insert(make_pair(arp_frame->source_ip, arp_frame->source_mac));
            break;
        }
    }
    return true;
}


//存储所有的设备
pcap_if_t* all_devs;

//保存错误信息
char err_buff[PCAP_ERRBUF_SIZE];

//路由表
RoutingTable routing_table;

//ip与mac的映射关系
map<IPAddress, MACAddress>ip_mac_map;

//最大的IP地址数量
const int max_ip_number = 5;

int main()
{
    //加载Npcap相关函数
    if (!LoadNpcapDlls()) {
        printErrorMsg("Npcap加载错误！");
        return 0;
    }

    //获取设备列表
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &all_devs, err_buff) == -1) {
        printErrorMsg("获取设备列表错误！");
        return 0;
    }

    //打印设备列表
    int count_devs = 0;
    printf("----------获取到的设备列表：----------\n");
    for (pcap_if_t* curr_dev = all_devs; curr_dev; curr_dev = curr_dev->next) {
        count_devs++;

        printf("%d, %s", count_devs, curr_dev->name);
        if (curr_dev->description) {
            printf(" (%s)\n", curr_dev->description);
        }
        else {
            printf(" (无描述)\n");
        }

        //获取这个设备的IP地址信息
        for (pcap_addr_t* curr_addr = curr_dev->addresses; curr_addr != NULL; curr_addr = curr_addr->next) {
            if (curr_addr->addr->sa_family == AF_INET) {
                char ip_char[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(((struct sockaddr_in*)curr_addr->addr)->sin_addr), ip_char, INET_ADDRSTRLEN);
                printf("\tIP地址: %s\n", ip_char);

                char netmask_char[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(((struct sockaddr_in*)curr_addr->netmask)->sin_addr), netmask_char, INET_ADDRSTRLEN);
                printf("\t子网掩码: %s\n", netmask_char);
            }
        }
    }
    printf("\n");
    if (count_devs == 0) {
        printErrorMsg("没有捕获到设备！");
        return 0;
    }

    //选择设备
    int dev_num;
    printf("----------选择设备：----------\n");
    printf("请输入设备的标号：");
    scanf_s("%d", &dev_num);
    if (dev_num < 1 || dev_num > count_devs) {
        printErrorMsg("输入标号超限！");
        return 0;
    }
    pcap_if_t* my_dev = all_devs;
    pcap_t* my_dev_handle;
    for (int i = 0; i < dev_num - 1; i++) {
        my_dev = my_dev->next;
    }
    printf("\n");

    //打开选定的设备
    if ((my_dev_handle = pcap_open(my_dev->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 500, NULL, err_buff)) == NULL) {
        printErrorMsg("打开设备失败！");
        pcap_freealldevs(all_devs);
        return 0;
    }

    //获取本地的IP地址
    DWORD local_ip_dw[max_ip_number];
    int ip_number = 0;
    for (pcap_addr_t* curr_addr = my_dev->addresses; curr_addr != NULL; curr_addr = curr_addr->next) {
        if (curr_addr->addr->sa_family == AF_INET) {
            local_ip_dw[ip_number++] = inet_addr(inet_ntoa(((struct sockaddr_in*)(curr_addr->addr))->sin_addr));
        }
    }

    //获取设备的子网掩码
    u_int net_mask;
    if (my_dev->addresses != NULL) {
        net_mask = ((struct sockaddr_in*)(my_dev->addresses->netmask))->sin_addr.S_un.S_addr;
    }
    else {
        net_mask = 0xffffff;
    }

    //编译网络数据包过滤器
    struct bpf_program fcode;
    char packet_filter[] = "ip or arp";
    if (pcap_compile(my_dev_handle, &fcode, packet_filter, 1, net_mask) < 0) {
        printErrorMsg("编译过滤器失败！");
        return 0;
    }

    //将已编译的过滤器与设备关联
    if (pcap_setfilter(my_dev_handle, &fcode) < 0) {
        printErrorMsg("过滤器设置失败！");
        return 0;
    }

    //捕获本地的MAC地址
    
    IPAddress local_ip[max_ip_number];
    for (int i = 0; i < ip_number; i++) {
        local_ip[i].bytes[0] = local_ip_dw[i] & 0xFF;
        local_ip[i].bytes[1] = (local_ip_dw[i] >> 8) & 0xFF;
        local_ip[i].bytes[2] = (local_ip_dw[i] >> 16) & 0xFF;
        local_ip[i].bytes[3] = (local_ip_dw[i] >> 24) & 0xFF;
    }
    MACAddress source_mac;
    source_mac.bytes[0] = 0x66;
    source_mac.bytes[1] = 0x66;
    source_mac.bytes[2] = 0x66;
    source_mac.bytes[3] = 0x66;
    source_mac.bytes[4] = 0x66;
    source_mac.bytes[5] = 0x66;
    IPAddress source_ip;
    source_ip.bytes[0] = 0x70;
    source_ip.bytes[1] = 0x70;
    source_ip.bytes[2] = 0x70;
    source_ip.bytes[3] = 0x70;
    
    MACAddress local_mac[max_ip_number];
    for (int i = 0; i < ip_number; i++) {
        if (!send_getARP(&ip_mac_map, my_dev_handle, source_mac, source_ip, local_ip[i])) {
            printErrorMsg("ARP传输错误！");
            return 0;
        }
        auto it = ip_mac_map.find(local_ip[i]);
        if (it != ip_mac_map.end()) {
            local_mac[i] = it->second;
        }
        else {
            printErrorMsg("获取本地mac地址错误！");
            return 0;
        }
    }
    /*printf("开始发送测试arp~~~~~~~~\n");
    send_getARP(&ip_mac_map, my_dev_handle, local_mac[0], local_ip[0], *string2ip("206.1.2.2"));*/

    for (int i = 0; i < ip_number; i++) {
        string mask = mask_int_to_str(net_mask);
        routing_table.insertEntry(ip2net(ip2string(local_ip[i]),mask), mask, "直接投递");
    }

    //手动添加路由表项
    printf("----------设置路由表----------\n");
    for (;;) {
        cout << ">>>";
        string command;
        cin >> command;
        if (command == "exit") {
            break;
        }
        else if (command == "insert") {
            string dest_ip, mask, next_hop;
            cin >> dest_ip >> mask >> next_hop;
            routing_table.insertEntry(dest_ip, mask, next_hop);
        }
        else if (command == "clear") {
            routing_table.clearEntries();
        }
        else if (command == "remove") {
            int index;
            cin >> index;
            if (!routing_table.removeEntryByIndex(index)) {
                printErrorMsg("删除路由表项失败！");
            }
        }
        else if (command == "show") {
            routing_table.printEntries();
        }
        else {
            printErrorMsg("未识别的命令！");
        }
    }
    
    system("pause");

    //开始捕获数据包
    
    

    printf("\n开始捕获数据包 （%s）...\n", my_dev->description);
    struct pcap_pkthdr* pkt_header;
    const u_char* pkt_data;
    //string curr_fil = "";
    while (true) {
        //printf("while begin!!!\n");
  
        int rtn = pcap_next_ex(my_dev_handle, &pkt_header, &pkt_data);
        if (rtn == -1) {
            printErrorMsg("捕获数据包时发生错误！");
            return 0;
        }
        else if (rtn == 0) {
            printErrorMsg("没有捕获到数据包！\n");
            //return 0;
        }
        else {
            u_char* pkt_data_v = (u_char*)pkt_data;
            FrameHeader* frame_header = (FrameHeader*)pkt_data_v;
            IPHeader* ip_header = (IPHeader*)(pkt_data_v + 14);


            //判断条件
            MACAddress pkt_dest_mac = frame_header->dest_mac_address;
            IPAddress pkt_dest_ip = ip_header->dest_addr;
            bool ip_same, mac_same, trans;
            trans = true;
            for (int i = 0; i < ip_number; i++) {
                ip_same = true;
                for (int j = 0; j < 4; j++) {
                    if (pkt_dest_ip.bytes[j] != local_ip[i].bytes[j]) {
                        ip_same = false;
                        break;
                    }
                }
                mac_same = true;
                for (int j = 0; j < 6; j++) {
                    if (pkt_dest_mac.bytes[j] != local_mac[i].bytes[j]) {
                        mac_same = false;
                        break;
                    }
                }
                if (!(mac_same && !ip_same)) {
                    trans = false;
                    break;
                }
            }
            if (!trans) {
                continue;
            }


            printf("\n打印数据包信息：\n");
            printPktInfo(pkt_header, pkt_data_v);
            int length = pkt_header->len + sizeof(FrameHeader);
            string dest_ip = ip2string(ip_header->dest_addr);
            string next_hop, next_hop_mask;
            if (!routing_table.selectHop(dest_ip, &next_hop, &next_hop_mask)) {
                printErrorMsg("获取下一跳失败！\n");
                //return 0;
                continue;
            }
            printf("获取的下一跳的IP地址：%s\n", next_hop.c_str());
            if (next_hop == "直接投递") {
                next_hop = dest_ip;
            }
            IPAddress* next_hop_ip = string2ip(next_hop);

            //看一下哪个IP和目的IP匹配
            int target_index = -1;
            for (int i = 0; i < ip_number; i++) {
                if (isIPMatch(ip2string(local_ip[i]), next_hop, next_hop_mask)) {
                    target_index = i;
                    break;
                }
            }
            if (target_index == -1) {
                printErrorMsg("获取的下一跳的IP地址与本机不在一个网络中！");
                return 0;
            }
            printf("匹配到的IP地址：%s\n", ip2string(local_ip[target_index]).c_str());
                 
            //获取MAC地址
            MACAddress dest_mac;
            auto it = ip_mac_map.find(*next_hop_ip);
            if (it != ip_mac_map.end()) {
                dest_mac = it->second;
            }
            else {
                send_getARP(&ip_mac_map, my_dev_handle, local_mac[target_index], local_ip[target_index], *next_hop_ip);
                auto it2 = ip_mac_map.find(*next_hop_ip);
                if (it2 == ip_mac_map.end()) {
                    printErrorMsg("获取MAC地址错误！");
                    //return 0;
                    continue;
                }
                else {
                    dest_mac = it2->second;
                }
                continue;
            }
            printf("获取MAC地址完成！\n");

            //封装数据包，更改目的MAC地址
            for (int i = 0; i < 6; i++) {
                frame_header->dest_mac_address.bytes[i] = dest_mac.bytes[i];
                frame_header->source_mac_address.bytes[i] = local_mac[target_index].bytes[i];
            }
            printf("封装数据包完成!\n");
            printf("数据包封装结果：\n");
            printPktInfo(pkt_header, pkt_data_v);
            //发送数据报
            pcap_sendpacket(my_dev_handle, (u_char*)pkt_data_v, length);
            printf("发送数据报完成!\n");
        }
        //printf("while end!!!!!\n");
    }

    pcap_freealldevs(all_devs);
    system("pause");
    return 0;
}
