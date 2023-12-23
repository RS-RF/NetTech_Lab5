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
    * ���� GetSystemDirectory ������ȡϵͳĿ¼·����������洢�� npcap_dir �С�
    * �����ĵڶ������� 480 ��ʾ npcap_dir ����������СΪ 480��
    */
    if (!len) {
        fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
        return FALSE;
    }
    _tcscat_s(npcap_dir, 512, _T("\\Npcap"));
    /*
    * ʹ�� _tcscat_s ������ \Npcap �ַ���׷�ӵ� npcap_dir ����ĩβ���γ������� Npcap ��װĿ¼·����
    */
    if (SetDllDirectory(npcap_dir) == 0) {
        fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
        return FALSE;
    }
    /*
    * ���� SetDllDirectory �������� DLL ������·��Ϊ npcap_dir��ʹ�ó�������ҵ������ظ�Ŀ¼�µ� DLL �ļ��������������ֵΪ 0����˵������ʧ�ܣ���ӡ������Ϣ������ FALSE��
    */
    return TRUE;
}

#pragma pack(1)

//6�ֽڵ�MAC��ַ
typedef struct MACAddress {
    u_char bytes[6];
}MACAddress;

//4�ֽڵ�IP��ַ
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
        // �����ȣ������Ƚ���һ���ֽ�
    }
    return false;  // ��������ֽڶ���ȣ�����Ϊ���
}
bool operator==(const IPAddress& lhs, const IPAddress& rhs) {
    for (int i = 0; i < 4; ++i) {
        if (lhs.bytes[i] != rhs.bytes[i]) {
            return false;  // ������ڲ���ȵ��ֽڣ����� false
        }
    }
    return true;  // ��������ֽڶ���ȣ����� true
}
bool operator!=(const IPAddress& lhs, const IPAddress& rhs) {
    return !(lhs == rhs);  // �����������������岻��������
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
    u_char  ver_ihl;//�汾��4bits���Ͱ�ͷ���ȣ�4bits��
    u_char  tos;//��������
    u_short tlen;//�ܳ���
    u_short identification;//��ʶ
    u_short flags_fo;//��־��Ƭƫ��
    u_char  ttl;//��������
    u_char  proto;//Э��
    u_short crc;//ͷ��У���
    IPAddress  source_addr;//ԴIP��ַ
    IPAddress  dest_addr;//Ŀ��IP��ַ
    u_int  op_pad;//ѡ��+���
}IPHeader;

#pragma pack()

void printErrorMsg(string msg) {
    printf("[ERROR!] %s \n", msg.c_str());
}

void setARP(ARPFrame* arp, MACAddress source_mac, IPAddress source_ip, IPAddress dest_ip) {
    // ����Ŀ�ĵ�ַΪ�㲥��ַ
    for (int i = 0; i < 6; i++) {
        arp->frame_header.dest_mac_address.bytes[i] = 0xFF;
    }

    //���ñ���������MAC��ַ
    for (int i = 0; i < 6; i++) {
        arp->frame_header.source_mac_address.bytes[i] = source_ip.bytes[i];
    }

    //����֡����Ϊ0x0806
    arp->frame_header.type = htons(0x0806);

    //����Ӳ������Ϊ��̫��
    arp->hardware_type = htons(0x0001);

    //����Э������ΪIP
    arp->protocol_type = htons(0x0800);

    //����Ӳ����ַ����Ϊ6
    arp->h_len = 6;

    //����Э���ַ����Ϊ4
    arp->p_len = 4;

    //���ò���ΪARP����
    arp->operation = htons(0x0001);

    //���ñ���������MAC��ַ
    for (int i = 0; i < 6; i++) {
        arp->source_mac.bytes[i] = source_mac.bytes[i];
    }

    //���ñ���������IP��ַ
    for (int i = 0; i < 4; i++) {
        arp->source_ip.bytes[i] = source_ip.bytes[i];
    }

    //����Ŀ��MAC��ַΪ0
    for (int i = 0; i < 6; i++) {
        arp->dest_mac.bytes[i] = 0x00;
    }

    //���������IP��ַ
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
        printf("��ǰ��·�ɱ�\n");
        for (int i = 0; i < (int)this->entries.size(); i++) {
            printf("(index = %d)  %s  %s  %s\n", i, this->entries[i]->getDestIP().c_str(), this->entries[i]->getMask().c_str(), this->entries[i]->getNextHop().c_str());

        }
        if (this->entries.size() == 0) {
            printf("(empty)\n");
        }
    }
};


void printPktInfo(const struct pcap_pkthdr* pkt_header, const u_char* pkt_data) {
    // ��ӡʱ��������ݰ�����
    printf("***********************���ݰ�����begin****************************\n\n");
    printf("ʱ���: %ld.%06ld, ���ݰ�����: %d �ֽ�\n",
        pkt_header->ts.tv_sec, pkt_header->ts.tv_usec, pkt_header->len);

    
    //��ӡ��ͷ��Ϣ
    FrameHeader* frame_header = (FrameHeader*)pkt_data;
    IPHeader* ip_header = (IPHeader*)(pkt_data + 14);
    printf("ԴIP��ַ��%d.%d.%d.%d -> Ŀ��IP��ַ��%d.%d.%d.%d\n",
        ip_header->source_addr.bytes[0],
        ip_header->source_addr.bytes[1],
        ip_header->source_addr.bytes[2],
        ip_header->source_addr.bytes[3],

        ip_header->dest_addr.bytes[0],
        ip_header->dest_addr.bytes[1],
        ip_header->dest_addr.bytes[2],
        ip_header->dest_addr.bytes[3]
    );

    printf("ԴMAC��ַ��%02x-%02x-%02x-%02x-%02x-%02x ->Ŀ��MAC��ַ��%02x-%02x-%02x-%02x-%02x-%02x\n",
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
    

    //��ӡǰ16���ֽڵ����ݰ�����
    printf("���ݰ�����:\n");
    for (int i = 0; i < 48 && i < pkt_header->len; ++i) {
        printf("%02X ", pkt_data[i]);
    }
    printf("\n***********************���ݰ�����end****************************\n");
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
            ss >> separator; // ��ȡ�ָ���
        }
        ss >> std::hex >> byte; // ��ʮ�����ƶ�ȡ�ֽ�
        result->bytes[i] = static_cast<u_char>(byte);
    }

    return result;
}
IPAddress* string2ip(const std::string& ipStr) {
    IPAddress* ipAddress = new IPAddress;

    // ʹ�� stringstream ���ַ������� '.' �ָ�
    stringstream ss(ipStr);
    string token;
    vector<int> octets;

    while (std::getline(ss, token, '.')) {
        octets.push_back(std::stoi(token));
    }

    // ���ָ�õ�������ֵ�洢�� IPAddress �ṹ����
    for (size_t i = 0; i < min(octets.size(), sizeof(ipAddress->bytes)); ++i) {
        ipAddress->bytes[i] = static_cast<u_char>(octets[i]);
    }

    return ipAddress;
}
string mask_int_to_str(uint32_t mask) {
    // ��32λ�����ֳ��ĸ�8λ�Ĳ���
    int octets[4];
    octets[0] = (mask >> 24) & 0xFF;
    octets[1] = (mask >> 16) & 0xFF;
    octets[2] = (mask >> 8) & 0xFF;
    octets[3] = mask & 0xFF;

    // ʹ���ַ������������ַ���
    std::stringstream ss;
    ss << octets[3] << "." << octets[2] << "." << octets[1] << "." << octets[0];

    // �����ַ���
    return ss.str();
}
bool send_getARP(map<IPAddress, MACAddress>* map, pcap_t* my_dev_handle, MACAddress source_mac, IPAddress source_ip, IPAddress dest_ip) {
    //������ԴMAC��ԴIP��Ŀ��IP

    printf("����ARP����ԴMAC��%s, ԴIP��%s��Ŀ��IP��%s\n", mac2string(source_mac).c_str(), ip2string(source_ip).c_str(), ip2string(dest_ip).c_str());


    ARPFrame arp_frame;

    setARP(&arp_frame, source_mac, source_ip, dest_ip);
    pcap_sendpacket(my_dev_handle, (u_char*)&arp_frame, sizeof(arp_frame));
    struct pcap_pkthdr* pkt_header_arp;
    const u_char* pkt_data_arp;
    while (true) {
        int rtn = pcap_next_ex(my_dev_handle, &pkt_header_arp, &pkt_data_arp);
        bool match = true;
        if (rtn == -1) {
            printErrorMsg("�������ݰ�ʱ��������");
            return false;
        }
        else if (rtn == 0) {
            printErrorMsg("û�в������ݰ���");
            //return false;
            continue;
        }
        else {
            ARPFrame* arp_frame = (ARPFrame*)pkt_data_arp;
            for (int i = 0; i < 4; i++) {
                if (arp_frame->dest_ip.bytes[i] != source_ip.bytes[i]) {
                    //printErrorMsg("���񵽵����ݰ���Ŀ��IP��ƥ�䣡");
                    match = false;
                }
                if (arp_frame->source_ip.bytes[i] != dest_ip.bytes[i]) {
                    //printErrorMsg("���񵽵����ݰ���ԴIP��ƥ�䣡");
                    match = false;
                }
                if (!match) break;
            }
            if (!match) continue;

            printf("IP��ַ��MAC��ַ�Ķ�Ӧ��ϵ���£�\n");
            printf("IP��ַ��%d.%d.%d.%d <==> MAC��ַ�� %02x-%02x-%02x-%02x-%02x-%02x\n",
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


//�洢���е��豸
pcap_if_t* all_devs;

//���������Ϣ
char err_buff[PCAP_ERRBUF_SIZE];

//·�ɱ�
RoutingTable routing_table;

//ip��mac��ӳ���ϵ
map<IPAddress, MACAddress>ip_mac_map;

//����IP��ַ����
const int max_ip_number = 5;

int main()
{
    //����Npcap��غ���
    if (!LoadNpcapDlls()) {
        printErrorMsg("Npcap���ش���");
        return 0;
    }

    //��ȡ�豸�б�
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &all_devs, err_buff) == -1) {
        printErrorMsg("��ȡ�豸�б����");
        return 0;
    }

    //��ӡ�豸�б�
    int count_devs = 0;
    printf("----------��ȡ�����豸�б�----------\n");
    for (pcap_if_t* curr_dev = all_devs; curr_dev; curr_dev = curr_dev->next) {
        count_devs++;

        printf("%d, %s", count_devs, curr_dev->name);
        if (curr_dev->description) {
            printf(" (%s)\n", curr_dev->description);
        }
        else {
            printf(" (������)\n");
        }

        //��ȡ����豸��IP��ַ��Ϣ
        for (pcap_addr_t* curr_addr = curr_dev->addresses; curr_addr != NULL; curr_addr = curr_addr->next) {
            if (curr_addr->addr->sa_family == AF_INET) {
                char ip_char[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(((struct sockaddr_in*)curr_addr->addr)->sin_addr), ip_char, INET_ADDRSTRLEN);
                printf("\tIP��ַ: %s\n", ip_char);

                char netmask_char[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(((struct sockaddr_in*)curr_addr->netmask)->sin_addr), netmask_char, INET_ADDRSTRLEN);
                printf("\t��������: %s\n", netmask_char);
            }
        }
    }
    printf("\n");
    if (count_devs == 0) {
        printErrorMsg("û�в����豸��");
        return 0;
    }

    //ѡ���豸
    int dev_num;
    printf("----------ѡ���豸��----------\n");
    printf("�������豸�ı�ţ�");
    scanf_s("%d", &dev_num);
    if (dev_num < 1 || dev_num > count_devs) {
        printErrorMsg("�����ų��ޣ�");
        return 0;
    }
    pcap_if_t* my_dev = all_devs;
    pcap_t* my_dev_handle;
    for (int i = 0; i < dev_num - 1; i++) {
        my_dev = my_dev->next;
    }
    printf("\n");

    //��ѡ�����豸
    if ((my_dev_handle = pcap_open(my_dev->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 500, NULL, err_buff)) == NULL) {
        printErrorMsg("���豸ʧ�ܣ�");
        pcap_freealldevs(all_devs);
        return 0;
    }

    //��ȡ���ص�IP��ַ
    DWORD local_ip_dw[max_ip_number];
    int ip_number = 0;
    for (pcap_addr_t* curr_addr = my_dev->addresses; curr_addr != NULL; curr_addr = curr_addr->next) {
        if (curr_addr->addr->sa_family == AF_INET) {
            local_ip_dw[ip_number++] = inet_addr(inet_ntoa(((struct sockaddr_in*)(curr_addr->addr))->sin_addr));
        }
    }

    //��ȡ�豸����������
    u_int net_mask;
    if (my_dev->addresses != NULL) {
        net_mask = ((struct sockaddr_in*)(my_dev->addresses->netmask))->sin_addr.S_un.S_addr;
    }
    else {
        net_mask = 0xffffff;
    }

    //�����������ݰ�������
    struct bpf_program fcode;
    char packet_filter[] = "ip or arp";
    if (pcap_compile(my_dev_handle, &fcode, packet_filter, 1, net_mask) < 0) {
        printErrorMsg("���������ʧ�ܣ�");
        return 0;
    }

    //���ѱ���Ĺ��������豸����
    if (pcap_setfilter(my_dev_handle, &fcode) < 0) {
        printErrorMsg("����������ʧ�ܣ�");
        return 0;
    }

    //���񱾵ص�MAC��ַ
    
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
            printErrorMsg("ARP�������");
            return 0;
        }
        auto it = ip_mac_map.find(local_ip[i]);
        if (it != ip_mac_map.end()) {
            local_mac[i] = it->second;
        }
        else {
            printErrorMsg("��ȡ����mac��ַ����");
            return 0;
        }
    }
    /*printf("��ʼ���Ͳ���arp~~~~~~~~\n");
    send_getARP(&ip_mac_map, my_dev_handle, local_mac[0], local_ip[0], *string2ip("206.1.2.2"));*/

    for (int i = 0; i < ip_number; i++) {
        string mask = mask_int_to_str(net_mask);
        routing_table.insertEntry(ip2net(ip2string(local_ip[i]),mask), mask, "ֱ��Ͷ��");
    }

    //�ֶ����·�ɱ���
    printf("----------����·�ɱ�----------\n");
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
                printErrorMsg("ɾ��·�ɱ���ʧ�ܣ�");
            }
        }
        else if (command == "show") {
            routing_table.printEntries();
        }
        else {
            printErrorMsg("δʶ������");
        }
    }
    
    system("pause");

    //��ʼ�������ݰ�
    
    

    printf("\n��ʼ�������ݰ� ��%s��...\n", my_dev->description);
    struct pcap_pkthdr* pkt_header;
    const u_char* pkt_data;
    //string curr_fil = "";
    while (true) {
        //printf("while begin!!!\n");
  
        int rtn = pcap_next_ex(my_dev_handle, &pkt_header, &pkt_data);
        if (rtn == -1) {
            printErrorMsg("�������ݰ�ʱ��������");
            return 0;
        }
        else if (rtn == 0) {
            printErrorMsg("û�в������ݰ���\n");
            //return 0;
        }
        else {
            u_char* pkt_data_v = (u_char*)pkt_data;
            FrameHeader* frame_header = (FrameHeader*)pkt_data_v;
            IPHeader* ip_header = (IPHeader*)(pkt_data_v + 14);


            //�ж�����
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


            printf("\n��ӡ���ݰ���Ϣ��\n");
            printPktInfo(pkt_header, pkt_data_v);
            int length = pkt_header->len + sizeof(FrameHeader);
            string dest_ip = ip2string(ip_header->dest_addr);
            string next_hop, next_hop_mask;
            if (!routing_table.selectHop(dest_ip, &next_hop, &next_hop_mask)) {
                printErrorMsg("��ȡ��һ��ʧ�ܣ�\n");
                //return 0;
                continue;
            }
            printf("��ȡ����һ����IP��ַ��%s\n", next_hop.c_str());
            if (next_hop == "ֱ��Ͷ��") {
                next_hop = dest_ip;
            }
            IPAddress* next_hop_ip = string2ip(next_hop);

            //��һ���ĸ�IP��Ŀ��IPƥ��
            int target_index = -1;
            for (int i = 0; i < ip_number; i++) {
                if (isIPMatch(ip2string(local_ip[i]), next_hop, next_hop_mask)) {
                    target_index = i;
                    break;
                }
            }
            if (target_index == -1) {
                printErrorMsg("��ȡ����һ����IP��ַ�뱾������һ�������У�");
                return 0;
            }
            printf("ƥ�䵽��IP��ַ��%s\n", ip2string(local_ip[target_index]).c_str());
                 
            //��ȡMAC��ַ
            MACAddress dest_mac;
            auto it = ip_mac_map.find(*next_hop_ip);
            if (it != ip_mac_map.end()) {
                dest_mac = it->second;
            }
            else {
                send_getARP(&ip_mac_map, my_dev_handle, local_mac[target_index], local_ip[target_index], *next_hop_ip);
                auto it2 = ip_mac_map.find(*next_hop_ip);
                if (it2 == ip_mac_map.end()) {
                    printErrorMsg("��ȡMAC��ַ����");
                    //return 0;
                    continue;
                }
                else {
                    dest_mac = it2->second;
                }
                continue;
            }
            printf("��ȡMAC��ַ��ɣ�\n");

            //��װ���ݰ�������Ŀ��MAC��ַ
            for (int i = 0; i < 6; i++) {
                frame_header->dest_mac_address.bytes[i] = dest_mac.bytes[i];
                frame_header->source_mac_address.bytes[i] = local_mac[target_index].bytes[i];
            }
            printf("��װ���ݰ����!\n");
            printf("���ݰ���װ�����\n");
            printPktInfo(pkt_header, pkt_data_v);
            //�������ݱ�
            pcap_sendpacket(my_dev_handle, (u_char*)pkt_data_v, length);
            printf("�������ݱ����!\n");
        }
        //printf("while end!!!!!\n");
    }

    pcap_freealldevs(all_devs);
    system("pause");
    return 0;
}
