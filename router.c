#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include "queue.h"
#include "lib.h"
#include "protocols.h"


struct route_table_entry* rtable;
int rtable_len;

struct arp_entry* arp_table;
int arp_table_len = 0;

typedef struct trie_node {
    struct trie_node* child[2];
    struct route_table_entry* entry;
} trie_node_t;

/* Pentru a retine in coada pachetele, trebuie sa retinem
si interfata pe care le trimitem. De aceea, retinem intr-o
structura si interfata. */

typedef struct queue_buf {
    char buf[MAX_PACKET_LEN];
    int interface;
} queue_buf;

trie_node_t* new_node() {
    trie_node_t* elem = (trie_node_t*)malloc(sizeof(trie_node_t));
    if (elem) {
        elem->child[0] = NULL;
        elem->child[1] = NULL;
    }
    return elem;
}

// Complexitate temporala algoritm: O(log rtable_len).
void insert_trie(trie_node_t* root, struct route_table_entry* entry) {
    /*  Nu ne afecteaza faptul ca masca vine in Network Order. 
    Vrem sa aflam numarul de biti setati ai mastii. */  
    int len = 0;
    uint32_t mask = entry->mask;
    while (mask != 0) {
        len += mask & 1;
        mask >>= 1;
    }
    trie_node_t* elem = root;
    uint32_t prefix = ntohl(entry->prefix); // Convertim prefixul la Host Order.
    /* Tranversam prefixul de la root pana la nodul corespondent prefixului,
    Ultimul bit va fi bitul numarul len, unde len e lungimea mastii. 
    Acesta va fi frunza trie-ului nostru. */
    for (int i = 31; i >= 32 - len && elem != NULL; i--) {
        int bit = (prefix >> i) & 1; // Bitul numarul i din prefix.
        // Creez un nou nod daca bitul nu este parte din alti subarbori.
        if (!elem->child[bit]) 
            elem->child[bit] = new_node();
        // Ma deplasez catre copilul care match-uieste bitul curent al adresei.
        elem = elem->child[bit];
    }
    // Salvam ultimul entry, al frunzei.
    elem->entry = entry;
}

void free_node(trie_node_t* elem) {
    if (!elem) 
        return;
    if (elem->child[0]) 
        free_node(elem->child[0]);
    if (elem->child[1])
        free_node(elem->child[1]);
    if (elem->entry)
        free(elem->entry);
    free(elem);
}

struct route_table_entry* get_best_route_trie(trie_node_t* root, uint32_t ip_dest) {
    trie_node_t* elem = root;
    struct route_table_entry* entry = NULL;
    // Primim adresa IP a destinatiei in Network Order, deci o convertim in Host Order.
    uint32_t ip_dest_2 = ntohl(ip_dest);
    // Parcurgem de la bitul cel mai semnificativ 
    for (int i = 31; i >= 0; i--) {
        int bit = (ip_dest_2 >> i) & 1;
        if (elem->child[bit]) {
            elem = elem->child[bit];
            entry = elem->entry;
            }
    }
    return entry;
}

/* Functie ce ne returneaza ARP entry-ul corespondent ip-ului dat. 
Am preluat aceasta functie din laborator. */
struct arp_entry* get_arp_entry(uint32_t ip_dest)
{
    for (int i = 0; i < arp_table_len; i++) {
        // Cum tabela este sortată, primul match este prefixul ce mai specific 
        if (arp_table[i].ip == ip_dest) {
            return &(arp_table[i]);
        }
    }
    return NULL;
}


void arp_request(struct route_table_entry* best_route) {
    // Creez buffer pt. a retine pachetul pt. ARP request.
    char replybuf[MAX_PACKET_LEN];
    struct ether_header* eth_hdr = (struct ether_header*)replybuf;
    struct arp_header* arp_hdr = (struct arp_header*)(replybuf + sizeof(struct ether_header));
    size_t len = sizeof(struct ether_header) + sizeof(struct arp_header);
    int interface = best_route->interface;

    uint8_t mac[6];
    get_interface_mac(interface, mac);
    memcpy(eth_hdr->ether_shost, mac, 6);
    uint8_t broadcast[6] = {255, 255, 255, 255, 255, 255};
    memcpy(eth_hdr->ether_dhost, broadcast, 6);
    eth_hdr->ether_type = htons(0x0806);

    arp_hdr->hlen = 6;
    arp_hdr->plen = 4;
    arp_hdr->htype = htons(1); // Tipul adresei hardware este Ethernet
    arp_hdr->ptype = htons(0x0800);
    arp_hdr->op = htons(1); // Pachetul este un ARP request.

    /* sha = adresa MAC a router-ului care cere ARP request.
     (dorim sa trimitem in continuare pe best_route->interface). */
    memcpy(arp_hdr->sha, mac, 6);
    // Goala, deoarece inca nu avem MAC-ul cautat, de aceea intrebam broadcast-ul. 
    memset(arp_hdr->tha, 0, 6);

    /* Extragem adresa IP a sender-ului cu ajutorul functiei 
    date, insa e nevoie sa o convertim de la char* la uint32_t.
    Pentru acest lucru, folosim functia inet_aton, implementata in 
    biblioteca inet.h. */
    struct in_addr addr;
    inet_aton(get_interface_ip(best_route->interface), &(addr));
    arp_hdr->spa = addr.s_addr;
    // Target-ul nostru este urmatorul hop.
    arp_hdr->tpa = best_route->next_hop;
    send_to_link(interface, replybuf, len);
}

// Trimit ca argument arp_hdr pentru 
void arp_reply(int interface, char buf[]) {
    // Creez buffer pt. a retine pachetul pt. ARP reply.
    char replybuf[MAX_PACKET_LEN];
    size_t reply_len = sizeof(struct ether_header) + sizeof(struct arp_header);

    struct arp_header *arp_hdr = (struct arp_header*)(buf + sizeof(struct ether_header));

    // Incapsulam ARP reply-ul intr-un header Ethernet. Le vom construi pe amandoua:
    struct ether_header* eth_hdr_rply = (struct ether_header*)replybuf;
    struct arp_header* arp_hdr_rply = (struct arp_header*)(replybuf + sizeof(struct ether_header));

    uint8_t mac[6];
    get_interface_mac(interface, mac);

    /* Adresa sursa este adresa MAC de pe interfata pe care trimitem ARP reply.
    Adresa destinatie este adresa device-ului care a initiat ARP request, pe care
    o putem lua ori ca fiind eth_hdr->ether_shost, ori din campul arp_hdr->sha. */
    memcpy(eth_hdr_rply->ether_shost, mac, 6);
    memcpy(eth_hdr_rply->ether_dhost, arp_hdr->sha, 6);
    eth_hdr_rply->ether_type = htons(0x0806);

    arp_hdr_rply->hlen = 6;
    arp_hdr_rply->plen = 4;
    arp_hdr_rply->op = htons(2); // Pachetul este un ARP reply.
    arp_hdr_rply->htype = htons(1);
    arp_hdr_rply->ptype = htons(0x0800);

    // sha = Sender Hardware Address = adresa MAC a interfetei ce trimite ARP reply
    memcpy(arp_hdr_rply->sha, mac, 6);
    /* spa = Sender Protocol Address = adresa IP a interfetei ce trimite ARP reply */
    struct in_addr addr;
    inet_aton(get_interface_ip(interface), &(addr));
    arp_hdr_rply->spa = addr.s_addr;
    // tha = Target Hardware Address = adresa MAC ce a initiat ARP request = sha a ARP request-ului.
    memcpy(arp_hdr_rply->tha, arp_hdr->sha, 6);
    // tpa = Target Protocol Address = adresa IP ce a initiat ARP request = spa a ARP request-ului.
    arp_hdr_rply->tpa = arp_hdr->spa;
    // Trimitem ARP reply.
    send_to_link(interface, replybuf, reply_len);
}

void icmp_message(char buf[], int interface, int type){

    struct ether_header* eth_hdr = (struct ether_header*)buf;
    struct iphdr* ip_hdr = (struct iphdr*)(buf + sizeof(struct ether_header));
    struct icmphdr *icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

    uint8_t interface_mac[6];
	get_interface_mac(interface, interface_mac);
    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
    memcpy(eth_hdr->ether_shost, interface_mac, 6);

    uint32_t src = ip_hdr->saddr;
    uint32_t dest = ip_hdr->daddr;
    ip_hdr->saddr = dest;
    ip_hdr->daddr = src;

    ip_hdr->protocol = 1;
    ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
    ip_hdr->check = 0;
    ip_hdr->check = htons(checksum((uint16_t*)ip_hdr, sizeof(struct iphdr)));

    icmp_hdr->type = type;
    icmp_hdr->code = 0;
    icmp_hdr->checksum = 0;
    icmp_hdr->checksum = htons(checksum((uint16_t*)icmp_hdr, sizeof(struct icmphdr)));

    size_t len =  sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
    send_to_link(interface, buf, len);
}

int main(int argc, char* argv[])
{
    char buf[MAX_PACKET_LEN];

    // Do not modify this line
    init(argc - 2, argv + 2);

    rtable = malloc(sizeof(struct route_table_entry) * 100000);
    rtable_len = read_rtable(argv[1], rtable);

    arp_table = malloc(sizeof(struct arp_entry) * 1001);

    /* Coada pachetelor pe care nu le putem dirija, deoarece nu se gaseste
    adresa in cache-ul ARP. Pachetul va fi trimis mai tarziu, dupa sosirea
    raspunsului ARP. */
    queue q = queue_create();

    trie_node_t* root = new_node();

    // Adaugam tabela in trie.
    for (int i = 0; i < rtable_len; i++) {
        insert_trie(root, &rtable[i]);
    }
    
    while (1) {

        int interface;
        size_t len;

        printf("hello\n");
        interface = recv_from_any_link(buf, &len);
        
        DIE(interface < 0, "recv_from_any_links");

        struct ether_header* eth_hdr = (struct ether_header*)buf;
        struct iphdr* ip_hdr = (struct iphdr*)(buf + sizeof(struct ether_header));
        struct arp_header* arp_hdr = (struct arp_header*)(buf + sizeof(struct ether_header));
        // Implementare protocol IP
        if (eth_hdr->ether_type == htons(0x0800)) {
            // Testare ARP static:
            //arp_table_len = parse_arp_table("arp_table_initial.txt", arp_table);

            struct in_addr addr;
            inet_aton(get_interface_ip(interface), &(addr));
            uint32_t get_ip = addr.s_addr;
            uint32_t network_ip_dest = ip_hdr->daddr;

            /* Deoarece si routerul este o entitate de retea,
            verificam daca pachetul este destinat chiar lui insusi. Aceasta
            verificare se poate face si prin verificarea type-ului din ICMP,
            de tip request (type = 8). Raspundem cu un mesaj ICMP echo reply.
            (type = 0). */
            if(get_ip == network_ip_dest){
                // ICMP Echo Reply.
                icmp_message(buf, interface, 0);
                continue;
            }

            uint16_t check_aux = ip_hdr->check;
            ip_hdr->check = 0;


            if (checksum((uint16_t*)ip_hdr, sizeof(*ip_hdr)) != ntohs(check_aux)) {
                continue;
            }

            if (ip_hdr->ttl <= 1) {
                icmp_message(buf, interface, 11);
                continue;
            }
            ip_hdr->ttl--;


            struct route_table_entry *best_route = get_best_route_trie(root, ip_hdr->daddr);
            // printf("%08x /n", best_route->prefix);
            if (best_route == NULL) {
                icmp_message(buf, interface, 3);
                continue;
            }

            ip_hdr->check = 0;
            ip_hdr->check = htons(checksum((uint16_t*)ip_hdr, sizeof(*ip_hdr)));

            // Cautam o intrare ARP pentru urmatorul hop gasit prin best_route.
            struct arp_entry* arp_entry = get_arp_entry(best_route->next_hop);

            /* Daca adresa necesara nu se gaseste in cache ARP, 
            realizam interogare ARP si adaugam pachetul intr-o coada pe care 
            o vom folosi in procesul ARP. Motivul pentru care folosim acest proces este
            ca dorim sa primim si alte pachete intre timp. */
            if (arp_entry == NULL) {
                // Stocam in elementul nostru buf-ul si interfata actuala. Len-ul il vom lua direct din buf.
                queue_buf* elem = (queue_buf*)malloc(sizeof(queue_buf));
                memcpy(elem->buf, buf, len);
                elem->interface = best_route->interface;
                queue_enq(q, elem);
                // Generam ARP request.
                arp_request(best_route);
                continue;
            }
            else {
                // Daca avem un ARP entry, trimitem pachetul. 
                uint8_t mac[6];
                get_interface_mac(best_route->interface, mac);
                memcpy(eth_hdr->ether_shost, mac, 6);
                memcpy(eth_hdr->ether_dhost, arp_entry->mac, 6);
                send_to_link(best_route->interface, buf, len);
            }
        }
        // Protocol ARP
        else if (eth_hdr->ether_type == htons(0x0806)) {
            // Daca am ARP REQUEST, trimit un ARP reply cu adresa MAC a interfetei sursa.
            if (arp_hdr->op == htons(1)) {
                //printf("Hellohgkjfgdhgdsgdsgd\n");
                arp_reply(interface, buf);
                continue;
            }
            else {
                // ARP REPLY => Actualizam tabela ARP si eliminam pachete 
                arp_table[arp_table_len].ip = arp_hdr->spa;
                memcpy(arp_table[arp_table_len++].mac, arp_hdr->sha, 6);

                // Procesul de dirijare pachete
                while (queue_empty(q) != 1) {
                    // Extragem din coada
                    queue_buf* elem = queue_deq(q);
                    struct ether_header* eth_hdr_q = (struct ether_header*)elem->buf;
                    struct iphdr* ip_hdr_q = (struct iphdr*)(elem->buf + sizeof(struct ether_header));
                   /* printf("D: %.8x\n", ip_hdr_m->daddr);
                    printf("S: %.8x\n", ip_hdr_m->saddr);
                    printf("next_hop: %.8x\n", m->interface);
                    printf("%.8x\n", ip_hdr_m->protocol);
                    printf("%.8x\n", ip_hdr_m->ttl);*/

                    struct route_table_entry* best_route = get_best_route_trie(root, ip_hdr_q->daddr);
                    struct arp_entry* arp_entry = get_arp_entry(best_route->next_hop);

                    /* Daca, intre timp, primim prin ARP reply o adresa MAC pentru next_hop a
                     adresei pachetului nostru, inseamna ca putem scapa de acesta si il trimitem pe interfata. */
                    if(arp_entry != NULL){
                        uint8_t mac[6];
                        get_interface_mac(elem->interface, mac);
                        memcpy(eth_hdr_q->ether_shost, mac, 6);
                        memcpy(eth_hdr_q->ether_dhost, arp_entry->mac, 6);
                        send_to_link(elem->interface, elem->buf, len);
                        free(elem);
                    }
                    // Altfel, adaugam pachetul la loc in coada si continuam procesul.
                    else{
                        queue_enq(q, elem);
            
                    }
                }

            }
        }
    }
    // Eliberam memoria
    free(rtable);
    free(arp_table);
    free_node(root);
    return 0;
}





