#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
/* You will to add includes here */
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <map>
#include <iostream>
#include <netdb.h>
/* You will to add includes here */

// Included to get the support library
#include "calcLib.h"

#include "protocol.h"

#define DNS_SERVER_PORT 53
#define DNS_SERVER_IP "114.114.114.114"

#define DNS_HOST 0x01
#define DNS_CNAME 0x05

using std::cout;
using std::endl;
using std::map;
using std::string;

struct dns_header
{

  unsigned short id;    // 会话标识
  unsigned short flags; // 标志

  unsigned short questions; // 问题数
  unsigned short answer;    // 回答 资源记录数

  unsigned short authority;  // 授权 资源记录数
  unsigned short additional; // 附加 资源记录数
};

struct dns_queries
{

  int length;
  unsigned short qtype;
  unsigned short qclass;
  unsigned char *name;
};

struct dns_item
{

  char *domain;
  char *ip;
};

// client sendto dns server

int dns_create_header(struct dns_header *header)
{

  if (header == NULL)
    return -1;
  memset(header, 0, sizeof(struct dns_header));

  // random
  srandom(time(NULL));
  header->id = random();

  header->flags = htons(0x0100); // 转化成网络字节序
  header->questions = htons(1);
}

// hostname:  www.baidu.com

// name:		3www5baidu3com0

int dns_create_queries(struct dns_queries *question, const char *hostname)
{

  if (question == NULL || hostname == NULL)
    return -1;
  memset(question, 0, sizeof(struct dns_queries));

  question->name = (unsigned char *)malloc(strlen(hostname) + 2);
  if (question->name == NULL)
  {
    return -2;
  }

  question->length = strlen(hostname) + 2;

  question->qtype = htons(1);
  question->qclass = htons(1);

  const char delim[2] = ".";
  char *qname = (char *)question->name;

  char *hostname_dup = strdup(hostname); // strdup -->malloc
  char *token = strtok(hostname_dup, delim);

  while (token != NULL)
  {

    size_t len = strlen(token);

    *qname = len;
    qname++;

    strncpy(qname, token, len + 1);
    qname += len;

    token = strtok(NULL, delim);
  }

  free(hostname_dup);
}

int dns_build_request(struct dns_header *header, struct dns_queries *question, char *request, int rlen)
{

  if (header == NULL || question == NULL || request == NULL)
    return -1;

  int offset = 0;

  memset(request, 0, rlen);

  memcpy(request, header, sizeof(struct dns_header));
  offset = sizeof(struct dns_header);

  memcpy(request + offset, question->name, question->length);
  offset += question->length;

  memcpy(request + offset, &question->qtype, sizeof(question->qtype));
  offset += sizeof(question->qtype);

  memcpy(request + offset, &question->qclass, sizeof(question->qclass));
  offset += sizeof(question->qclass);

  return offset;
}

static int is_pointer(int in)
{
  return ((in & 0xC0) == 0xC0);
}

static void dns_parse_name(unsigned char *chunk, unsigned char *ptr, char *out, int *len)
{

  int flag = 0, n = 0, alen = 0;
  char *pos = out + (*len);

  while (1)
  {

    flag = (int)ptr[0];
    if (flag == 0)
      break;

    if (is_pointer(flag))
    {

      n = (int)ptr[1];
      ptr = chunk + n;
      dns_parse_name(chunk, ptr, out, len);
      break;
    }
    else
    {

      ptr++;
      memcpy(pos, ptr, flag);
      pos += flag;
      ptr += flag;

      *len += flag;
      if ((int)ptr[0] != 0)
      {
        memcpy(pos, ".", 1);
        pos += 1;
        (*len) += 1;
      }
    }
  }
}

static int dns_parse_response(char *buffer, struct dns_item **domains)
{

  int i = 0;
  unsigned char *ptr = (unsigned char *)buffer;

  ptr += 4;
  int querys = ntohs(*(unsigned short *)ptr);

  ptr += 2;
  int answers = ntohs(*(unsigned short *)ptr);

  ptr += 6;
  for (i = 0; i < querys; i++)
  {
    while (1)
    {
      int flag = (int)ptr[0];
      ptr += (flag + 1);

      if (flag == 0)
        break;
    }
    ptr += 4;
  }

  char cname[128], aname[128], ip[20], netip[4];
  int len, type, ttl, datalen;

  int cnt = 0;
  struct dns_item *list = (struct dns_item *)calloc(answers, sizeof(struct dns_item));
  if (list == NULL)
  {
    return -1;
  }

  for (i = 0; i < answers; i++)
  {

    bzero(aname, sizeof(aname));
    len = 0;

    dns_parse_name((unsigned char *)buffer, ptr, aname, &len);
    ptr += 2;

    type = htons(*(unsigned short *)ptr);
    ptr += 4;

    ttl = htons(*(unsigned short *)ptr);
    ptr += 4;

    datalen = ntohs(*(unsigned short *)ptr);
    ptr += 2;

    if (type == DNS_CNAME)
    {

      bzero(cname, sizeof(cname));
      len = 0;
      dns_parse_name((unsigned char *)buffer, ptr, cname, &len);
      ptr += datalen;
    }
    else if (type == DNS_HOST)
    {

      bzero(ip, sizeof(ip));

      if (datalen == 4)
      {
        memcpy(netip, ptr, datalen);
        inet_ntop(AF_INET, netip, ip, sizeof(struct sockaddr));

        printf("%s has address %s\n", aname, ip);
        printf("\tTime to live: %d minutes , %d seconds\n", ttl / 60, ttl % 60);

        list[cnt].domain = (char *)calloc(strlen(aname) + 1, 1);
        memcpy(list[cnt].domain, aname, strlen(aname));

        list[cnt].ip = (char *)calloc(strlen(ip) + 1, 1);
        memcpy(list[cnt].ip, ip, strlen(ip));

        cnt++;
      }

      ptr += datalen;
    }
  }

  *domains = list;
  ptr += 2;

  return cnt;
}

char *dns_client_commit(const char *domain)
{

  int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd < 0)
  {
    return NULL;
  }

  struct sockaddr_in servaddr = {0};
  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(DNS_SERVER_PORT);
  servaddr.sin_addr.s_addr = inet_addr(DNS_SERVER_IP);

  int ret = connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr));
  // printf("cooect: %d\n", ret);

  struct dns_header header = {0};
  dns_create_header(&header);

  struct dns_queries question = {0};
  dns_create_queries(&question, domain);

  char request[1024] = {0};
  int length = dns_build_request(&header, &question, request, 1024);

  // request
  int slen = sendto(sockfd, request, length, 0, (struct sockaddr *)&servaddr, sizeof(struct sockaddr));

  // recvfrom
  char response[1024] = {0};
  struct sockaddr_in addr = {0};
  size_t addr_len = sizeof(struct sockaddr_in);

  int n = recvfrom(sockfd, response, sizeof(response), 0, (struct sockaddr *)&addr, (socklen_t *)&addr_len);

  // printf("recvfrom: %d,%s\n", n, response);

  struct dns_item *dns_domain = NULL;
  dns_parse_response(response, &dns_domain);
  if (dns_domain->ip == NULL)
  {
    return (char *)domain;
  }

  free(dns_domain);
  return dns_domain->ip;

  // return n;
}

typedef unsigned char byte;
// transform from calcMessage to the byte array
void swap_byteArray(byte *array, int offset, int endset)
{
  while (offset < endset)
  {
    byte temp = array[offset];
    array[offset] = array[endset];
    array[endset] = temp;
    offset++;
    endset--;
  }
}

void calcMessage_to_byteArray(calcMessage message, byte *temp)
{
  int offset = 1; // the actual filling location
  temp[0] = 0;
  memcpy(temp + 1, &message.type, 1);
  // copy the messsage info
  offset = offset + 4;
  for (int i = 2; i < offset; i++)
  {
    temp[i] = 0;
  }
  memcpy(temp + offset, &message.message, 1);
  // copy the protocol info
  offset = offset + 2;
  temp[offset - 1] = 0;
  memcpy(temp + offset, &message.protocol, 1);
  // copy the major version
  offset = offset + 2;
  temp[offset - 1] = 0;
  memcpy(temp + offset, &message.major_version, 1);
  // copy the minor version
  offset = offset + 2;
  temp[offset - 1] = 0;
  memcpy(temp + offset, &message.minor_version, 1);
}

void calcProtocol_to_byteArray(calcProtocol protocol, byte *array)
{
  // 2,2,2,4,4,4,4,4,8,8,8
  memcpy(array, &protocol.type, 2);
  swap_byteArray(array, 0, 1);

  memcpy(array + 2, &protocol.major_version, 2);
  swap_byteArray(array, 2, 3);

  memcpy(array + 4, &protocol.minor_version, 2);
  swap_byteArray(array, 4, 5);

  memcpy(array + 6, &protocol.id, 4);
  swap_byteArray(array, 6, 9);

  memcpy(array + 10, &protocol.arith, 4);
  swap_byteArray(array, 10, 13);

  memcpy(array + 14, &protocol.inValue1, 4);
  swap_byteArray(array, 14, 17);

  memcpy(array + 18, &protocol.inValue2, 4);
  swap_byteArray(array, 18, 21);

  memcpy(array + 22, &protocol.inResult, 4);
  swap_byteArray(array, 22, 25);

  // for the float value,no need to swap the byte order
  memcpy(array + 26, &protocol.flValue1, 8);
  // swap_byteArray(array,26,33);

  memcpy(array + 34, &protocol.flValue2, 8);
  // swap_byteArray(array,34,41);

  memcpy(array + 42, &protocol.flResult, 8);
  // swap_byteArray(array,42,49);
}

void interpret_calcProtocol(calcProtocol &protocol, byte *array)
{
  // 2,2,2,4,4,4,4,4,8,8,8
  // type transform swap,notice the litter endian transform
  // type
  swap_byteArray(array, 0, 1);
  memcpy(&protocol.type, array, 2);

  // major_version
  swap_byteArray(array, 2, 3);
  memcpy(&protocol.major_version, array + 2, 2);

  // minor_version
  swap_byteArray(array, 4, 5);
  memcpy(&protocol.minor_version, array + 4, 2);

  // id
  swap_byteArray(array, 6, 9);
  memcpy(&protocol.id, array + 6, 4);

  // arith
  swap_byteArray(array, 10, 13);
  memcpy(&protocol.arith, array + 10, 4);

  // inValue1
  swap_byteArray(array, 14, 17);
  memcpy(&protocol.inValue1, array + 14, 4);

  // inValue2
  swap_byteArray(array, 18, 21);
  memcpy(&protocol.inValue2, array + 18, 4);

  // inResult
  swap_byteArray(array, 22, 25);
  memcpy(&protocol.inResult, array + 22, 4);

  // flValue1
  // swap_byteArray(array, 26, 33);
  memcpy(&protocol.flValue1, array + 26, 8);

  // flValue2
  // swap_byteArray(array, 34, 41);
  memcpy(&protocol.flValue2, array + 34, 8);

  // flResult
  // swap_byteArray(array, 42, 49);
  memcpy(&protocol.flResult, array + 42, 8);
}

void interpret_calcMessage(calcMessage &message, byte *array)
{
  swap_byteArray(array, 0, 1);
  memcpy(&message.type, array, 2);

  swap_byteArray(array, 2, 5);
  memcpy(&message.message, array + 2, 4);

  swap_byteArray(array, 6, 7);
  memcpy(&message.protocol, array + 6, 2);

  swap_byteArray(array, 8, 9);
  memcpy(&message.major_version, array + 8, 2);

  swap_byteArray(array, 10, 11);
  memcpy(&message.minor_version, array + 10, 2);
}

int main(int argc, char *argv[])
{
#define DEBUG
  /* Do magic */
  setbuf(stdout, NULL);
  char delim[] = ":";
  char *Desthost = strtok(argv[1], delim);
  char *Destport = strtok(NULL, delim);
  // *Desthost now points to a sting holding whatever came before the delimiter, ':'.
  // *Dstport points to whatever string came after the delimiter.

  /* Do magic */
  int port = atoi(Destport);
#ifdef DEBUG
  printf("Host %s, and port %d.\n", Desthost, port);
#endif
  // DNS parse
  char *ip = dns_client_commit(Desthost);
  cout << "Connected to " << ip << ":" << port;
  // the former is to output the host and port
  // begin to connect to the server and continue the task
  int socket_id;             // the socket id
  struct sockaddr_in server; // the server struct
  socklen_t server_len = sizeof(server);
  memset(&server, 0, sizeof(server)); // init the server
  // create the socket using udp protocol
  if ((socket_id = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
  {
    printf("create socket failed:%s\n", strerror(errno));
    return 1;
  }
  // assign the server
  server.sin_family = AF_INET;
  server.sin_port = htons(port);
  server.sin_addr.s_addr = inet_addr(ip);

  // 绑定本地IP地址和端口号
  sockaddr_in client_addr{};
  client_addr.sin_family = AF_INET;
  client_addr.sin_addr.s_addr = htonl(INADDR_ANY); // 绑定所有IP地址
  client_addr.sin_port = htons(0);                 // 随机选择一个本地端口号
  bind(socket_id, (sockaddr *)&client_addr, sizeof(client_addr));

  // 获取绑定的本地端口号
  sockaddr_in addr{};
  socklen_t addrlen = sizeof(addr);
  getsockname(socket_id, (sockaddr *)&client_addr, &addrlen);

  cout << " local 127.0.0.1:" << client_addr.sin_port << endl;
  // printf("the client tries to connect the server...\n");
  // socklen_t addrlen = sizeof(server);
  // if (getsockname(socket_id, reinterpret_cast<sockaddr *>(&server), &addrlen) == -1)
  // {
  //   perror("getsockname error");
  //   close(socket_id);
  //   return 1;
  // }

  // cout << "Local port: " << ntohs(server.sin_port) << endl;
  // begin to connect
  if (connect(socket_id, (struct sockaddr *)&server, sizeof(server)) < 0)
  {
    printf("connect failed!\n");
    return 1;
  }
  printf("connect success!\n");

  // begin to start the task
  // byte sendbf[1024]; // sed buffer to sed data to server
  byte recvbf[1024]; // receive buffer to get data from server
  // memset(sendbf, '\0', 1024);
  memset(recvbf, '\0', 1024);

  // 1.first sed,client->server calcmessage(type,message,protocol,major_version,minor_version)
  calcMessage first_calcMessage;
  first_calcMessage.type = 22;
  first_calcMessage.message = 0;
  first_calcMessage.protocol = 17;
  first_calcMessage.major_version = 1;
  first_calcMessage.minor_version = 0;

  byte first_byte_calcMessage[12];
  calcMessage_to_byteArray(first_calcMessage, first_byte_calcMessage);
  // sendto(socket_id, first_byte_calcMessage, 12, 0, (sockaddr *)&server, server_len);
  //  set the timer and control the timeout
  /* 设置阻塞超时 */
  struct timeval timeOut;
  timeOut.tv_sec = 2; // 设置2s超时
  timeOut.tv_usec = 0;
  if (setsockopt(socket_id, SOL_SOCKET, SO_RCVTIMEO, &timeOut, sizeof(timeOut)) < 0)
  {
    printf("time out setting failed\n");
  }
  /* 数据阻塞接收 */
  // 2.first receive the calcProtocol
  int first_recv_len = 0;
  // int receivePacketLen = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&svr_addr, &addrLen);
  int first_times = 1;
  while (first_times < 4)
  {
    sendto(socket_id, first_byte_calcMessage, 12, 0, (sockaddr *)&server, server_len);
    first_recv_len = recvfrom(socket_id, recvbf, 1024, 0, (sockaddr *)&server, &server_len);
    if (first_recv_len == -1 && errno == EAGAIN) // 阻塞接收超时
    {
      if (first_times == 3)
      {
        printf("first_send_error:receive failed:%s\n", strerror(errno));
        close(socket_id);
        return 0; // exit the program
      }
      printf("first_times_send:%d---timeout, no input!\n", first_times);
      first_times++;
    }
    else
    {
      break;
    }
  }

  // printf("received_len:%d\n",first_recv_len);
  // printf("protocol---recvbf:%d %d\n",recvbf[0],recvbf[1]);
  if (first_recv_len < 50)
  {
    printf("the server sed the NOT OK message!");
    return 0;
  }

  // 3.interpret the assignment from server
  calcProtocol protocol;
  interpret_calcProtocol(protocol, recvbf); // transform the byte array to protocol struct
  // define the operation mapping
  map<int, string> operation_map;
  operation_map[1] = "add";
  operation_map[2] = "sub";
  operation_map[3] = "mul";
  operation_map[4] = "div";
  operation_map[5] = "fadd";
  operation_map[6] = "fsub";
  operation_map[7] = "fmul";
  operation_map[8] = "fdiv";
  // 4.second sed the interpreted assignment
  // printf("protocol.type: %d\n",protocol.type);
  // printf("protocol.major_version:%d\n",protocol.major_version);
  // printf("protocol.arith: %d\n",protocol.arith);
  // 4.1 calculate the result
  calcProtocol second_sendto_protocol;
  // printf("size of protocol:%ld\n",sizeof(second_sendto_protocol));
  second_sendto_protocol.type = 2;
  second_sendto_protocol.major_version = 1;
  second_sendto_protocol.minor_version = 0;
  second_sendto_protocol.id = protocol.id;
  second_sendto_protocol.arith = protocol.arith;
  second_sendto_protocol.inValue1 = protocol.inValue1;
  second_sendto_protocol.inValue2 = protocol.inValue2;
  second_sendto_protocol.inResult = protocol.inResult;
  second_sendto_protocol.flValue1 = protocol.flValue1;
  second_sendto_protocol.flValue2 = protocol.flValue2;
  second_sendto_protocol.flResult = protocol.flResult;
  // bool is_correct = false;
  switch (protocol.arith)
  {
  case 1:
    second_sendto_protocol.inResult = protocol.inValue1 + protocol.inValue2;
    break;
  case 2:
    second_sendto_protocol.inResult = protocol.inValue1 - protocol.inValue2;
    break;
  case 3:
    second_sendto_protocol.inResult = protocol.inValue1 * protocol.inValue2;
    break;
  case 4:
    second_sendto_protocol.inResult = protocol.inValue1 / protocol.inValue2;
    break;
  case 5:
    second_sendto_protocol.flResult = protocol.flValue1 + protocol.flValue2;
    break;
  case 6:
    second_sendto_protocol.flResult = protocol.flValue1 - protocol.flValue2;
    break;
  case 7:
    second_sendto_protocol.flResult = protocol.flValue1 * protocol.flValue2;
    break;
  case 8:
    second_sendto_protocol.flResult = protocol.flValue1 / protocol.flValue2;
    break;
  }
  string arith = operation_map[protocol.arith];
  char myresult[20];
  if (arith.length() == 3)
  {
    printf("Assignment: %s %d %d\n", operation_map[protocol.arith].c_str(), protocol.inValue1, protocol.inValue2);
    printf("Calculated the result to %d\n", second_sendto_protocol.inResult);
    sprintf(myresult, "(myresult=%d)\n", second_sendto_protocol.inResult);
    // sprintf((char *)sedbf, "%s %d %d", operation_map[protocol.arith].c_str(), protocol.inValue1, protocol.inValue2);
  }
  else
  {
    printf("Assignment: %s %8.8g %8.8g\n", operation_map[protocol.arith].c_str(), protocol.flValue1, protocol.flValue2);
    printf("Calculated the result to %8.8g\n", second_sendto_protocol.flResult);
    sprintf(myresult, "(myresult=%8.8g)\n", second_sendto_protocol.flResult);
    // sprintf((char *)sedbf, "%s %8.8g %8.8g", operation_map[protocol.arith].c_str(), protocol.flValue1, protocol.flValue2);
  }
  // if (is_correct)
  // {
  //   second_message.message = 1;
  // }
  // else
  // {
  //   second_message.message = 2;
  // }
  // second_message.protocol = 17;
  // second_message.major_version = 1;
  // second_message.minor_version = 0;
  // calcMessage_to_byteArray(second_message,second_calcMessage_array);
  // printf("the second_protocol is:%d,%d,%d,%d,%d,%d,%d,%d,%8.8g,%8.8g,%8.8g,\n",second_sendto_protocol.type,
  // second_sendto_protocol.major_version,second_sendto_protocol.minor_version,
  // second_sendto_protocol.id,second_sendto_protocol.arith,second_sendto_protocol.inValue1,second_sendto_protocol.inValue2,
  // second_sendto_protocol.inResult,second_sendto_protocol.flValue1,second_sendto_protocol.flValue2,second_sendto_protocol.flResult);
  byte second_calcProtocol_array[50];
  calcProtocol_to_byteArray(second_sendto_protocol, second_calcProtocol_array);
  //

  // 5.second receive the control calculation correctness
  memset(recvbf, (int)'\0', 1024); // clear the recvbf
  // int second_recv_len = recvfrom(socket_id, recvbf, 1024, 0, (sockaddr *)&server, &server_len);
  int second_times = 1;
  while (second_times < 4)
  {
    sendto(socket_id, second_calcProtocol_array, 50, 0, (sockaddr *)&server, server_len);
    memset(recvbf, (int)'\0', 1024); // clear the recvbf
    int second_recv_len = recvfrom(socket_id, recvbf, 1024, 0, (sockaddr *)&server, &server_len);
    if (second_recv_len == -1 && errno == EAGAIN) // 阻塞接收超时
    {
      if (second_times == 3)
      {
        printf("second__send_error:receive failed:%s\n", strerror(errno));
        close(socket_id);
        return 0; // exit the program
      }
      printf("second_times_send:%d---timeout, no input!\n", second_times);
      second_times++;
    }
    else
    {
      break;
    }
  }
  // printf("second_recv_len:%d\n", second_recv_len);
  // printf("messge:----%d\n",recvbf[5]);
  calcMessage second_recv_calcMessage;
  interpret_calcMessage(second_recv_calcMessage, recvbf);
  // printf("second_calcMessage is:%d,%d,%d,%d,%d\n", second_recv_calcMessage.type,second_recv_calcMessage.message,second_recv_calcMessage.protocol,second_recv_calcMessage.major_version,second_recv_calcMessage.minor_version);
  // printf("second_calcMessage.message:%d\n", second_recv_calcMessage.message);
  switch (second_recv_calcMessage.message)
  {
  case 1:
    printf("OK %s\n", myresult);
    break;
  case 2:
    printf("NOT OK\n");
    break;
  case 0:
    printf("Not applicable\n");
    break;
  }
  close(socket_id);
}
