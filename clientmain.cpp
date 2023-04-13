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
/* You will to add includes here */

// Included to get the support library
#include "calcLib.h"

#include "protocol.h"
using std::map;
using std::string;

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
  server.sin_addr.s_addr = inet_addr(Desthost);

  // printf("the client tries to connect the server...\n");

  // begin to connect
  if (connect(socket_id, (struct sockaddr *)&server, sizeof(server)) < 0)
  {
    printf("connect failed!\n");
    return 1;
  }

  // begin to start the task
  //byte sendbf[1024]; // sed buffer to sed data to server
  byte recvbf[1024]; // receive buffer to get data from server
  //memset(sendbf, '\0', 1024);
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
        printf("first_error:receive failed:%s\n", strerror(errno));
        close(socket_id);
        return 0; // exit the program
      }
      printf("first_times:%d---timeout, no input!\n", first_times);
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
  string arith = operation_map[protocol.arith];
  if (arith.length() == 3)
  {
    printf("Assignment: %s %d %d\n", operation_map[protocol.arith].c_str(), protocol.inValue1, protocol.inValue2);
    // sprintf((char *)sedbf, "%s %d %d", operation_map[protocol.arith].c_str(), protocol.inValue1, protocol.inValue2);
  }
  else
  {
    printf("Assignment: %s %8.8g %8.8g\n", operation_map[protocol.arith].c_str(), protocol.flValue1, protocol.flValue2);
    // sprintf((char *)sedbf, "%s %8.8g %8.8g", operation_map[protocol.arith].c_str(), protocol.flValue1, protocol.flValue2);
  }
  // 4.1 calculate the result
  calcProtocol second_sendto_protocol;
  // printf("size of protocol:%ld\n",sizeof(second_sendto_protocol));
  second_sendto_protocol.type = 22;
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
        printf("second_error:receive failed:%s\n", strerror(errno));
        close(socket_id);
        return 0; // exit the program
      }
      printf("second_times:%d---timeout, no input!\n", second_times);
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
    printf("OK\n");
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
