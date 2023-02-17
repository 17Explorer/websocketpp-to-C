#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "wss_client_api.h"

clientptr c_ptr; //定义一个客户端指针
//定义回调函数
void on_message(const char* const msg,const size_t len, const int id)
{
   printf("收到来自id%d的消息:\n", id);
   printf("消息内容为%s\n", msg);
}
void on_pong(const char* const msg,const size_t len,const int id)
{
   printf("收到来自id%d的pong\n", id);
   printf("消息附带信息为:%s", msg);
}
void on_ping(const char* const msg,const size_t len,const int id)
{
   printf("收到来自id%d的pong\n", id);
   printf("消息附带信息为:%s", msg);
}

void on_fail(const int id)
{
   printf("id%d--建立连接失败\n",id);
}

void on_open(const int id)
{
   printf("id%d--连接成功\n",id);
}

void on_close(const int id)
{
   printf("id%d--连接关闭\n",id);
}

int main()
{
   c_ptr = getclientptr(); //获取客户端指针
   char uri[] = "wss://170s2247n7.51mypc.cn/ws/cs/YK0122110001";
   char key[] = "Sec-WebSocket-Protocol"; //请求header
   char val[] = "ocpp1.6";
   ws_set_headers(c_ptr, key,strlen(key), val,strlen(val));           //设置请求headers
   ws_set_textMessage_callback(c_ptr, on_message); //设置收到消息时的回调函数
   ws_set_close_callback(c_ptr,on_close);
   ws_set_fail_callback(c_ptr,on_fail);
   ws_set_open_callback(c_ptr,on_open);
   ws_set_pong_callback(c_ptr, on_pong);       //设置收到pong时的回调函数
   ws_set_ping_callback(c_ptr, on_ping);       //设置收到ping时的回调函数

   int id = ws_connect(c_ptr, uri,strlen(uri)); //发起连接请求，返回一个id，有效的id为非负整数。

   char input[50];
   int done = 1;
   while (done)
   {
      printf("Enter Command:\n");
      scanf("%s", input);
      if (strncmp(input, "help", 4) == 0)
      {
         printf("Command List:\n"
                "send <message>\n"
                "close <connection id> [<close code:default=1000>] [<close reason>]\n"
                "help: Display this help text\n"
                "ping<payload>\n"
                "quit: Exit the program\n");
      }
      else if (strncmp(input, "send", 4) == 0)
      {
         input += 5;
         ws_send_text(c_ptr, id, input,strlen(input)-5);
         input -= 5;
      }
      else if (strncmp(input, "close", 5) == 0)
      {
         ws_close(c_ptr, id);
      }
      else if (strncmp(input, "ping", 4) == 0)
      {
         input += 5;
         ws_ping(c_ptr, id, input,strlen(input)-5);
         input -= 5;
      }
      else if (strncmp(input, "quit", 4) == 0)
      {
         done = 0;
         delete_clientptr(c_ptr);
      }
   }
   return 0;
}
