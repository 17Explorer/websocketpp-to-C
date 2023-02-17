#include <iostream>
#include <stdio.h>
#include <string>

#include "wss_client.h"
#include "wss_client_api.h"

using namespace std;
#ifdef __cplusplus
extern "C"
{
#endif
    /*ws_client代表一个客户端类，因c语言中没有类，所以用结构体代替，c语言定义客户端对象时，通过getclientptr()获取一个实际对象指针，send、ping、pong等操作
    都要通过这个对象指针来实现*/
    struct ws_client
    {
        websocket_endpoint *endpointptr;
    };
    typedef struct ws_client *clientptr;

    clientptr getclientptr()
    {
        clientptr reptr = (clientptr)malloc(sizeof(struct ws_client));
        reptr->endpointptr = new websocket_endpoint();
        return reptr;
    }
    /*删除客户端指针*/
    void delete_clientptr(clientptr c_ptr)
    {
        delete c_ptr->endpointptr;
        free(c_ptr);
    }

    void ws_getStatus(clientptr c_ptr, const int id, char *status)
    {
        c_ptr->endpointptr->getStatus(id, status);
    }
    /*建立连接*/
    int ws_connect(clientptr c_ptr, const char *uri, const int len)
    {
        string uris;
        int i = 0;
        while (i < len)
        {
            uris += uri[i++];
        }
        int id = c_ptr->endpointptr->connect(uris);
        return id;
    }

    void ws_close(clientptr c_ptr, const int id)
    {
        int close_code = websocketpp::close::status::normal;
        std::string reason;
        c_ptr->endpointptr->close(id, close_code, reason);
    }

    void ws_send_text(clientptr c_ptr, const int id, const char *const str, const size_t len)
    {
        string message;
        int i = 0;
        message=str;
        c_ptr->endpointptr->send_text(id, message);
    }

    void ws_send_binary(clientptr c_ptr, const int id, const void *const str, const size_t len)
    {
        c_ptr->endpointptr->send_binary(id, str, len);
    }

    void ws_ping(clientptr c_ptr, const int id, const char *const payload, const size_t len)
    {
        string ppayload;
        int i = 0;
        while (i < len)
        {
            ppayload += payload[i++];
        }
        c_ptr->endpointptr->ping(id, ppayload);
    }

    void ws_pong(clientptr c_ptr, const int id, const char *const payload, const size_t len)
    {
        string ppayload;
        int i = 0;
        while (i < len)
        {
            ppayload += payload[i++];
        }
        c_ptr->endpointptr->pong(id, ppayload);
    }

    void ws_set_headers(clientptr c_ptr, const char *const key, const size_t lenk, const char *const val, const size_t lenv)
    {
        string keyy;
        string vall;
        int i = 0;
        while (i < lenk)
        {
            keyy += key[i++];
        }
        i = 0;
        while (i < lenv)
        {
            vall += val[i++];
        }
        c_ptr->endpointptr->set_headers(keyy, vall);
    }

    void ws_set_binaryMessage_callback(clientptr c_ptr, binary_callback msgfun)
    {
        c_ptr->endpointptr->set_binaryMessage_handler(msgfun);
    }

    void ws_set_textMessage_callback(clientptr c_ptr, callback msgfun)
    {
        c_ptr->endpointptr->set_textMessage_handler(msgfun);
    }

    void ws_set_ping_callback(clientptr c_ptr, callback pingfun)
    {
        c_ptr->endpointptr->set_ping_handler(pingfun);
    }

    void ws_set_pong_callback(clientptr c_ptr, callback pongfun)
    {
        c_ptr->endpointptr->set_pong_handler(pongfun);
    }

    void ws_set_open_callback(clientptr c_ptr, connectCallback openfun)
    {
        c_ptr->endpointptr->set_open_handler(openfun);
    }
    void ws_set_close_callback(clientptr c_ptr, connectCallback closefun)
    {
        c_ptr->endpointptr->set_close_handler(closefun);
    }

    void ws_set_fail_callback(clientptr c_ptr, connectCallback failfun)
    {
        c_ptr->endpointptr->set_fail_handler(failfun);
    }

    void ws_set_msgbuffersize(clientptr c_ptr, const size_t size)
    {
        c_ptr->endpointptr->set_msgbuffer(size);
    }

    void ws_run(clientptr c_ptr)
    {
        c_ptr->endpointptr->run();
    }

    void ws_stop(clientptr c_ptr)
    {
        c_ptr->endpointptr->stop();
    }

#ifdef __cplusplus
}
#endif