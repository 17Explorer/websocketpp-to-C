#define ASIO_STANDALONE

#ifndef WSS_CLIENT_H
#define WSS_CLIENT_H

#include <websocketpp/config/asio_client.hpp>
#include <websocketpp/client.hpp>
#include <websocketpp/common/thread.hpp>
#include <websocketpp/common/memory.hpp>

#include <map>
using namespace std;

typedef websocketpp::client<websocketpp::config::asio_tls_client> client;
typedef websocketpp::lib::shared_ptr<websocketpp::lib::asio::ssl::context> context_ptr;

using websocketpp::lib::bind;
using websocketpp::lib::placeholders::_1;
using websocketpp::lib::placeholders::_2;

bool verify_subject_alternative_name(const char *hostname, X509 *cert);
bool verify_common_name(char const *hostname, X509 *cert);
bool verify_certificate(const char *hostname, bool preverified, asio::ssl::verify_context &ctx);
context_ptr on_tls_init(const char *hostname, websocketpp::connection_hdl);

typedef void (*on_callback)(const char *const, const size_t, const int);
typedef void (*binary_callback)(const void *const, const size_t, const int);
typedef void (*on_connection)(const int);

class connection_metadata
{
public:
    on_callback ontextmsgfun;
    binary_callback onbinarymsgfun;
    on_callback onpingfun;
    on_callback onpongfun;
    on_connection onopenfun;
    on_connection onfailfun;
    on_connection onclosefun;

    char *msgbuffer;
    typedef websocketpp::lib::shared_ptr<connection_metadata> ptr;

    connection_metadata(int id, websocketpp::connection_hdl hdl, std::string uri, int bufsize,
                        on_callback textmsgfun, binary_callback binarymsgfun, on_callback pingfun, on_callback pongfun, on_connection openfun, on_connection failfun, on_connection closefun);

    void on_message(websocketpp::connection_hdl hdl, client::message_ptr msg);
    void on_open(client *c, websocketpp::connection_hdl hdl);
    void on_fail(client *c, websocketpp::connection_hdl hdl);
    void on_close(client *c, websocketpp::connection_hdl hdl);
    void on_ping(websocketpp::connection_hdl hdl, std::string payload);
    void on_pong(websocketpp::connection_hdl hdl, std::string payload);

    websocketpp::connection_hdl get_hdl() const;
    int get_id() const;
    std::string get_status() const;

    friend std::ostream &operator<<(std::ostream &out, connection_metadata const &data);

private:
    int buffersize;
    int m_id;
    websocketpp::connection_hdl m_hdl;
    std::string m_status;
    std::string m_uri;
    std::string m_server;
    std::string m_error_reason;
    std::vector<std::string> m_messages;
};

std::ostream &operator<<(std::ostream &out, connection_metadata const &data);

class websocket_endpoint
{
public:
    websocket_endpoint();
    ~websocket_endpoint();

    on_callback ontextmsg; //指向c语言定义的回调函数
    binary_callback onbinarymsg;
    on_callback onpong;
    on_callback onping;
    on_connection onopen;
    on_connection onfail;
    on_connection onclose;
    // void on_socket_init(websocketpp::connection_hdl hdl, asio::ssl::stream<asio::ip::tcp::socket> &socket);

    void set_headers(const string keyy, const string vall);
    void set_open_handler(on_connection openfun);
    void set_close_handler(on_connection closefun);
    void set_fail_handler(on_connection failfun);
    void set_binaryMessage_handler(binary_callback msgfun);
    void set_textMessage_handler(on_callback msgfun);
    void set_ping_handler(on_callback pingfun);
    void set_pong_handler(on_callback pongfun);
    void set_msgbuffer(int size);

    void getStatus(const int id, char *status);

    int connect(std::string const &uri);
    void close(int id, websocketpp::close::status::value code, std::string reason);
    void send_binary(const int id, void const *const payload, const size_t len);
    void send_text(const int id, const string message);
    void ping(int id, std::string const &payload);
    void pong(int id, std::string const &payload);
    void run();
    void stop();

    connection_metadata::ptr get_metadata(int id) const;

private:
    char *msgbuffer; //用于存放当前接收到的信息。
    string key;
    string val;
    int buffersize;
    typedef std::map<int, connection_metadata::ptr> con_list;
    client m_endpoint;
    websocketpp::lib::shared_ptr<websocketpp::lib::thread> m_thread;
    con_list m_connection_list;
    int m_next_id;
};
#endif // WSS_CLIENT_H