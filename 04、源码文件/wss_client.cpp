#include <cstdlib>
#include <iostream>
#include <string>
#include <sstream>
#include "wss_client.h"

bool verify_subject_alternative_name(const char *hostname, X509 *cert)
{
    STACK_OF(GENERAL_NAME) *san_names = NULL;
    san_names = (STACK_OF(GENERAL_NAME) *)X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (san_names == NULL)
    {
        return false;
    }
    int san_names_count = sk_GENERAL_NAME_num(san_names);
    bool result = false;
    for (int i = 0; i < san_names_count; i++)
    {
        const GENERAL_NAME *current_name = sk_GENERAL_NAME_value(san_names, i);
        if (current_name->type != GEN_DNS)
        {
            continue;
        }
        char const *dns_name = (char const *)ASN1_STRING_get0_data(current_name->d.dNSName);
        if (ASN1_STRING_length(current_name->d.dNSName) != strlen(dns_name))
        {
            break;
        }
        result = (strcasecmp(hostname, dns_name) == 0);
    }

    sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);

    return result;
}

bool verify_common_name(char const *hostname, X509 *cert)
{
    int common_name_loc = X509_NAME_get_index_by_NID(X509_get_subject_name(cert), NID_commonName, -1);
    if (common_name_loc < 0)
    {
        return false;
    }
    X509_NAME_ENTRY *common_name_entry = X509_NAME_get_entry(X509_get_subject_name(cert), common_name_loc);
    if (common_name_entry == NULL)
    {
        return false;
    }
    ASN1_STRING *common_name_asn1 = X509_NAME_ENTRY_get_data(common_name_entry);
    if (common_name_asn1 == NULL)
    {
        return false;
    }
    char const *common_name_str = (char const *)ASN1_STRING_get0_data(common_name_asn1);

    if (ASN1_STRING_length(common_name_asn1) != strlen(common_name_str))
    {
        return false;
    }
    return (strcasecmp(hostname, common_name_str) == 0);
}

bool verify_certificate(const char *hostname, bool preverified, asio::ssl::verify_context &ctx)
{

    int depth = X509_STORE_CTX_get_error_depth(ctx.native_handle());

    if (depth == 0 && preverified)
    {
        X509 *cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());

        if (verify_subject_alternative_name(hostname, cert))
        {
            return true;
        }
        else if (verify_common_name(hostname, cert))
        {
            return true;
        }
        else
        {
            return false;
        }
    }
    return preverified;
}

context_ptr on_tls_init(const char *hostname, websocketpp::connection_hdl hdl)
{

    context_ptr ctx = websocketpp::lib::make_shared<asio::ssl::context>(asio::ssl::context::tlsv12);
    try
    {
        ctx->set_options(asio::ssl::context::default_workarounds |
                         asio::ssl::context::no_sslv2 |
                         asio::ssl::context::no_sslv3 |
                         asio::ssl::context::single_dh_use);
        //    ctx->set_verify_mode(asio::ssl::verify_peer);
        ctx->set_verify_mode(asio::ssl::verify_none);
        // ctx->set_verify_callback(bind(&verify_certificate, hostname, ::_1, ::_2));
        // ctx->load_verify_file("ca.pem");
    }
    catch (std::exception &e)
    {
        std::cout << e.what() << std::endl;
    }
    return ctx;
}

connection_metadata::connection_metadata(int id, websocketpp::connection_hdl hdl, std::string uri, int bufsize, on_callback textmsgfun, binary_callback binarymsgfun,
                                         on_callback pingfun, on_callback pongfun, on_connection openfun, on_connection failfun, on_connection closefun) : m_id(id), m_hdl(hdl),
                                                                                                                                                           m_status("Connecting"), m_uri(uri), m_server("N/A"), buffersize(bufsize), ontextmsgfun(textmsgfun), onbinarymsgfun(binarymsgfun), onpingfun(pingfun), onpongfun(pongfun),
                                                                                                                                                           onopenfun(openfun), onfailfun(failfun), onclosefun(closefun)
{
    msgbuffer = (char *)malloc(buffersize);
}

void connection_metadata::on_message(websocketpp::connection_hdl hdl, client::message_ptr msg)
{
    if (msg->get_opcode() == websocketpp::frame::opcode::text)
    {
        if (ontextmsgfun)
        {
            string tmpmsg = msg->get_payload();
            strcpy(msgbuffer, tmpmsg.c_str());
            ontextmsgfun(msgbuffer,tmpmsg.size(),m_id);
        }
        else
        {
            cout << "Callback function not created" << endl;
        }
    }
    else
    {
        if (onbinarymsgfun)
        {
            string tmpmsg = websocketpp::utility::to_hex(msg->get_payload());
            strcpy(msgbuffer, tmpmsg.c_str());
            onbinarymsgfun(msgbuffer, tmpmsg.size(),m_id);
        }
        else
        {
            cout << "Callback function not created" << endl;
        }
    }
}

void connection_metadata::on_open(client *c, websocketpp::connection_hdl hdl)
{
    m_status = "Open";
    client::connection_ptr con = c->get_con_from_hdl(hdl);
    m_server = con->get_response_header("Server");
    if (onopenfun)
        onopenfun(m_id);
    // cout<<"连接成功,触发on_open"<<endl;
}

void connection_metadata::on_fail(client *c, websocketpp::connection_hdl hdl)
{
    m_status = "Failed";
    client::connection_ptr con = c->get_con_from_hdl(hdl);
    m_server = con->get_response_header("Server");
    m_error_reason = con->get_ec().message();
    if (onfailfun)
        onfailfun(m_id);
    // cout<<"连接失败,触发on_fail"<<endl;
}

void connection_metadata::on_close(client *c, websocketpp::connection_hdl hdl)
{
    m_status = "Closed";
    // cout<<"触发on_close"<<endl;
    client::connection_ptr con = c->get_con_from_hdl(hdl);
    std::stringstream s;
    s << "close code: " << con->get_remote_close_code() << " ("
      << websocketpp::close::status::get_string(con->get_remote_close_code())
      << "), close reason: " << con->get_remote_close_reason();
    m_error_reason = s.str();
    if (onclosefun)
        onclosefun(m_id);
}

void connection_metadata::on_ping(websocketpp::connection_hdl hdl, std::string payload)
{
    std::cout << "id-" << m_id << "Received a ping message" << payload << std::endl;
    strcpy(msgbuffer, payload.c_str());
    if (onpingfun)
    {
        onpingfun(msgbuffer, payload.size(), m_id);
    }
}

void connection_metadata::on_pong(websocketpp::connection_hdl hdl, std::string payload)
{
    std::cout << "id-" << m_id << "Received a pong message" << payload << std::endl;
    strcpy(msgbuffer, payload.c_str());
    if (onpongfun)
    {
        onpongfun(msgbuffer, payload.size(), m_id);
    }
}

websocketpp::connection_hdl connection_metadata::get_hdl() const
{
    return m_hdl;
}

int connection_metadata::get_id() const
{
    return m_id;
}

std::string connection_metadata::get_status() const
{
    return m_status;
}

std::ostream &operator<<(std::ostream &out, connection_metadata const &data)
{
    out << "> URI: " << data.m_uri << "\n"
        << "> Status: " << data.m_status << "\n"
        << "> Remote Server: " << (data.m_server.empty() ? "None Specified" : data.m_server) << "\n"
        << "> Error/close reason: " << (data.m_error_reason.empty() ? "N/A" : data.m_error_reason) << "\n";
    out << "> Messages Processed: (" << data.m_messages.size() << ") \n";
    std::vector<std::string>::const_iterator it;
    for (it = data.m_messages.begin(); it != data.m_messages.end(); ++it)
    {
        out << *it << "\n";
    }
    return out;
}

void websocket_endpoint ::run()
{
    m_endpoint.run();
}

void websocket_endpoint ::stop()
{
    m_endpoint.stop();
}

websocket_endpoint ::websocket_endpoint() : m_next_id(0), buffersize(500)
{
    m_endpoint.set_access_channels(websocketpp::log::alevel::all);
    m_endpoint.clear_access_channels(websocketpp::log::alevel::frame_payload);
    m_endpoint.set_error_channels(websocketpp::log::elevel::all);
    m_endpoint.init_asio();
    m_endpoint.start_perpetual();
    m_thread = websocketpp::lib::make_shared<websocketpp::lib::thread>(&client::run, &m_endpoint);
}

websocket_endpoint ::~websocket_endpoint()
{
    m_endpoint.stop_perpetual();
    for (con_list::const_iterator it = m_connection_list.begin(); it != m_connection_list.end(); ++it)
    {
        if (it->second->get_status() != "Open")
        {
            continue;
        }
        std::cout << "> Closing connection " << it->second->get_id() << std::endl;
        websocketpp::lib::error_code ec;
        m_endpoint.close(it->second->get_hdl(), websocketpp::close::status::going_away, "", ec);
        if (ec)
        {
            std::cout << "> Error closing connection " << it->second->get_id() << ": "
                      << ec.message() << std::endl;
        }
    }
    m_thread->join();
}

void websocket_endpoint ::set_msgbuffer(int size)
{
    buffersize = size;
}

void websocket_endpoint ::set_binaryMessage_handler(binary_callback msgfun)
{
    onbinarymsg = msgfun;
}

void websocket_endpoint ::set_textMessage_handler(on_callback msgfun)
{
    ontextmsg = msgfun;
}
void websocket_endpoint ::set_ping_handler(on_callback pingfun)
{
    onping = pingfun;
}
void websocket_endpoint ::set_pong_handler(on_callback pongfun)
{
    onpong = pongfun;
}

void websocket_endpoint::set_open_handler(on_connection openfun)
{
    onopen = openfun;
}

void websocket_endpoint::set_close_handler(on_connection closefun)
{
    onclose = closefun;
}

void websocket_endpoint::set_fail_handler(on_connection failfun)
{
    onfail = failfun;
}

/*
void websocket_endpoint::on_socket_init(websocketpp::connection_hdl hdl, asio::ssl::stream<asio::ip::tcp::socket> &socket)
{
    client::connection_ptr conn = m_endpoint.get_con_from_hdl(hdl);

    string key="Sec-WebSocket-Protocol";
    string val="ocpp1.6";
    conn->append_header(key, val);
    asio::ip::tcp::no_delay option(true);
    //?crash socket.set_option(option);
}
*/

void websocket_endpoint ::set_headers(const string keyy, const string vall)
{
    key = keyy;
    val = vall;
}

void websocket_endpoint ::getStatus(const int id, char *status)
{
    con_list::const_iterator metadata_it = m_connection_list.find(id);
    if (metadata_it == m_connection_list.end())
    {
        cout << "No connection found with id" << endl;
        return;
    }
    else
    {
        string statuss = metadata_it->second->get_status();
        strcpy(status, statuss.c_str());
    }
}

int websocket_endpoint ::connect(std::string const &uri)
{
    websocketpp::lib::error_code ec;
    string hostname;
    int i = 6;
    while (uri[i] != '/' && uri[i] != ':')
    {
        hostname += uri[i++];
    }
    m_endpoint.set_tls_init_handler(bind(&on_tls_init, hostname.c_str(), ::_1));
    client::connection_ptr con = m_endpoint.get_connection(uri, ec);
    asio::ip::tcp::no_delay option(true);
    if (ec)
    {
        std::cout << "> Connect initialization error: " << ec.message();
        return -1;
    }
    con->append_header(key, val);

    int new_id = m_next_id++;
    connection_metadata::ptr metadata_ptr = websocketpp::lib::make_shared<connection_metadata>(new_id, con->get_handle(),
                                                                                               uri, buffersize, ontextmsg, onbinarymsg, onping, onpong, onopen, onfail, onclose);
    m_connection_list[new_id] = metadata_ptr;
    con->set_open_handler(websocketpp::lib::bind(
        &connection_metadata::on_open,
        metadata_ptr,
        &m_endpoint,
        websocketpp::lib::placeholders::_1));
    con->set_fail_handler(websocketpp::lib::bind(
        &connection_metadata::on_fail,
        metadata_ptr,
        &m_endpoint,
        websocketpp::lib::placeholders::_1));
    con->set_close_handler(websocketpp::lib::bind(
        &connection_metadata::on_close,
        metadata_ptr,
        &m_endpoint,
        websocketpp::lib::placeholders::_1));
    con->set_pong_handler(websocketpp::lib::bind(
        &connection_metadata::on_pong,
        metadata_ptr,
        websocketpp::lib::placeholders::_1,
        websocketpp::lib::placeholders::_2));
    con->set_message_handler(websocketpp::lib::bind(
        &connection_metadata::on_message,
        metadata_ptr,
        websocketpp::lib::placeholders::_1,
        websocketpp::lib::placeholders::_2));
    m_endpoint.connect(con);
    return new_id;
}

void websocket_endpoint ::close(int id, websocketpp::close::status::value code, std::string reason)
{
    websocketpp::lib::error_code ec;
    con_list::iterator metadata_it = m_connection_list.find(id);
    if (metadata_it == m_connection_list.end())
    {
        std::cout << "> No connection found with id " << id << std::endl;
        return;
    }
    m_endpoint.close(metadata_it->second->get_hdl(), code, reason, ec);
    if (ec)
    {
        std::cout << "> Error initiating close: " << ec.message() << std::endl;
    }
    else
    {
        m_connection_list.erase(id);
    }
}

void websocket_endpoint ::send_text(const int id, const string message)
{
    websocketpp::lib::error_code ec;
    con_list::iterator metadata_it = m_connection_list.find(id);
    if (metadata_it == m_connection_list.end())
    {
        std::cout << "> No connection found with id " << id << std::endl;
        return;
    }
   
    m_endpoint.send(metadata_it->second->get_hdl(), message, websocketpp::frame::opcode::text, ec);
    if (ec)
    {
        std::cout << "> Error sending message: " << ec.message() << std::endl;
        return;
    }
}

void websocket_endpoint ::send_binary(const int id, const void *const payload, const size_t len)
{
    websocketpp::lib::error_code ec;
    con_list::iterator metadata_it = m_connection_list.find(id);
    if (metadata_it == m_connection_list.end())
    {
        std::cout << "> No connection found with id " << id << std::endl;
        return;
    }
    std::cout<<"sending binary message"<<std::endl;
    m_endpoint.send(metadata_it->second->get_hdl(), payload, len, websocketpp::frame::opcode::binary, ec);
    if (ec)
    {
        std::cout << "> Error sending message: " << ec.message() << std::endl;
        return;
    }
}

void websocket_endpoint ::ping(int id, std::string const &payload)
{
    websocketpp::lib::error_code ec;
    con_list::iterator metadata_it = m_connection_list.find(id);
    if (metadata_it == m_connection_list.end())
    {
        std::cout << "> No connection found with id " << id << std::endl;
        return;
    }
    m_endpoint.ping(metadata_it->second->get_hdl(), payload, ec);
    if (ec)
    {
        std::cout << "> Error ping message: " << ec.message() << std::endl;
        return;
    }
}

void websocket_endpoint ::pong(int id, std::string const &payload)
{
    websocketpp::lib::error_code ec;
    con_list::iterator metadata_it = m_connection_list.find(id);
    if (metadata_it == m_connection_list.end())
    {
        std::cout << "> No connection found with id " << id << std::endl;
        return;
    }
    m_endpoint.pong(metadata_it->second->get_hdl(), payload, ec);
    if (ec)
    {
        std::cout << "> Error pong message: " << ec.message() << std::endl;
        return;
    }
}

connection_metadata::ptr websocket_endpoint ::get_metadata(int id) const
{
    con_list::const_iterator metadata_it = m_connection_list.find(id);
    if (metadata_it == m_connection_list.end())
    {
        return connection_metadata::ptr();
    }
    else
    {
        return metadata_it->second;
    }
}
