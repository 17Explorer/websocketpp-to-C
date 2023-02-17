#ifndef WSS_CLIENT_API_H
#define WSS_CLIENT_API_H

#include <stddef.h>
#ifdef __cplusplus

extern "C"
{
#endif

  typedef void (*callback)(const char *const, const size_t, const int);
  typedef void (*binary_callback)(const void *const, const size_t, const int);
  typedef void (*connectCallback)(const int);

  struct ws_client;

  typedef struct ws_client *clientptr;

  clientptr getclientptr();

  void delete_clientptr(clientptr c_ptr);

  void ws_getStatus(clientptr c_ptr, const int id, char *status);

  int ws_connect(clientptr c_ptr, const char *const uri, const int len);

  void ws_close(clientptr c_ptr, const int id);

  void ws_send_text(clientptr c_ptr, const int id, const char *const str, const size_t len);

  void ws_send_binary(clientptr c_ptr, const int id, const void *const str, const size_t len);

  void ws_ping(clientptr c_ptr, const int id, const char *const payload, const size_t len);

  void ws_pong(clientptr c_ptr, const int id, const char *const payload, const size_t len);

  void ws_set_headers(clientptr c_ptr, const char *const key, const size_t lenk, const char *const val, const size_t lenv);

  void ws_set_binaryMessage_callback(clientptr c_ptr, binary_callback msgfun);

  void ws_set_textMessage_callback(clientptr c_ptr, callback msgfun);

  void ws_set_ping_callback(clientptr c_ptr, callback pingfun);

  void ws_set_pong_callback(clientptr c_ptr, callback pongfun);

  void ws_set_open_callback(clientptr c_ptr, connectCallback openfun);

  void ws_set_close_callback(clientptr c_ptr, connectCallback closefun);

  void ws_set_fail_callback(clientptr c_ptr, connectCallback failfun);

  void ws_set_msgbuffersize(clientptr c_ptr, const size_t size);

  void ws_run(clientptr c_ptr);

  void ws_stop(clientptr c_ptr);

#ifdef __cplusplus
}
#endif

#endif // WSS_CLIENT_API_H
