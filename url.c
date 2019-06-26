#include <curl/urlapi.h>
#include <stdio.h>
#include <yara/mem.h>
#include <yara/modules.h>

#define MODULE_NAME url



unsigned int FLAGS = CURLU_URLDECODE | CURLU_DEFAULT_SCHEME | CURLU_DEFAULT_PORT;

typedef struct {
  char* scheme;
  char* user;
  char* password;
  char* options;
  char* host;
  char* port;
  char* path;
  char* query;
  char* fragment;
  char* zoneid;
} URLParts;

int yr_re_match_curlupart(char* url_part, YR_SCAN_CONTEXT* context, RE* regexp) {
  int result = 0;

  if (yr_re_match(context, regexp, url_part) > 0)
  {
    result = 1;
  }

  return result;
}

define_function(scheme) {
  URLParts* url_parts_ptr = module()->data;
  int result = yr_re_match_curlupart(url_parts_ptr->scheme, scan_context(), regexp_argument(1));
  return_integer(result);
}

define_function(user) {
  URLParts* url_parts_ptr = module()->data;
  int result = yr_re_match_curlupart(url_parts_ptr->user, scan_context(), regexp_argument(1));
  return_integer(result);
}

define_function(password) {
  URLParts* url_parts_ptr = module()->data;
  int result = yr_re_match_curlupart(url_parts_ptr->password, scan_context(), regexp_argument(1));
  return_integer(result);
}

define_function(options) {
  URLParts* url_parts_ptr = module()->data;
  int result = yr_re_match_curlupart(url_parts_ptr->options, scan_context(), regexp_argument(1));
  return_integer(result);
}

define_function(host) {
  URLParts* url_parts_ptr = module()->data;
  int result = yr_re_match_curlupart(url_parts_ptr->host, scan_context(), regexp_argument(1));
  return_integer(result);
}

define_function(port) {
  URLParts* url_parts_ptr = module()->data;
  int result = yr_re_match_curlupart(url_parts_ptr->port, scan_context(), regexp_argument(1));
  return_integer(result);
}

define_function(path) {
  URLParts* url_parts_ptr = module()->data;
  int result = yr_re_match_curlupart(url_parts_ptr->path, scan_context(), regexp_argument(1));
  return_integer(result);
}

define_function(query) {
  URLParts* url_parts_ptr = module()->data;
  int result = yr_re_match_curlupart(url_parts_ptr->query, scan_context(), regexp_argument(1));
  return_integer(result);
}

define_function(fragment) {
  URLParts* url_parts_ptr = module()->data;
  int result = yr_re_match_curlupart(url_parts_ptr->fragment, scan_context(), regexp_argument(1));
  return_integer(result);
}

define_function(zoneid) {
  URLParts* url_parts_ptr = module()->data;
  int result = yr_re_match_curlupart(url_parts_ptr->zoneid, scan_context(), regexp_argument(1));
  return_integer(result);
}


begin_declarations;

  declare_string("scheme");
  declare_string("user");
  declare_string("password");
  declare_string("options");
  declare_string("host");
  declare_string("port");
  declare_string("path");
  declare_string("query");
  declare_string("fragment");
  declare_string("zoneid");

  begin_struct("match");

    declare_function("scheme", "r", "i", scheme);
    declare_function("user", "r", "i", user);
    declare_function("password", "r", "i", password);
    declare_function("options", "r", "i", options);
    declare_function("host", "r", "i", host);
    declare_function("port", "r", "i", port);
    declare_function("path", "r", "i", path);
    declare_function("query", "r", "i", query);
    declare_function("fragment", "r", "i", fragment);
    declare_function("zoneid", "r", "i", zoneid);

  end_struct("match");

end_declarations;


int module_initialize(YR_MODULE* module) {
  return ERROR_SUCCESS;
}

int module_finalize(YR_MODULE* module) {
  return ERROR_SUCCESS;
}

int module_load(YR_SCAN_CONTEXT* context, YR_OBJECT* module_object, void* module_data, size_t module_data_size) {
  CURLUcode uc;
  CURLU* url;
  URLParts* url_parts_ptr = yr_malloc(sizeof(URLParts));

  url = curl_url();
  if (!url)
    return -1;

  YR_MEMORY_BLOCK* block = first_memory_block(context);
  const char* block_data = (char *)block->fetch_data(block);

  uc = curl_url_set(url, CURLUPART_URL, block_data, 0);
  if (uc)
    return -1;

  uc = curl_url_get(url, CURLUPART_SCHEME, &url_parts_ptr->scheme, FLAGS);
  if (!uc)
    set_string(url_parts_ptr->scheme, module_object, "scheme");

  uc = curl_url_get(url, CURLUPART_USER, &url_parts_ptr->user, FLAGS);
  if (!uc)
    set_string(url_parts_ptr->user, module_object, "user");

  uc = curl_url_get(url, CURLUPART_PASSWORD, &url_parts_ptr->password, FLAGS);
  if (!uc)
    set_string(url_parts_ptr->password, module_object, "password");

  uc = curl_url_get(url, CURLUPART_HOST, &url_parts_ptr->host, FLAGS);
  if (!uc)
    set_string(url_parts_ptr->host, module_object, "host");

  uc = curl_url_get(url, CURLUPART_PORT, &url_parts_ptr->port, FLAGS);
  if (!uc)
    set_string(url_parts_ptr->port, module_object, "port");

  uc = curl_url_get(url, CURLUPART_PATH, &url_parts_ptr->path, FLAGS);
  if (!uc)
    set_string(url_parts_ptr->path, module_object, "path");

  uc = curl_url_get(url, CURLUPART_QUERY, &url_parts_ptr->query, FLAGS);
  if (!uc)
    set_string(url_parts_ptr->query, module_object, "query");

  uc = curl_url_get(url, CURLUPART_FRAGMENT, &url_parts_ptr->fragment, FLAGS);
  if (!uc)
    set_string(url_parts_ptr->fragment, module_object, "fragment");

  uc = curl_url_get(url, CURLUPART_ZONEID, &url_parts_ptr->zoneid, FLAGS);
  if (!uc)
    set_string(url_parts_ptr->zoneid, module_object, "zoneid");

  curl_url_cleanup(url);
  module_object->data = url_parts_ptr;

  return ERROR_SUCCESS;
}

int module_unload(YR_OBJECT* module_object) {
  URLParts* url_parts_ptr = module_object->data;
  curl_free(url_parts_ptr->scheme);
  curl_free(url_parts_ptr->user);
  curl_free(url_parts_ptr->password);
  curl_free(url_parts_ptr->options);
  curl_free(url_parts_ptr->host);
  curl_free(url_parts_ptr->port);
  curl_free(url_parts_ptr->path);
  curl_free(url_parts_ptr->query);
  curl_free(url_parts_ptr->fragment);
  curl_free(url_parts_ptr->zoneid);
  yr_free(url_parts_ptr);
  return ERROR_SUCCESS;
}


/*

configure.ac needs:

AC_ARG_ENABLE([url],
  [AS_HELP_STRING([--enable-url], [enable url module])],
  [if test x$enableval = xyes; then
    build_url_module=true
    AC_CHECK_HEADERS([curl/urlapi.h],,
      AC_MSG_ERROR([url module requires libcurl >= 7.62.0]))
    AC_CHECK_LIB(curl, curl_url,,
      AC_MSG_ERROR([url module requires libcurl >= 7.62.0]))
    CFLAGS="$CFLAGS -DURL_MODULE"
    PC_REQUIRES_PRIVATE="$PC_REQUIRES_PRIVATE curl"
  fi])

*/