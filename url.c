#include <curl/urlapi.h>
#include <stdio.h>
#include <yara/modules.h>

#define MODULE_NAME url



unsigned int FLAGS = CURLU_URLDECODE | CURLU_DEFAULT_SCHEME | CURLU_DEFAULT_PORT;


int yr_re_match_curlupart(CURLU *url, CURLUPart curl_part, YR_SCAN_CONTEXT* context, RE* regexp) {
  int result = 0;
  char *url_part;
  curl_url_get(url, curl_part, &url_part, FLAGS);

  if (yr_re_match(context, regexp, url_part) > 0)
  {
    result = 1;
  }

  curl_free(url_part);
  return result;
}


define_function(scheme) {
  int result = yr_re_match_curlupart(module()->data, CURLUPART_SCHEME, scan_context(), regexp_argument(1));
  return_integer(result);
}

define_function(user) {
  int result = yr_re_match_curlupart(module()->data, CURLUPART_USER, scan_context(), regexp_argument(1));
  return_integer(result);
}

define_function(password) {
  int result = yr_re_match_curlupart(module()->data, CURLUPART_PASSWORD, scan_context(), regexp_argument(1));
  return_integer(result);
}

define_function(options) {
  int result = yr_re_match_curlupart(module()->data, CURLUPART_OPTIONS, scan_context(), regexp_argument(1));
  return_integer(result);
}

define_function(host) {
  int result = yr_re_match_curlupart(module()->data, CURLUPART_HOST, scan_context(), regexp_argument(1));
  return_integer(result);
}

define_function(port) {
  int result = yr_re_match_curlupart(module()->data, CURLUPART_PORT, scan_context(), regexp_argument(1));
  return_integer(result);
}

define_function(path) {
  int result = yr_re_match_curlupart(module()->data, CURLUPART_PATH, scan_context(), regexp_argument(1));
  return_integer(result);
}

define_function(query) {
  int result = yr_re_match_curlupart(module()->data, CURLUPART_QUERY, scan_context(), regexp_argument(1));
  return_integer(result);
}

define_function(fragment) {
  int result = yr_re_match_curlupart(module()->data, CURLUPART_FRAGMENT, scan_context(), regexp_argument(1));
  return_integer(result);
}

define_function(zoneid) {
  int result = yr_re_match_curlupart(module()->data, CURLUPART_ZONEID, scan_context(), regexp_argument(1));
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
  CURLU *url;

  url = curl_url();
  if (!url)
    return -1;

  YR_MEMORY_BLOCK* block = first_memory_block(context);
  const char* block_data = (char *)block->fetch_data(block);

  uc = curl_url_set(url, CURLUPART_URL, block_data, 0);
  if (uc)
    return -1;

  char *url_part;

  curl_url_get(url, CURLUPART_SCHEME, &url_part, FLAGS);
  if (url_part)
    set_string(url_part, module_object, "scheme");

  curl_url_get(url, CURLUPART_USER, &url_part, FLAGS);
  if (url_part)
    set_string(url_part, module_object, "user");

  curl_url_get(url, CURLUPART_PASSWORD, &url_part, FLAGS);
  if (url_part)
    set_string(url_part, module_object, "password");

  curl_url_get(url, CURLUPART_OPTIONS, &url_part, FLAGS);
  if (url_part)
    set_string(url_part, module_object, "options");

  curl_url_get(url, CURLUPART_HOST, &url_part, FLAGS);
  if (url_part)
    set_string(url_part, module_object, "host");

  curl_url_get(url, CURLUPART_PORT, &url_part, FLAGS);
  if (url_part)
    set_string(url_part, module_object, "port");

  curl_url_get(url, CURLUPART_PATH, &url_part, FLAGS);
  if (url_part)
    set_string(url_part, module_object, "path");

  curl_url_get(url, CURLUPART_QUERY, &url_part, FLAGS);
  if (url_part)
    set_string(url_part, module_object, "query");

  curl_url_get(url, CURLUPART_FRAGMENT, &url_part, FLAGS);
  if (url_part)
    set_string(url_part, module_object, "fragment");

  curl_url_get(url, CURLUPART_ZONEID, &url_part, FLAGS);
  if (url_part)
    set_string(url_part, module_object, "zoneid");

  curl_free(url_part);

  module_object->data = url;

  return ERROR_SUCCESS;
}


int module_unload(YR_OBJECT* module_object) {
  curl_url_cleanup(module_object->data);
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