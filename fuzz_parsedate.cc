extern "C"
{
  #include <string.h>
  #include <curl/curl.h>
  #include <lib/parsedate.h>
}

// fuzz_target.cc

extern "C" int LLVMFuzzerTestOneInput(char *data, size_t size) {
  time_t output = 0;
  char date[100];
  size_t len = size >= 100 ? 99 : size;
  memcpy(date, data, len);
  date[len] = 0;
  Curl_getdate_capped(date);
  return 0;  // Values other than 0 and -1 are reserved for future use.
}
