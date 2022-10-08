extern "C"
{
    #include <stdlib.h>
    #include <signal.h>
    #include <string.h>
    #include <unistd.h>
    #include <curl/curl.h>
    #include <cassert>

    char *curl_escape(const char *string, int inlength);
}

// fuzz_target.cc

extern "C" int LLVMFuzzerTestOneInput(char *data, size_t size) {
  if(size == 0) return 0;
  char* terminated_data = (char *)malloc(size+1);
  memcpy(terminated_data, data, size);
  terminated_data[size] = '\0';

  int output_len;
  char *input = (char *)malloc(size);
  memcpy(input, terminated_data, size);

  char *escaped = curl_easy_escape(NULL, input, size);
  char *unescaped = curl_easy_unescape(NULL, escaped, 0, &output_len);
  assert(size == output_len);
  assert(memcmp(unescaped, terminated_data, size) == 0);

  free(terminated_data);
  free(input);
  curl_free(escaped);
  curl_free(unescaped);
  return 0;  // Values other than 0 and -1 are reserved for future use.
}
