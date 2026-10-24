/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <cstdio>
#include <cstdlib>

namespace {

void Expect(bool condition, const char *message) {
  if (!condition) {
    std::fprintf(stderr, "%s\n", message);
    std::exit(1);
  }
}

std::size_t CountAddresses(const addrinfo *address) {
  std::size_t count = 0;
  for (; address != nullptr; address = address->ai_next) {
    ++count;
  }
  return count;
}

void TestPositiveAddresses() {
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  addrinfo *result = nullptr;
  Expect(getaddrinfo("resolver-positive.test", "8080", &hints, &result) == 0,
         "positive shim lookup failed");
  Expect(CountAddresses(result) == 2,
         "positive shim lookup did not return two addresses");
  for (const addrinfo *address = result; address != nullptr;
       address = address->ai_next) {
    Expect(address->ai_family == AF_INET && address->ai_addr != nullptr,
           "positive shim returned a malformed IPv4 address");
    const auto *ipv4 = reinterpret_cast<const sockaddr_in *>(address->ai_addr);
    Expect(ntohs(ipv4->sin_port) == 8080,
           "positive shim did not preserve the service port");
  }
  freeaddrinfo(result);
}

void TestNegativeAndUnknownNames() {
  addrinfo *result = nullptr;
  Expect(getaddrinfo("resolver-negative.test", "80", nullptr, &result) ==
                 EAI_NONAME &&
             result == nullptr,
         "negative shim lookup was not authoritative");
  Expect(getaddrinfo("ambient.example", "80", nullptr, &result) == EAI_NONAME &&
             result == nullptr,
         "shim allowed an ambient hostname lookup");
}

void TestLinkLocalRetryShapes() {
  addrinfo hints{};
  hints.ai_family = AF_INET6;
  addrinfo *result = nullptr;
  Expect(getaddrinfo("resolver-link-local.test", "443", &hints, &result) == 0,
         "link-local IPv6 lookup failed");
  Expect(CountAddresses(result) == 1 && result->ai_family == AF_INET6,
         "link-local IPv6 lookup returned the wrong family set");
  const auto *ipv6 = reinterpret_cast<const sockaddr_in6 *>(result->ai_addr);
  Expect(IN6_IS_ADDR_LINKLOCAL(&ipv6->sin6_addr) && ipv6->sin6_scope_id == 0,
         "link-local lookup did not return a scope-less address");
  freeaddrinfo(result);

  hints.ai_family = AF_UNSPEC;
  result = nullptr;
  Expect(getaddrinfo("resolver-link-local.test", "443", &hints, &result) == 0,
         "link-local AF_UNSPEC retry failed");
  Expect(CountAddresses(result) == 2 && result->ai_family == AF_INET6 &&
             result->ai_next->ai_family == AF_INET,
         "link-local retry did not return IPv6 followed by IPv4");
  freeaddrinfo(result);
}

void TestPartialAddresses() {
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  addrinfo *result = nullptr;
  Expect(getaddrinfo("resolver-partial.test", "80", &hints, &result) == 0,
         "partial shim lookup failed");
  Expect(CountAddresses(result) == 4 && result->ai_family == AF_INET6 &&
             result->ai_next->ai_family == AF_INET6 &&
             result->ai_next->ai_next->ai_family == AF_INET,
         "partial shim lookup returned the wrong family order");
  freeaddrinfo(result);
}

} // namespace

int main() {
  TestPositiveAddresses();
  TestNegativeAndUnknownNames();
  TestLinkLocalRetryShapes();
  TestPartialAddresses();
  return 0;
}
