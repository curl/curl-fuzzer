/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

/// @file
/// @brief Target-local deterministic getaddrinfo backend for resolver fuzzing.

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <thread>

namespace {

constexpr char kPositiveHost[] = "resolver-positive.test";
constexpr char kPartialHost[] = "resolver-partial.test";
constexpr char kNegativeHost[] = "resolver-negative.test";
constexpr char kLinkLocalHost[] = "resolver-link-local.test";

unsigned short ParsePort(const char* service) {
  if (service == nullptr || *service == '\0') {
    return 0;
  }
  char* end = nullptr;
  errno = 0;
  const unsigned long value = std::strtoul(service, &end, 10);
  if (errno != 0 || end == service || *end != '\0' || value > UINT16_MAX) {
    return 0;
  }
  return static_cast<unsigned short>(value);
}

addrinfo* AllocateAddress(int family, const addrinfo* hints, unsigned short port, const void* address) {
  auto* node = static_cast<addrinfo*>(std::calloc(1, sizeof(addrinfo)));
  if (node == nullptr) {
    return nullptr;
  }

  const std::size_t address_size = family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
  auto* socket_address = static_cast<sockaddr*>(std::calloc(1, address_size));
  if (socket_address == nullptr) {
    std::free(node);
    return nullptr;
  }

  node->ai_flags = hints == nullptr ? 0 : hints->ai_flags;
  node->ai_family = family;
  node->ai_socktype = hints == nullptr || hints->ai_socktype == 0 ? SOCK_STREAM : hints->ai_socktype;
  node->ai_protocol = hints == nullptr ? 0 : hints->ai_protocol;
  node->ai_addrlen = static_cast<socklen_t>(address_size);
  node->ai_addr = socket_address;

  if (family == AF_INET) {
    auto* ipv4 = reinterpret_cast<sockaddr_in*>(socket_address);
    ipv4->sin_family = AF_INET;
    ipv4->sin_port = htons(port);
    std::memcpy(&ipv4->sin_addr, address, sizeof(ipv4->sin_addr));
  } else {
    auto* ipv6 = reinterpret_cast<sockaddr_in6*>(socket_address);
    ipv6->sin6_family = AF_INET6;
    ipv6->sin6_port = htons(port);
    std::memcpy(&ipv6->sin6_addr, address, sizeof(ipv6->sin6_addr));
  }
  return node;
}

bool AppendAddress(addrinfo** head, addrinfo** tail, int family, const addrinfo* hints, unsigned short port,
                   const char* address) {
  in_addr ipv4{};
  in6_addr ipv6{};
  const void* bytes = nullptr;
  if (family == AF_INET) {
    if (inet_pton(AF_INET, address, &ipv4) != 1) {
      return false;
    }
    bytes = &ipv4;
  } else {
    if (inet_pton(AF_INET6, address, &ipv6) != 1) {
      return false;
    }
    bytes = &ipv6;
  }

  addrinfo* node = AllocateAddress(family, hints, port, bytes);
  if (node == nullptr) {
    return false;
  }
  if (*tail == nullptr) {
    *head = node;
  } else {
    (*tail)->ai_next = node;
  }
  *tail = node;
  return true;
}

void FreeAddressList(addrinfo* address) noexcept {
  while (address != nullptr) {
    addrinfo* next = address->ai_next;
    std::free(address->ai_addr);
    std::free(address->ai_canonname);
    std::free(address);
    address = next;
  }
}

}  // namespace

/// Replace libc name service only in curl_fuzzer_proto_resolver. The fixed
/// hostnames are installed by target policy, so no mutation or ambient
/// resolver configuration can select another destination.
/// @param nodename Hostname selected by the fixed resolver target policy.
/// @param service Decimal service port, or null when no port is requested.
/// @param hints Requested address family and socket properties, or null.
/// @param[out] result Newly allocated address chain on success.
/// @return Zero on success, otherwise the matching EAI_* resolver error.
extern "C" int getaddrinfo(const char* nodename, const char* service, const addrinfo* hints, addrinfo** result) {
  if (result == nullptr) {
    return EAI_FAIL;
  }
  *result = nullptr;
  if (nodename == nullptr) {
    return EAI_NONAME;
  }

  const bool negative = std::strcmp(nodename, kNegativeHost) == 0;

  const bool positive = std::strcmp(nodename, kPositiveHost) == 0;
  const bool partial = std::strcmp(nodename, kPartialHost) == 0;
  const bool link_local = std::strcmp(nodename, kLinkLocalHost) == 0;
  if (!positive && !negative && !partial && !link_local) {
    return EAI_NONAME;
  }

  // Hold every owned answer for one bounded interval so curl's first public
  // poll observes live resolver work. Unlike a scheduler race or debug-only
  // environment hook, this is part of the target-local backend contract.
  std::this_thread::sleep_for(std::chrono::milliseconds(1));
  if (negative) {
    return EAI_NONAME;
  }

  const int family = hints == nullptr ? AF_UNSPEC : hints->ai_family;
  if (family != AF_UNSPEC && family != AF_INET && family != AF_INET6) {
    return EAI_FAMILY;
  }

  const unsigned short port = ParsePort(service);
  if (partial && family == AF_INET) {
    // Keep the A answer behind the AAAA answer by a small, fixed interval.
    // curl can then consume the first asynchronous family through its live
    // resolver accessor before the complete result moves into the DNS cache.
    std::this_thread::sleep_for(std::chrono::milliseconds(4));
  }
  addrinfo* head = nullptr;
  addrinfo* tail = nullptr;
  bool ok = true;
  if (positive || partial) {
    if (family == AF_UNSPEC || family == AF_INET6) {
      ok = AppendAddress(&head, &tail, AF_INET6, hints, port, "::1") &&
           AppendAddress(&head, &tail, AF_INET6, hints, port, "::2");
    }
    if (ok && (family == AF_UNSPEC || family == AF_INET)) {
      ok = AppendAddress(&head, &tail, AF_INET, hints, port, "127.0.0.1") &&
           AppendAddress(&head, &tail, AF_INET, hints, port, "127.0.0.2");
    }
  } else if (family == AF_INET6) {
    ok = AppendAddress(&head, &tail, AF_INET6, hints, port, "fe80::1");
  } else if (family == AF_UNSPEC) {
    ok = AppendAddress(&head, &tail, AF_INET6, hints, port, "fe80::1") &&
         AppendAddress(&head, &tail, AF_INET, hints, port, "127.0.0.1");
  } else {
    ok = AppendAddress(&head, &tail, AF_INET, hints, port, "127.0.0.1");
  }

  if (!ok || head == nullptr) {
    FreeAddressList(head);
    return EAI_MEMORY;
  }
  *result = head;
  return 0;
}

/// Match the ownership contract of the target-local getaddrinfo definition.
/// @param address Address chain returned by the target-local getaddrinfo.
extern "C" void freeaddrinfo(addrinfo* address) noexcept { FreeAddressList(address); }
