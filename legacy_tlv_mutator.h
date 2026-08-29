/*
 * Copyright (C) Max Dymond, <cmeister2@gmail.com>, et al.
 *
 * SPDX-License-Identifier: curl
 */

#ifndef LEGACY_TLV_MUTATOR_H_
#define LEGACY_TLV_MUTATOR_H_

#include <stddef.h>
#include <stdint.h>

namespace legacy_tlv_mutator {

/**
 * Frequency of the deliberate unstructured-mutation escape hatch.
 *
 * Raw mutation is needed to find framing/parser bugs, but making it the common
 * path wastes executions because a damaged TLV length or type prevents curl
 * from seeing the option payloads. Keeping this policy public also lets tests
 * exercise both paths without duplicating an otherwise hidden magic number.
 */
constexpr unsigned int kRawMutationPeriod = 16;

/**
 * Returns the canonical non-resolving value for a routing-sensitive TLV type.
 *
 * The legacy harness uses this same mapping when executing an existing corpus
 * input directly, because libFuzzer does not pass initial seeds or standalone
 * reproducers through the custom mutator first. `nullptr` means the type is not
 * one of the resolver-sensitive routing options covered by this policy.
 */
const char *CanonicalRoutingValue(uint16_t type);

/**
 * Mutates one legacy TLV input in place without exceeding `max_size`.
 *
 * Most calls preserve record framing so mutations reach curl; malformed inputs
 * are repaired from their valid prefix before attempting a useful insertion.
 * Capacity exhaustion may leave that prefix unchanged. Periodic raw calls
 * intentionally relax the framing invariant for parser coverage. Any result
 * that remains structurally executable has resolver-sensitive routing strings
 * canonicalized to loopback; malformed raw results retain their framing while
 * any independently framed routing value is neutralized in place.
 */
size_t Mutate(uint8_t *data, size_t size, size_t max_size,
              unsigned int seed);

/**
 * Crosses complete TLV records from two parents into `out`.
 *
 * Record boundaries, required transfer records, and the mutator's duplicate
 * policy are preserved so the child is normally executable. Invalid or empty
 * parents use bounded byte crossover, retaining malformed framing across
 * generations. Executable children also canonicalize inherited proxy,
 * interface, and FTP active-mode endpoints so old corpus values cannot escape
 * the in-process peer.
 */
size_t CrossOver(const uint8_t *data1, size_t size1,
                 const uint8_t *data2, size_t size2,
                 uint8_t *out, size_t max_out_size,
                 unsigned int seed);

/**
 * Reports whether an input is safe for the structure-aware operations.
 *
 * This deliberately enforces more semantics than the legacy byte parser:
 * known top-level IDs, four-byte numeric values, valid nested MIME records,
 * and no duplicates for records classified as scalar by mutation policy. It
 * is public only to make those mutation preconditions directly testable and
 * useful for corpus validation.
 */
bool IsStructurallyValid(const uint8_t *data, size_t size);

}  // namespace legacy_tlv_mutator

#endif  // LEGACY_TLV_MUTATOR_H_
