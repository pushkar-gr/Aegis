#ifndef AEGIS_H
#define AEGIS_H

/**
 * @brief Session Lookup Key
 *
 * Used to identify unique flows in the BPF hash map.
 */
typedef struct session_key {
  __be32 src_ip;    // Source IP Address (Network Byte Order)
  __be32 dest_ip;   // Destination IP Address (Network Byte Order)
  __be16 dest_port; // Destination Port (Network Byte Order)
} __attribute__((packed)) session_key;

/**
 * @brief Session Value / Telemetry
 *
 * Stores the state and telemetry data for an active session.
 */
typedef struct session_val {
  __u64 last_seen_ns;  // Timestamp of the last valid packet (System uptime)
  __u64 created_at_ns; // Timestamp when the session was authorized
} session_val;

/**
 * @brief Reversal Lookup Key
 *
 * Used to identify connections being diverted to trap endpoint.
 */
struct trap_reversal_key {
  __be32 src_ip;   // Original client IP
  __be16 src_port; // Original client port
} __attribute__((packed)) trap_reversal_key;

/**
 * @brief Reversal Lookup Value
 *
 * Stores original destination ip:port value of conections diverted to trap
 * endpoint.
 */
struct trap_reversal_val {
  __be32 orig_dest_ip;   // Original destination IP (before trap)
  __be16 orig_dest_port; // Original destination port (before trap)
} __attribute__((packed)) trap_reversal_val;

#endif // AEGIS_H
