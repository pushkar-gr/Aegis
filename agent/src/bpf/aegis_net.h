#ifndef AEGIS_NET_H
#define AEGIS_NET_H

// Protocol constants
#define ETH_P_IP 0x0800
#define ETH_P_ARP 0x0806
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17

/**
 * @brief Redirect TCP traffic to trap endpoint
 *
 * Updates IP and TCP headers to redirect traffic to the trap server.
 *
 * @param iph IPv4 header pointer
 * @param tcph TCP header pointer
 * @return XDP_PASS to forward redirected packet
 */
static __always_inline int redirect_to_local_trap(struct iphdr *iph,
                                                  struct tcphdr *tcph);
/**
 * @brief Fold 32-bit checksum to 16-bit
 *
 * Do the final checksum folding step. Reduces 32-bit intermediate sum to 16-bit
 * final checksum.
 *
 * @param sum 32-bit intermediate checksum
 * @return 16-bit folded checksum
 */
static __always_inline __u16 aegis_csum_fold(__u32 sum) {
  sum = (sum & 0xFFFF) + (sum >> 16);
  sum = (sum & 0xFFFF) + (sum >> 16);
  return (__u16)sum;
}

/**
 * @brief Update 16-bit checksum
 *
 * Updates a 16-bit IP/TCP/UDP header checksum for a field change.
 *
 * @param check Current checksum value
 * @param old_v Previous field value (network byte order)
 * @param new_v New field value (network byte order)
 * @return Updated checksum (network byte order)
 */
static __always_inline __be16 aegis_csum_update2(__be16 check, __be16 old_v,
                                                 __be16 new_v) {
  __u32 sum = (__u16)~check;
  sum += (__u16)~old_v;
  sum += new_v;
  return (__be16)~aegis_csum_fold(sum);
}

/**
 * @brief Update 32-bit checksum
 *
 * Updates a 16-bit IP/TCP/UDP header checksum for a 32-bit field change.
 * Handles IPv4 address updates where both high and low 16-bit parts change.
 *
 * @param check Current checksum value
 * @param old_v Previous 32-bit value
 * @param new_v New 32-bit value
 * @return Updated checksum (network byte order)
 */
static __always_inline __be16 aegis_csum_update4(__be16 check, __be32 old_v,
                                                 __be32 new_v) {
  __u32 sum = (__u16)~check;
  sum += (__u16) ~(old_v & 0xFFFF);
  sum += (__u16) ~(old_v >> 16);
  sum += (new_v & 0xFFFF);
  sum += (new_v >> 16);
  return (__be16)~aegis_csum_fold(sum);
}

#endif // AEGIS_NET_H
