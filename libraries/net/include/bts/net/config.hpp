#pragma once

#define BTS_NET_PROTOCOL_VERSION                        105

/**
 * Define this to enable debugging code in the p2p network interface.
 * This is code that would never be executed in normal operation, but is
 * used for automated testing (creating artificial net splits,
 * tracking where messages came from and when)
 */
#define ENABLE_P2P_DEBUGGING_API                        1

/**
 * 512 kb
 */
#define MAX_MESSAGE_SIZE                                (512 * 1024)
#define BTS_NET_DEFAULT_PEER_CONNECTION_RETRY_TIME      30 // seconds

/**
 * AFter trying all peers, how long to wait before we check to
 * see if there are peers we can try again.
 */
#define BTS_PEER_DATABASE_RETRY_DELAY                   15 // seconds

#define BTS_NET_PEER_HANDSHAKE_INACTIVITY_TIMEOUT       5

#define BTS_NET_PEER_DISCONNECT_TIMEOUT                 20

#define BTS_NET_TEST_P2P_PORT                           1701
#define BTS_NET_DEFAULT_P2P_PORT                        1778
#define BTS_NET_DEFAULT_DESIRED_CONNECTIONS             8
#define BTS_NET_DELEGATE_DESIRED_CONNECTIONS            20
#define BTS_NET_DEFAULT_MAX_CONNECTIONS                 200

#define BTS_NET_MAXIMUM_QUEUED_MESSAGES_IN_BYTES        (1024 * 1024)

/**
 * We prevent a peer from offering us a list of blocks which, if we fetched them
 * all, would result in a blockchain that extended into the future.
 * This parameter gives us some wiggle room, allowing a peer to give us blocks
 * that would put our blockchain up to an hour in the future, just in case
 * our clock is a bit off.
 */
#define BTS_NET_FUTURE_SYNC_BLOCKS_GRACE_PERIOD_SEC     (60 * 60)

#define BTS_NET_INSUFFICIENT_RELAY_FEE_PENALTY_SEC      15

#define BTS_NET_MAX_INVENTORY_SIZE_IN_MINUTES           2

#define BTS_NET_MAX_BLOCKS_PER_PEER_DURING_SYNCING      100
