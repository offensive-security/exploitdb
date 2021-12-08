Source: https://bugs.chromium.org/p/project-zero/issues/detail?id=1061

Broadcom produces Wi-Fi HardMAC SoCs which are used to handle the PHY and MAC layer processing. These chips are present in both mobile devices and Wi-Fi routers, and are capable of handling many Wi-Fi related events without delegating to the host OS. On Android devices, the "bcmdhd" driver is used in order to communicate with the Wi-Fi SoC (also referred to as "dongle").

When the dongle wishes to notify the host OS of an event, it does so by encoding a special "packet" and transmitting it to the host. These packets have an ether type of 0x886C (referred to as ETHER_TYPE_BRCM), and do not contain actual packet data, but rather encapsulate information about events which must be handled by the driver.

After reading packets from the SDIO interface, the "bcmdhd" driver calls the function "dhd_rx_frame" to handle each of the received frames. If a frame has the special Broadcom ether type, it is passed on to an internal handling function, "dhd_wl_host_event". This function inspects the event code, and passes it onto the registered handlers for the given event type.

The function "wl_notify_gscan_event" is the registered handler for events of the following types:
  -WLC_E_PFN_BEST_BATCHING
  -WLC_E_PFN_SCAN_COMPLETE
  -WLC_E_PFN_GSCAN_FULL_RESULT
  -WLC_E_PFN_SWC
  -WLC_E_PFN_BSSID_NET_FOUND
  -WLC_E_PFN_BSSID_NET_LOST
  -WLC_E_PFN_SSID_EXT
  -WLC_E_GAS_FRAGMENT_RX
(for reference, see "wl_init_event_handler")

Specifically, when the event code "WLC_E_PFN_SWC" is received, the gscan handler function calls "dhd_handle_swc_evt" in order to process the event's data, like so:

1.  void * dhd_handle_swc_evt(dhd_pub_t *dhd, const void *event_data, int *send_evt_bytes)
2.  {
3.      ...
4.      wl_pfn_swc_results_t *results = (wl_pfn_swc_results_t *)event_data;
5.      ...
6.      gscan_params = &(_pno_state->pno_params_arr[INDEX_OF_GSCAN_PARAMS].params_gscan);
7.      ...
8.      if (!params->results_rxed_so_far) {
9.          if (!params->change_array) {
10.             params->change_array = (wl_pfn_significant_net_t *)
11.                                    kmalloc(sizeof(wl_pfn_significant_net_t) * results->total_count, GFP_KERNEL);
12.             ...
13.         }
14.     }
15.     ...
16.     change_array = &params->change_array[params->results_rxed_so_far];
17.     memcpy(change_array, results->list, sizeof(wl_pfn_significant_net_t) * results->pkt_count);
18.     params->results_rxed_so_far += results->pkt_count;
19.     ...
20. }

(where "event_data" is the arbitrary data encapsulated in the event passed in from the dongle)

When the function above is first invoked, the value of "params->change_array" is NULL. An attacker controlling the dongle may send a crafted WLC_E_PFN_SWC event, with the following values:

  - results->total_count = SMALL_VALUE
  - result->pkt_count = LARGE_VALUE

Since the function fails to verify that "pkt_count" is not larger than "total_count", this would cause the allocated buffer (lines 10-11) to be smaller than the size used in the memcpy operation (line 17), thus overflowing the buffer.

I've been able to statically verify these issues on the "bcmdhd-3.10" driver, and in the corresponding "bcmdhd" driver on the Nexus 6P's kernel (angler).

Adding sample EtherType exploit which achieves kernel code execution on the Nexus 5.

This exploit uses scapy-fakeap to broadcast a dummy network. The exploit starts the attack once a client with the target MAC connects to the network and sends an ARP request.


Proof of Concept:
https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/41808.zip