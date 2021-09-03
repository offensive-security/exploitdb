source: https://www.securityfocus.com/bid/3711/info

Prestige is a product line of DSL routers produced and distributed by Zyxel.

When a Zyxel router receives fragmented packets that after reassembly is greater than 64 kilobytes in length, the router crashes. The router must be power cycled to resume normal operation. This could lead to a remote user denying service to a legitimate user of the router. The router is affected only by fragmented packets received through the DSL interface. Fragmented packets sent through the LAN interface have no affect on the system.

ping -t -l 65500 victim.example.com