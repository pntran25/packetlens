// Registers every dissector. Import this module once before dissecting.
import { register } from '../core/registry.js';

import ethernet from './ethernet.js';
import vlan from './vlan.js';
import { sll, sll2, nullLoop, rawIp, ppp, pppoe, mpls } from './linklayers.js';
import arp from './arp.js';
import ipv4 from './ipv4.js';
import ipv6 from './ipv6.js';
import { icmp, icmpv6 } from './icmp.js';
import tcp from './tcp.js';
import udp from './udp.js';
import { gre, igmp } from './misc.js';

// Application-layer dissectors (each file exports default or a list).
import * as app from './app/index.js';

for (const d of [ethernet, vlan, sll, sll2, nullLoop, rawIp, ppp, pppoe, mpls, arp, ipv4, ipv6, icmp, icmpv6, tcp, udp, gre, igmp]) register(d);
for (const d of app.dissectors) register(d);
