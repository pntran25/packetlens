// Application-layer dissectors. Each module exports default an array of dissector objects.
import dns from './dns.js';
import dhcp from './dhcp.js';
import ntp from './ntp.js';
import nbns from './nbns.js';
import http from './http.js';
import ftp from './ftp.js';
import mail from './mail.js';
import telnet from './telnet.js';
import ssh from './ssh.js';
import smb from './smb.js';
import tls from './tls.js';

export const dissectors = [...dns, ...dhcp, ...ntp, ...nbns, ...http, ...ftp, ...mail, ...telnet, ...ssh, ...smb, ...tls];
