#!/usr/bin/perl

no utf8;

# Net::Radius test input
# Made with $Id: cisco-vpn3k-ar.p 74 2007-01-30 10:23:14Z lem $

$VAR1 = {
          'packet' => ' D�D�2�`{OAF�\'�<test��}��DS"���[      ��G\'=   ',
          'secret' => '',
          'description' => 'Cisco VPN-3000 Access-Request',
          'authenticator' => '�D�2�`{OAF�\'�<',
          'identifier' => 3,
          'dictionary' => undef,
          'opts' => {
                      'secret' => '',
                      'description' => 'Cisco VPN-3000 Access-Request',
                      'output' => 'packets/cisco-vpn3k-ar',
                      'authenticator' => '�D�2�`{OAF�\'�<',
                      'identifier' => 3,
                      'dont-embed-dict' => 1,
                      'dictionary' => [
                                        'dicts/dictionary',
                                        'dicts/dictionary.cisco.vpn3000'
                                      ],
                      'slots' => 4
                    },
          'slots' => 4
        };
