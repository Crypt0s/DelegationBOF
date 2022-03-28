# DelegationBOF

This tool uses LDAP to check a domain for known abusable Kerberos delegation settings.  Currently, it supports RBCD, Constrained, Constrained w/Protocol Transition, and Unconstrained Delegation checks.

## Instructions

Clone, run make, add the .cna to your CS client.

run help get-delegation

Syntax: get-delegation [Type] [optional: FQDN]

Type options : RBCD, Constrained, ConstrainedProto, Unconstrained, All

## Potential issues
In order to make the output not terrible I'm using Cobalt Strike's built in BeaconFormatAlloc fuction.  This requires a preset buffer, which I set to 2048.  If you are testing in a large domain I would suggest increasing this before running.


