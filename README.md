# DelegationBOF

This tool uses LDAP to check a domain for known abusable Kerberos delegation settings.  Currently, it supports RBCD, Constrained, Constrained w/Protocol Transition, and Unconstrained Delegation checks.

Despite the name, I decided to add in a couple more features since the bulk of the code was already there.  So now there is a get-spns command as well which can look for ASREP accounts or Kerberoastable SPNs.

## Instructions

Clone, run make, add the .cna to your CS client.

### Delegation
run help get-delegation

Syntax: get-delegation [Type] [optional: FQDN]

Type options : RBCD, Constrained, ConstrainedProto, Unconstrained, All

If no domain is provided, the local domain is used.

### Kerberoast 
run help get-spns

Syntax: get-spns [Type] [optional: FQDN]

Type options : spns, ASREP, All

If no domain is provided, the local domain is used.

## Potential issues
In order to make the output not terrible I'm using Cobalt Strike's built in BeaconFormatAlloc fuction.  This requires a preset buffer, which I set to 2048.  If you are testing in a large domain I would suggest increasing this before running.


