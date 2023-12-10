## defaultconf
defaultconf is a simple (complex) program that is intended to make handling multiple defaults
simpler on freebsd.  it accomplishes this by allowing protocols to register default gateways
with it, then uses the state of the system to select the best default to set up.

## configuration
defaultconf needs to be inserted into every place that a default gateway may be derived, and those
places too need to be modified to not set the default, but to delegate this function to defaultconf.
See examples for a dhcp protocol handling of this.

In addition to random configuration changes, a configuration file may be created to provide defaults.
The only configuration peice of note is probably the priority list, this list allows the administrator
to influence the selection of a default gateway based on priority.

```
/usr/local/etc/defaultconf.yaml
priority:
  - { af: inet6, link: cltun }
  - { link: tmnet }
```

In the example above, a priority list with two items is created.  The first item makes the highest priority
the cltun interface if the default being selected is inet6.  The second item makes the tmnet interface default
for both inet and inet6 overall.  The possible select fields to specify are af, link, and protocol.  Protocol
may be any of { dhcp, ra, static, ppp }

## installation
to install, copy the rc.d/defaultconf file to the rc.d directory.  optionally create the config file for
priority, and patch all of the default gateway ingress points to register defaults with defaultconf
