# Iker

Wrapper tool around ike-scan to help analyse the security of an IPsec based VPN endpoint.

This is a rewrite of the original tool initially developer by @julgoor

Released under th GPL v3 license <http://www.gnu.org/licenses/gpl-3.0.html>

### Funcionalities

* IPSec discovering
* IKE v2 support detection
* Vendor IDs (VID) extraction
* IPSec implementation guessing (backoff)
* IPSec main mode transforms listing
* IPSec aggressive mode transforms listing
* IPSec aggressive mode client/group IDs listing
* XML and text output

### Usage

```bash
$ python iker.py -i ips.txt -o iker_output.txt -x iker_output.xml -v
```

### Authors

* Borja <borja [at] libcrack [dot] so>
* Julio Gomez  <julgor [at] gmail [dot] com>
* Pablo Cat  <xkill [at] locolandia [dot] net>
