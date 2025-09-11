# IP ASN Server

Simple gRPC server for IP ASN and country code lookup.

`Usage: ./server <data.csv.gz> <tags.json>`

### Free IP Database:

https://ipinfo.io/lite

Any IP not in the dataset will be marked as bogon when queried

### ASN tags:

https://bgp.tools/tags/ --- https://github.com/63square/asn_tag_collector
