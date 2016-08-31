
Reverse IP file format description
==================================

All sections are always aligned to the global alignment boundary. This is
8 bytes for the current version, allowing pointer to effectively reach 32GB
within the file.

Header      Bytes R3RZ      4 bytes

Content table, list of 8 byte items:

 Type       32 bit LE number, enumerated
 Pointer    32 bit LE file pointer

List end is marked by (0, 0) tuple.
Possible types are:

 - 1  IP offset table
 - 2  Domain summary table
 - 3  IP summary table

IP offset table
---------------

A 32 bit LE elements table containing 2^24 entries (thus being 64MB in size)
that contains file pointers. Each entry represents the 24 highest bits of an
IP address, therefore to look up for IP X.Y.Z.W one has to access element
X*256*256 + Y*256 + W, and then read the file at the corresponding pointer
offset to find a compressed domain table containing the 256 possible IPs.

Domain summary table
--------------------

Number of domains discarded at the time of crawling      32 bit LE number
 due to being erroneus or a similar reason. These
 domains won't show up in the stats due to being
 discarded early in the pipeline.

Number of domains used at crawling                       32 bit LE number
Number of domains that had at least one valid IP         32 bit LE number
Number of domain extensions (32 bit LE number), entries being a tuple:

  Domain extension (string), zero padded, 64 byte max
  Number of domains of that type feeded into the system  32 bit LE number
  Number of domains with at least one IP                 32 bit LE number

65 table entries (32 bit LE number) defining a histogram of domain name length

IP summary table:

  Number of unique IPs   4bytes (at least 1 domain)
  


