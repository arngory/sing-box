---
icon: material/new-box
---

!!! question "neko addition"

# Fallback

Asks other DNS servers in order and moves on to the next one when a server
fails.

### Structure

```json
{
  "dns": {
    "servers": [
      {
        "type": "fallback",
        "tag": "",

        "servers": [],
        "timeout": ""
      }
    ]
  }
}
```

!!! note ""

    You can ignore the JSON Array [] tag when the content is only one item

### Fields

#### servers

==Required==

Tags of the DNS servers to ask, in order.

A server fails when its query ends in an error, when it does not answer
within `timeout`, or when it answers with an rcode other than `NOERROR` and
`NXDOMAIN` (`SERVFAIL`, `REFUSED`, ...). `NOERROR`, an empty one too, and
`NXDOMAIN` are answers and are returned as they are.

When a server fails with an error or a timeout and a later one answers, the
one that answered is asked first for the next 5 minutes, so a dead first
server does not hold up every query. A failing rcode does not do this: it is
about the one query. After the 5 minutes, or once the first server answers
again, or after a change of network, the order given is used again.

When every server fails, the first failing answer is returned, or the errors
when there is none.

#### timeout

How long a server may take to answer before the next one is asked, `4s` by
default. The last server asked has the query's own deadline.
