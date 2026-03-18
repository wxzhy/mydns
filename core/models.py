from dataclasses import dataclass
import dns.name
import dns.rdatatype
import dns.edns
import dns.rrset


@dataclass(slots=True)
class Query:
    """请求信息"""

    txid: int
    qname: dns.name.Name
    qtype: dns.rdatatype.RdataType
    ecs: dns.edns.ECSOption | None


@dataclass(slots=True)
class Answer:
    """响应信息"""

    rcode: int
    rrset: list[dns.rrset.RRset] | None


@dataclass(slots=True)
class IPList:
    """IP候选"""

    ips: list[str]
    results: dict[str, float | None]
