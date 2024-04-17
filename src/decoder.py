from typing import TypedDict
from typing import Union
from segmenter import segmentedDNSData

dNSQuery = TypedDict(
    "dNSQuery",
    {
        "Query": str,
        "Type": str,
        "Class": str,
    },
)

dNSAnswer = TypedDict(
    "dNSAnswer",
    {
        "Name": str,
        "Type": str,
        "Class": str,
        "TTL": int,
        "Data Length": int,
        "Address": str,
    },
)

dNSAuthority = TypedDict(
    "dNSAuthority",
    {
        "Name": str,
        "Type": str,
        "Class": str,
        "TTL": int,
        "Data Length": int,
        "Address": str,
    },
)

dNSAdditional = TypedDict(
    "dNSAdditional",
    {
        "Name": str,
        "Type": str,
        "Class": str,
        "TTL": int,
        "Data Length": int,
        "Address": str,
    },
)

decodedDNSData = TypedDict(
    "decodedDNSData",
    {
        "Transaction ID": str,
        "Flags": str,
        "Questions": int,
        "Answer RRs": int,
        "Authority RRs": int,
        "Additional RRs": int,
        "Queries": Union[list[dNSQuery], None],
        "Answers": Union[list[dNSAnswer], None],
        "Authority Servers": Union[list[dNSAuthority], None],
        "Additional Records": Union[list[dNSAdditional], None],
    },
)


def decodeDNSData(data: segmentedDNSData) -> decodedDNSData:
    pass
