package com.notrus.android.protocol

object ProtocolCatalog {
    fun label(protocol: String): String = when (protocol) {
        "signal-pqxdh-double-ratchet-v1" -> "PQXDH + Double Ratchet"
        "mls-rfc9420-v1" -> "MLS RFC 9420"
        "pairwise-v2" -> "Experimental Pairwise v2"
        "group-tree-v3" -> "Experimental Group Tree v3"
        "group-epoch-v2" -> "Experimental Group Epoch v2"
        else -> "Unknown Protocol"
    }

    fun tone(protocol: String): String = when (protocol) {
        "signal-pqxdh-double-ratchet-v1", "mls-rfc9420-v1" -> "Production path"
        else -> "Migration-only"
    }
}
