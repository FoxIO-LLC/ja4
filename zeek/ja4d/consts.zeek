module FINGERPRINT::JA4D;

export {
    global DHCP_MESSAGE_MAP: table[count] of string = {
        [1] = "disco", # DHCPDISCOVER
        [2] = "offer", # DHCPOFFER
        [3] = "reqst", # DHCPREQUEST
        [4] = "decln", # DHCPDECLINE
        [5] = "dpack", # DHCPACK
        [6] = "dpnak", # DHCPNAK
        [7] = "relse", # DHCPRELEASE
        [8] = "infor", # DHCPINFORM
        [9] = "frenw", # DHCPFORCERENEW
        [10] = "lqery", # DHCPLEASEQUERY
        [11] = "lunas", # DHCPLEASEUNASSIGNED
        [12] = "lunkn", # DHCPLEASEUNKNOWN
        [13] = "lactv", # DHCPLEASEACTIVE
        [14] = "blklq", # DHCPBULKLEASEQUERY
        [15] = "lqdon", # DHCPLEASEQUERYDONE
        [16] = "actlq", # DHCPACTIVELEASEQUERY
        [17] = "lqsta", # DHCPLEASEQUERYSTATUS
        [18] = "dhtls", # DHCPTLS
    };

    global DHCP_SKIP_OPTIONS: set[count] = {
        53,
        255,
        50,
        81,
    };
}