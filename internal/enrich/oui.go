package enrich

import "strings"

// LookupOUI returns the vendor name for a MAC address based on the OUI
// (first 3 octets). Best-effort; returns empty string if unknown.
func LookupOUI(mac string) string {
	mac = strings.ToUpper(mac)
	parts := strings.Split(mac, ":")
	if len(parts) < 3 {
		parts = strings.Split(mac, "-")
	}
	if len(parts) < 3 {
		return ""
	}
	oui := parts[0] + ":" + parts[1] + ":" + parts[2]
	if v, ok := commonOUIs[oui]; ok {
		return v
	}
	return ""
}

var commonOUIs = map[string]string{
	"00:50:56": "VMware", "08:00:27": "VirtualBox", "52:54:00": "QEMU/KVM",
	"02:42:AC": "Docker", "AC:DE:48": "Apple", "00:1A:11": "Google",
	"00:1B:21": "Intel", "00:1C:C4": "Intel", "00:21:5C": "Intel",
	"00:22:FA": "Intel", "00:24:D6": "Intel", "00:26:C7": "Intel",
	"00:50:F2": "Microsoft", "00:50:DA": "D-Link", "00:60:97": "3Com",
	"00:80:C2": "IEEE 802.1", "00:90:7A": "Cisco", "00:A0:C9": "Intel",
	"00:AA:00": "Intel", "00:E0:4C": "Realtek", "02:0F:B5": "Cisco",
	"02:1A:11": "Google", "02:60:8C": "Apple", "04:92:26": "Cisco",
	"08:00:20": "Sun/Oracle", "0C:41:3E": "Google", "10:BF:48": "Google",
	"18:03:73": "Dell", "18:66:DA": "Google", "1C:69:7A": "Huawei",
	"20:47:ED": "Google", "24:1D:BC": "Huawei", "28:6D:97": "Google",
	"2C:CF:58": "Intel", "30:9C:23": "Google", "34:02:86": "Amazon",
	"34:80:89": "Raspberry Pi", "38:F9:D3": "Apple", "3C:5A:B4": "Google",
	"3C:A9:F4": "Intel", "40:4E:36": "Huawei", "44:00:49": "Intel",
	"48:21:6B": "Intel", "48:A4:72": "Intel", "4C:CC:11": "Amazon",
	"50:1A:C5": "Huawei", "54:99:60": "Intel", "58:20:B1": "Intel",
	"5C:E2:86": "Intel", "60:45:BD": "Google", "64:00:6A": "Google",
	"64:5A:04": "Intel", "68:54:5A": "Huawei", "6C:29:95": "Intel",
	"70:03:7E": "Cisco", "74:E5:43": "Huawei", "78:0C:B8": "Intel",
	"78:4F:43": "Intel", "7C:49:EB": "Intel", "80:7A:BF": "Huawei",
	"84:47:09": "Intel", "88:79:7E": "Huawei", "8C:70:5A": "Intel",
	"90:2E:1C": "Intel", "94:65:9C": "Intel", "98:54:1B": "Huawei",
	"9C:29:76": "Intel", "A0:36:BC": "Intel", "A0:88:B4": "Intel",
	"A4:02:B9": "Intel", "A4:34:D9": "Intel", "A4:5E:60": "Intel",
	"A8:5E:45": "Intel", "AC:5F:3E": "Intel", "B0:35:8F": "Intel",
	"B0:BE:76": "Intel", "B4:6B:FC": "Intel", "B8:08:CF": "Intel",
	"BC:54:2F": "Intel", "C0:3F:D5": "Intel", "C4:00:AD": "Intel",
	"C8:5B:76": "Intel", "CC:2D:E0": "Intel", "D0:57:7B": "Intel",
	"D4:6D:6D": "Intel", "D8:3B:BF": "Intel", "DC:4A:3E": "Intel",
	"E0:3F:49": "Intel", "E4:A7:A0": "Intel", "E8:6A:64": "Intel",
	"EC:08:6B": "Intel", "F0:79:60": "Intel", "F4:06:69": "Intel",
	"F8:34:41": "Intel", "FC:45:96": "Intel",
}