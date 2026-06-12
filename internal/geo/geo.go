package geo

import (
    "fmt"
    "hash/fnv"
    "net"
    "os"

    "github.com/oschwald/geoip2-golang"
)

type Location struct {
    IP      string  `json:"ip"`
    Lat     float64 `json:"lat"`
    Lng     float64 `json:"lng"`
    Country string  `json:"country"`
    City    string  `json:"city"`
    Count   int     `json:"count"`
}

type Lookup struct {
    db      *geoip2.Reader
    mockMode bool
}

// New opens the GeoLite2-City.mmdb at path.
// If MOCK_GEO=true is set (dev/mock capture), fake locations are returned.
func New(path string) (*Lookup, error) {
    if os.Getenv("MOCK_GEO") == "true" {
        return &Lookup{mockMode: true}, nil
    }
    if _, err := os.Stat(path); os.IsNotExist(err) {
        return nil, fmt.Errorf("GeoLite2 DB not found at %s", path)
    }
    db, err := geoip2.Open(path)
    if err != nil {
        return nil, fmt.Errorf("geoip2 open: %w", err)
    }
    return &Lookup{db: db}, nil
}

func (l *Lookup) Close() {
    if l.db != nil {
        l.db.Close()
    }
}

// Locate resolves an IP to a geographic location.
// Returns nil, err for private IPs and lookup failures.
func (l *Lookup) Locate(ip string, count int) (*Location, error) {
    parsed := net.ParseIP(ip)
    if parsed == nil {
        return nil, fmt.Errorf("invalid IP: %s", ip)
    }

    if l.mockMode {
        if isPrivate(parsed) {
            return mockLocation(ip, count), nil
        }
    } else if isPrivate(parsed) {
        return nil, fmt.Errorf("private IP")
    }

    rec, err := l.db.City(parsed)
    if err != nil {
        return nil, err
    }
    return &Location{
        IP:      ip,
        Lat:     rec.Location.Latitude,
        Lng:     rec.Location.Longitude,
        Country: rec.Country.Names["en"],
        City:    rec.City.Names["en"],
        Count:   count,
    }, nil
}

// mockLocation returns a deterministic fake location derived from the IP.
func mockLocation(ip string, count int) *Location {
    h := fnv.New32a()
    h.Write([]byte(ip))
    n := h.Sum32()
    cities := []struct{ name, country string; lat, lng float64 }{
        {"Lagos", "Nigeria", 6.5244, 3.3792},
        {"London", "UK", 51.5074, -0.1278},
        {"New York", "US", 40.7128, -74.0060},
        {"Tokyo", "Japan", 35.6762, 139.6503},
        {"Sydney", "Australia", -33.8688, 151.2093},
        {"Berlin", "Germany", 52.5200, 13.4050},
        {"São Paulo", "Brazil", -23.5505, -46.6333},
        {"Mumbai", "India", 19.0760, 72.8777},
    }
    c := cities[n%uint32(len(cities))]
    return &Location{IP: ip, Lat: c.lat, Lng: c.lng, Country: c.country, City: c.name, Count: count}
}

var privateRanges []*net.IPNet

func init() {
    for _, cidr := range []string{
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1/128",
    } {
        _, n, _ := net.ParseCIDR(cidr)
        privateRanges = append(privateRanges, n)
    }
}

func isPrivate(ip net.IP) bool {
    for _, r := range privateRanges {
        if r.Contains(ip) {
            return true
        }
    }
    return false
}