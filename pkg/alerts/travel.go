package alerts

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"

	"siemlite/pkg/storage"
)

// minTravelKm is the distance under which two places count as the same: GeoIP is only
// accurate to a city or so, and a metro area is a short drive.
const minTravelKm = 200

// Verdict is how far and how fast a user seems to have travelled between two sign-ins.
type Verdict struct {
	DistanceKm, Hours, Kmh float64
}

// Haversine is the great-circle distance in km between two points given in degrees.
func Haversine(lat1, lon1, lat2, lon2 float64) float64 {
	const earthKm = 6371.0088
	rad := math.Pi / 180
	dLat, dLon := (lat2-lat1)*rad, (lon2-lon1)*rad
	a := math.Sin(dLat/2)*math.Sin(dLat/2) + math.Cos(lat1*rad)*math.Cos(lat2*rad)*math.Sin(dLon/2)*math.Sin(dLon/2)
	return 2 * earthKm * math.Asin(math.Min(1, math.Sqrt(a)))
}

func validCoords(lat, lon float64) bool {
	return !math.IsNaN(lat) && !math.IsNaN(lon) && !math.IsInf(lat, 0) && !math.IsInf(lon, 0) &&
		lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180
}

// Improbable reports whether the user could not have got from prev's place to cur's in the
// time between the two sign-ins at maxKmh. Places under 200 km apart, the same address, and
// times that are not in order never count. A gap under a minute counts as a minute, so
// two sign-ins moments apart don't give an infinite speed.
func Improbable(prev, cur storage.Login, maxKmh float64) (Verdict, bool) {
	if !validCoords(prev.Lat, prev.Lon) || !validCoords(cur.Lat, cur.Lon) || math.IsNaN(maxKmh) || maxKmh < 0 {
		return Verdict{}, false
	}
	if prev.IP != "" && prev.IP == cur.IP {
		return Verdict{}, false
	}
	dtMs := cur.TimeMs - prev.TimeMs
	if dtMs <= 0 {
		return Verdict{}, false
	}
	km := Haversine(prev.Lat, prev.Lon, cur.Lat, cur.Lon)
	if km < minTravelKm {
		return Verdict{}, false
	}
	hours := float64(max(dtMs, 60_000)) / 3_600_000
	v := Verdict{DistanceKm: km, Hours: hours, Kmh: km / hours}
	return v, v.Kmh > maxKmh
}

func place(l storage.Login) string {
	switch {
	case l.City != "" && l.Country != "":
		return l.City + ", " + l.Country
	case l.City != "":
		return l.City
	case l.Country != "":
		return l.Country
	}
	return "an unknown place"
}

func groupInt(n float64) string {
	s := strconv.FormatInt(int64(math.Round(n)), 10)
	for i := len(s) - 3; i > 0 && s[i-1] != '-'; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

func elapsed(h float64) string {
	m := int(math.Round(h * 60))
	if m < 60 {
		return fmt.Sprintf("%dm", m)
	}
	if m >= 48*60 {
		return fmt.Sprintf("%dd", m/(24*60))
	}
	return fmt.Sprintf("%dh%02dm", m/60, m%60)
}

// travelDetail describes a sign-in pair for an alert's announcement.
func travelDetail(prev, cur storage.Login, v Verdict) string {
	return fmt.Sprintf("%s (%s) -> %s (%s): %s km in %s (%s km/h)", place(prev), prev.IP, place(cur), cur.IP,
		groupInt(v.DistanceKm), elapsed(v.Hours), groupInt(v.Kmh))
}

// isTravelRule reports whether ru is the built-in improbable travel rule.
func isTravelRule(ru storage.Rule) bool {
	return ru.Builtin && strings.EqualFold(ru.Name, storage.TravelRuleName)
}

// checkTravel runs the improbable travel rule over the sign-ins with arrival numbers in
// (from, maxID]. Each new sign-in (with a user and coordinates) is compared with the same
// user's previous one within the rule's window; when the speed between them is above the
// rule's threshold (km/h) the user's alert is raised. It returns the arrival number the rule
// has been through: maxID, or, when more than storage.MaxTravelLogins sign-ins were new, the
// last one handled, so the next check goes on from there. A failure raises nothing and
// moves nothing, so the same range is checked again.
func (e *Engine) checkTravel(ctx context.Context, ru storage.Rule, from, maxID, now int64, res *Result) (int64, error) {
	ru, err := e.prepare(ctx, ru)
	if err != nil {
		return from, err
	}
	logins, err := e.store.TravelLogins(ctx, ru, from, maxID)
	if err != nil {
		return from, err
	}
	through := maxID
	if len(logins) >= storage.MaxTravelLogins {
		through = from
		for _, l := range logins {
			through = max(through, l.Seq)
		}
	}
	lookback := int64(ru.WindowMinutes) * 60_000
	if lookback <= 0 {
		lookback = 24 * 60 * 60_000
	}
	type hit struct {
		a    storage.AlertRaise
		note string
		cur  storage.Login
	}
	var hits []hit
	for _, cur := range logins {
		prev, err := e.store.PreviousLogin(ctx, ru, cur.User, cur.TimeMs, cur.Seq, lookback)
		if err != nil {
			return from, err
		}
		if prev == nil {
			continue
		}
		v, bad := Improbable(*prev, cur, float64(ru.Threshold))
		if !bad {
			continue
		}
		hits = append(hits, hit{a: storage.AlertRaise{Value: cur.User, NewCount: 1, WindowCount: 1, First: prev.TimeMs, Last: cur.TimeMs},
			note: travelDetail(*prev, cur, v), cur: cur})
	}
	if len(hits) == 0 {
		return through, nil
	}
	ru.GroupBy = "user"
	raises := make([]storage.AlertRaise, len(hits))
	for i, h := range hits {
		raises[i] = h.a
	}
	opened, err := e.store.RaiseAlerts(ctx, ru, raises, now)
	if err != nil {
		return from, err
	}
	for i, h := range hits {
		if opened[i] {
			res.Opened++
			e.log.Info("alert opened", "rule", ru.Name, "group", h.a.Value)
			e.opened(ctx, Opened{Rule: ru, Group: h.a.Value, Count: 1, Detail: h.note})
		} else {
			res.Updated++
		}
	}
	return through, nil
}
