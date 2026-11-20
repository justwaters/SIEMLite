package alerts

import (
	"math"
	"testing"

	"siemlite/pkg/storage"
)

func FuzzImprobable(f *testing.F) {
	f.Add(51.5, -0.1, -33.9, 151.2, int64(0), int64(7_200_000), 900.0)
	f.Add(0.0, 0.0, 0.0, 0.0, int64(5), int64(5), 1.0)
	f.Add(math.NaN(), 0.0, 91.0, 181.0, int64(0), int64(-1), math.Inf(1))
	f.Fuzz(func(t *testing.T, lat1, lon1, lat2, lon2 float64, t1, t2 int64, maxKmh float64) {
		a := storage.Login{IP: "a", Lat: lat1, Lon: lon1, TimeMs: t1}
		b := storage.Login{IP: "b", Lat: lat2, Lon: lon2, TimeMs: t2}
		v, bad := Improbable(a, b, maxKmh)
		if bad && (!validCoords(lat1, lon1) || !validCoords(lat2, lon2)) {
			t.Fatalf("improbable for invalid coordinates %v,%v %v,%v", lat1, lon1, lat2, lon2)
		}
		if bad && (math.IsNaN(v.Kmh) || math.IsInf(v.Kmh, 0)) {
			t.Fatalf("improbable with speed %v", v.Kmh)
		}
		if !validCoords(lat1, lon1) || !validCoords(lat2, lon2) {
			return
		}
		d1, d2 := Haversine(lat1, lon1, lat2, lon2), Haversine(lat2, lon2, lat1, lon1)
		if math.IsNaN(d1) || d1 < 0 || math.Abs(d1-d2) > 1e-6*math.Max(1, d1) {
			t.Fatalf("distance %v vs reverse %v", d1, d2)
		}
		// More time never makes the same trip faster.
		if t2 > t1 && t2 < math.MaxInt64-1_000_000 {
			v1, _ := Improbable(a, b, maxKmh)
			b2 := b
			b2.TimeMs = t2 + 1_000_000
			v2, _ := Improbable(a, b2, maxKmh)
			if v1.Kmh > 0 && v2.Kmh > v1.Kmh*(1+1e-9) {
				t.Fatalf("speed rose with more time: %v then %v", v1.Kmh, v2.Kmh)
			}
		}
	})
}
