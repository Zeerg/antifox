package embedmodel

import "testing"

func cos(a, b []float32) float64 {
	var dot float64
	for i := range a {
		dot += float64(a[i]) * float64(b[i])
	}
	return dot
}

func TestEmbedSanity(t *testing.T) {
	texts := []string{
		"SQL injection in the login form",
		"UNION SELECT password FROM users -- authentication bypass",
		"the weather forecast for Tuesday",
		"reflected XSS via the search parameter",
	}
	vecs, err := Embed(texts)
	if err != nil {
		t.Fatal(err)
	}
	if len(vecs) != 4 || len(vecs[0]) != Dim {
		t.Fatalf("bad shape: %d x %d", len(vecs), len(vecs[0]))
	}
	var norm float64
	for _, v := range vecs[0] {
		norm += float64(v) * float64(v)
	}
	if norm < 0.99 || norm > 1.01 {
		t.Fatalf("not normalized: %v", norm)
	}
	simSqli := cos(vecs[0], vecs[1])
	simUnrel := cos(vecs[0], vecs[2])
	simXss := cos(vecs[0], vecs[3])
	t.Logf("sqli-vs-union=%.3f  sqli-vs-weather=%.3f  sqli-vs-xss=%.3f", simSqli, simUnrel, simXss)
	if simSqli <= simUnrel {
		t.Fatalf("related texts less similar than unrelated: %v vs %v", simSqli, simUnrel)
	}
}
