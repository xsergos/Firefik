package schedule

import (
	"testing"
	"time"
)

func mustParse(t *testing.T, s string) Window {
	t.Helper()
	w, err := Parse(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return w
}

func TestParseBasic(t *testing.T) {
	w := mustParse(t, "09:00-18:00 Europe/Moscow Mon-Fri")
	if w.StartMin != 9*60 || w.EndMin != 18*60 {
		t.Errorf("times: %d-%d", w.StartMin, w.EndMin)
	}
	if w.Loc.String() != "Europe/Moscow" {
		t.Errorf("tz: %v", w.Loc)
	}
	if !w.Days[int(time.Monday)] || !w.Days[int(time.Friday)] {
		t.Errorf("days: %v", w.Days)
	}
	if w.Days[int(time.Saturday)] || w.Days[int(time.Sunday)] {
		t.Errorf("weekend should be excluded: %v", w.Days)
	}
}

func TestParseDaily(t *testing.T) {
	w := mustParse(t, "08:00-22:00 UTC daily")
	for _, ok := range w.Days {
		if !ok {
			t.Errorf("daily should cover all days: %v", w.Days)
		}
	}
}

func TestParseCommaList(t *testing.T) {
	w := mustParse(t, "10:00-12:00 Mon,Wed,Fri")
	want := map[time.Weekday]bool{time.Monday: true, time.Wednesday: true, time.Friday: true}
	for d := time.Sunday; d <= time.Saturday; d++ {
		if w.Days[int(d)] != want[d] {
			t.Errorf("day %v: got %v, want %v", d, w.Days[int(d)], want[d])
		}
	}
}

func TestActive(t *testing.T) {
	w := mustParse(t, "09:00-18:00 UTC Mon-Fri")
	mon1000 := time.Date(2026, 1, 5, 10, 0, 0, 0, time.UTC)
	if !w.Active(mon1000) {
		t.Errorf("Mon 10:00 should be active")
	}
	mon0800 := time.Date(2026, 1, 5, 8, 0, 0, 0, time.UTC)
	if w.Active(mon0800) {
		t.Errorf("Mon 08:00 should be inactive")
	}
	sat1000 := time.Date(2026, 1, 10, 10, 0, 0, 0, time.UTC)
	if w.Active(sat1000) {
		t.Errorf("Sat should be inactive")
	}
}

func TestOvernightWindow(t *testing.T) {
	w := mustParse(t, "22:00-06:00 UTC daily")
	midnightish := time.Date(2026, 1, 5, 23, 30, 0, 0, time.UTC)
	if !w.Active(midnightish) {
		t.Errorf("23:30 should be active in overnight window")
	}
	early := time.Date(2026, 1, 5, 5, 0, 0, 0, time.UTC)
	if !w.Active(early) {
		t.Errorf("05:00 should be active in overnight window")
	}
	midday := time.Date(2026, 1, 5, 12, 0, 0, 0, time.UTC)
	if w.Active(midday) {
		t.Errorf("12:00 should be inactive in overnight window")
	}
}

func TestParseBadHour(t *testing.T) {
	if _, err := Parse("25:00-26:00"); err == nil {
		t.Errorf("bad hour should fail")
	}
	if _, err := Parse("not-a-schedule"); err == nil {
		t.Errorf("malformed schedule should fail")
	}
}
