package schedule

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

type Window struct {
	StartMin int
	EndMin   int
	Days     [7]bool
	Loc      *time.Location
	Raw      string
}

var dayNames = map[string]time.Weekday{
	"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday,
	"wed": time.Wednesday, "thu": time.Thursday, "fri": time.Friday, "sat": time.Saturday,
	"sunday": time.Sunday, "monday": time.Monday, "tuesday": time.Tuesday,
	"wednesday": time.Wednesday, "thursday": time.Thursday, "friday": time.Friday,
	"saturday": time.Saturday,
}

func Parse(raw string) (Window, error) {
	w := Window{Raw: raw, Loc: time.UTC}
	parts := strings.Fields(strings.TrimSpace(raw))
	if len(parts) == 0 {
		return w, fmt.Errorf("empty schedule")
	}
	rng := parts[0]
	dash := strings.Index(rng, "-")
	if dash <= 0 {
		return w, fmt.Errorf("schedule: expected HH:MM-HH:MM, got %q", rng)
	}
	start, err := parseClock(rng[:dash])
	if err != nil {
		return w, err
	}
	end, err := parseClock(rng[dash+1:])
	if err != nil {
		return w, err
	}
	w.StartMin, w.EndMin = start, end

	allDays(&w.Days, true)
	for _, p := range parts[1:] {
		pLower := strings.ToLower(p)
		if strings.EqualFold(p, "daily") {
			allDays(&w.Days, true)
			continue
		}
		if ok := tryParseDays(pLower, &w.Days); ok {
			continue
		}
		loc, err := time.LoadLocation(p)
		if err != nil {
			return w, fmt.Errorf("schedule: unknown tz or day spec %q: %w", p, err)
		}
		w.Loc = loc
	}
	return w, nil
}

func parseClock(s string) (int, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return 0, fmt.Errorf("schedule clock %q: expected HH:MM", s)
	}
	h, err := strconv.Atoi(parts[0])
	if err != nil || h < 0 || h > 23 {
		return 0, fmt.Errorf("schedule clock %q: bad hour", s)
	}
	m, err := strconv.Atoi(parts[1])
	if err != nil || m < 0 || m > 59 {
		return 0, fmt.Errorf("schedule clock %q: bad minute", s)
	}
	return h*60 + m, nil
}

func allDays(d *[7]bool, v bool) {
	for i := range d {
		d[i] = v
	}
}

func tryParseDays(s string, dst *[7]bool) bool {
	if strings.Contains(s, "-") && !strings.Contains(s, ",") {
		dash := strings.Index(s, "-")
		a, ok1 := dayNames[s[:dash]]
		b, ok2 := dayNames[s[dash+1:]]
		if ok1 && ok2 {
			allDays(dst, false)
			for d := int(a); ; d = (d + 1) % 7 {
				dst[d] = true
				if time.Weekday(d) == b {
					break
				}
			}
			return true
		}
	}
	if strings.Contains(s, ",") {
		segs := strings.Split(s, ",")
		for _, seg := range segs {
			if _, ok := dayNames[strings.TrimSpace(seg)]; !ok {
				return false
			}
		}
		allDays(dst, false)
		for _, seg := range segs {
			d := dayNames[strings.TrimSpace(seg)]
			dst[int(d)] = true
		}
		return true
	}
	if d, ok := dayNames[s]; ok {
		allDays(dst, false)
		dst[int(d)] = true
		return true
	}
	return false
}

func (w Window) Active(at time.Time) bool {
	t := at.In(w.Loc)
	day := t.Weekday()
	if !w.Days[int(day)] {
		return false
	}
	mins := t.Hour()*60 + t.Minute()
	if w.StartMin == w.EndMin {
		return true
	}
	if w.StartMin < w.EndMin {
		return mins >= w.StartMin && mins < w.EndMin
	}

	return mins >= w.StartMin || mins < w.EndMin
}
