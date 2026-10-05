package render

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Xwalims/netgraph/pkg/models"
)

// routeWith builds a small but realistic route.
func routeWith(hops ...models.Hop) *models.Route {
	return &models.Route{
		Target:           "example.com",
		Protocol:         models.ProtocolUDP,
		Hops:             hops,
		StartedAt:        time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC),
		Reached:          true,
		MaxHopsRequested: 30,
		ProbesPerHop:     3,
	}
}

func TestASCIIDrawsThePath(t *testing.T) {
	route := routeWith(
		models.Hop{Number: 1, Address: "192.168.1.1", RTT: time.Millisecond, IsPrivate: true, Sent: 3, Received: 3},
		models.Hop{Number: 2, Address: "203.0.113.1", RTT: 12 * time.Millisecond, ASN: 64500, OrgName: "Example Transit", Sent: 3, Received: 3},
		models.Hop{Number: 3, Address: "198.51.100.9", RTT: 20 * time.Millisecond, ASN: 64500, OrgName: "Example Transit", Sent: 3, Received: 3},
	)
	route.ReachedAt = 3

	out := ASCII(route)

	for _, want := range []string{"LOCAL", "192.168.1.1", "AS64500", "DESTINATION", "example.com"} {
		if !strings.Contains(out, want) {
			t.Errorf("output is missing %q:\n%s", want, out)
		}
	}
}

// TestASCIICollapsesOneOrganisation is the reason the drawing groups runs: a
// route through one provider's backbone is twenty hops of identical ownership,
// and printing all of them says nothing.
func TestASCIICollapsesOneOrganisation(t *testing.T) {
	var hops []models.Hop
	for i := 1; i <= 5; i++ {
		hops = append(hops, models.Hop{
			Number: i, Address: "198.51.100.1", RTT: time.Duration(i) * time.Millisecond,
			ASN: 64500, OrgName: "Backbone", Sent: 3, Received: 3,
		})
	}
	route := routeWith(hops...)
	route.ReachedAt = 5

	out := ASCII(route)

	if !strings.Contains(out, "Backbone") {
		t.Fatal("the organisation should still be named")
	}
	if !strings.Contains(out, "5 hops") {
		t.Errorf("a run of five hops should be summarised as a count:\n%s", out)
	}
	// One label, not five: that is the point of grouping.
	if count := strings.Count(out, "Backbone"); count > 2 {
		t.Errorf("the organisation appears %d times; it should be collapsed:\n%s", count, out)
	}
}

// TestASCIIDoesNotDrawAPathThatWasNotMeasured is the invariant that matters most
// in this package.
//
// An empty diagram with "LOCAL" at the top and "DESTINATION" at the bottom
// asserts both that a path exists and that nothing was lost, when in fact
// nothing was measured.
func TestASCIIDoesNotDrawAPathThatWasNotMeasured(t *testing.T) {
	route := &models.Route{
		Target:           "unreachable.example",
		Protocol:         models.ProtocolUDP,
		MaxHopsRequested: 30,
		Error:            "no hop answered",
	}

	out := ASCII(route)

	if strings.Contains(out, "DESTINATION") {
		t.Errorf("no destination should be drawn when nothing was reached:\n%s", out)
	}
	if !strings.Contains(out, "no route was measured") {
		t.Errorf("the output should say plainly that nothing was measured:\n%s", out)
	}
	// A loss figure over no probes is a claim about data that does not exist.
	if strings.Contains(out, "total loss") {
		t.Errorf("no loss figure should be printed for an unmeasured route:\n%s", out)
	}
}

// TestASCIISurfacesWarnings checks that the route's own caveats appear in the
// drawing, not only in the JSON.
func TestASCIISurfacesWarnings(t *testing.T) {
	route := routeWith(models.Hop{Number: 1, Address: "10.0.0.1", RTT: time.Millisecond, Sent: 3, Received: 3})
	route.Reached = false
	route.ReachedAt = 0
	route.Warnings = []string{"the final destination did not answer"}

	out := ASCII(route)
	if !strings.Contains(out, "the final destination did not answer") {
		t.Errorf("a warning must reach the output:\n%s", out)
	}
	if !strings.Contains(out, "not reached") {
		t.Errorf("an incomplete trace should say so:\n%s", out)
	}
}

func TestRowsAreOrderedAndComplete(t *testing.T) {
	route := routeWith(
		models.Hop{Number: 3, Address: "c", RTT: 3 * time.Millisecond, ASN: 64503, OrgName: "Third", Sent: 3, Received: 3},
		models.Hop{Number: 1, Address: "a", RTT: time.Millisecond, ASN: 64501, OrgName: "First", Sent: 3, Received: 2},
		models.Hop{Number: 2, Address: "b", RTT: 2 * time.Millisecond, ASN: 64502, OrgName: "Second", Sent: 3, Received: 3},
	)
	route.ReachedAt = 3

	rows := Rows(route)
	if len(rows) != 3 {
		t.Fatalf("expected three rows, got %d", len(rows))
	}
	if rows[0].Hop != 1 || rows[1].Hop != 2 || rows[2].Hop != 3 {
		t.Errorf("rows must be in hop order, got %d %d %d", rows[0].Hop, rows[1].Hop, rows[2].Hop)
	}
	if rows[0].Loss != "33%" && rows[0].Loss != "34%" {
		t.Errorf("one of three probes lost should read as 33%%, got %q", rows[0].Loss)
	}
	if !rows[2].Reached {
		t.Error("the destination hop should be marked as reached")
	}
}

// TestRowsIgnoreAStaleLossField checks the recomputation is unconditional.
//
// The guard used to read `if Sent > 0 && Received != Sent`, which left Hop.Loss
// in charge precisely when it was hardest to notice: a hop whose probes all
// answered. A Hop carrying a stale 0.5 next to 3 sent / 3 received printed
// "50%" for a hop that dropped nothing.
func TestRowsIgnoreAStaleLossField(t *testing.T) {
	cases := []struct {
		name string
		hop  models.Hop
		want string
	}{
		{
			"stale field, all probes answered",
			models.Hop{Number: 1, Sent: 3, Received: 3, Loss: 0.5},
			"0%",
		},
		{
			"stale field, every probe lost",
			models.Hop{Number: 2, Sent: 3, Received: 0, Loss: 0},
			"100%",
		},
		{
			"received above sent is not a negative loss",
			models.Hop{Number: 3, Sent: 3, Received: 5, Loss: 0},
			"0%",
		},
		{
			"consistent counts",
			models.Hop{Number: 4, Sent: 4, Received: 1, Loss: 0.75},
			"75%",
		},
	}

	for _, c := range cases {
		route := routeWith(c.hop)
		rows := Rows(route)
		if rows[0].Loss != c.want {
			t.Errorf("%s: sent=%d received=%d field=%.2f rendered %q, want %q",
				c.name, c.hop.Sent, c.hop.Received, c.hop.Loss, rows[0].Loss, c.want)
		}
	}
}

// TestCSVQuotesFieldsThatNeedIt covers the escaping, because a CSV reader that
// strips quotes unconditionally turns a value containing a comma into two
// columns and silently corrupts the data.
func TestCSVQuotesFieldsThatNeedIt(t *testing.T) {
	route := routeWith(models.Hop{
		Number: 1, Address: "198.51.100.1", RTT: time.Millisecond,
		OrgName: "Smith, Jones and Co", ASN: 64500, Sent: 1, Received: 1,
	})

	out := CSV(route)

	if !strings.Contains(out, `"Smith, Jones and Co"`) {
		t.Errorf("a value containing a comma must be quoted:\n%s", out)
	}
	if !strings.HasPrefix(out, "hop,address,hostname,asn,organisation") {
		t.Errorf("a header row is expected:\n%s", out)
	}
}

// TestCSVQuotesEmbeddedQuotes covers the doubled-quote rule.
func TestCSVQuotesEmbeddedQuotes(t *testing.T) {
	route := routeWith(models.Hop{
		Number: 1, Address: "198.51.100.1", RTT: time.Millisecond,
		Hostname: `a"quoted"name.example`, Sent: 1, Received: 1,
	})

	out := CSV(route)
	if !strings.Contains(out, `""quoted""`) {
		t.Errorf("an embedded quote must be doubled:\n%s", out)
	}
}

// TestHTMLHasNoExternalReferences is a property, not a style preference: a
// report that needs a network connection to display stops working exactly when
// someone tries to share it from an air-gapped machine.
func TestHTMLHasNoExternalReferences(t *testing.T) {
	route := routeWith(
		models.Hop{Number: 1, Address: "192.168.1.1", RTT: time.Millisecond, IsPrivate: true, Sent: 3, Received: 3},
		models.Hop{Number: 2, Address: "198.51.100.9", RTT: 20 * time.Millisecond, ASN: 64500, OrgName: "Example", Sent: 3, Received: 3},
	)
	route.ReachedAt = 2

	page := HTML(route)

	for _, forbidden := range []string{"http://", "https://", "//cdn", "src=", "@import"} {
		if strings.Contains(page, forbidden) {
			t.Errorf("the page must not reference %q", forbidden)
		}
	}
	if !strings.Contains(page, "<!doctype html>") {
		t.Error("the page should be a complete document")
	}
	if !strings.Contains(page, "Example") {
		t.Error("the organisation should appear in the report")
	}
}

// TestHTMLEscapesHostileValues matters because a hostname comes from the
// network, and an unescaped one is a script injection into the report.
func TestHTMLEscapesHostileValues(t *testing.T) {
	route := routeWith(models.Hop{
		Number: 1, Address: "198.51.100.1", RTT: time.Millisecond,
		OrgName: `<script>alert("xss")</script>`,
		Sent:    1, Received: 1,
	})

	page := HTML(route)

	if strings.Contains(page, "<script>alert") {
		t.Errorf("a value from the network must be escaped:\n%s", page)
	}
	if !strings.Contains(page, "&lt;script&gt;") {
		t.Error("the escaped form should be present")
	}
}

// TestHTMLStatesAnUnmeasuredRoute checks the empty case in the other format.
func TestHTMLStatesAnUnmeasuredRoute(t *testing.T) {
	route := &models.Route{Target: "unreachable.example", Error: "no hop answered"}

	page := HTML(route)

	if strings.Contains(page, "<table") {
		t.Errorf("no table should be drawn for an unmeasured route:\n%s", page)
	}
	if !strings.Contains(page, "No route was measured") {
		t.Errorf("the page should say nothing was measured:\n%s", page)
	}
}

func TestJSONRoundTrips(t *testing.T) {
	route := routeWith(models.Hop{Number: 1, Address: "198.51.100.1", RTT: time.Millisecond, Sent: 1, Received: 1})

	encoded, err := JSON(route)
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}

	var decoded models.Route
	if err := json.Unmarshal([]byte(encoded), &decoded); err != nil {
		t.Fatalf("the output is not valid JSON: %v", err)
	}
	if decoded.Target != route.Target {
		t.Errorf("target did not survive: got %q", decoded.Target)
	}
	if len(decoded.Hops) != 1 || decoded.Hops[0].Address != "198.51.100.1" {
		t.Errorf("hops did not survive: %+v", decoded.Hops)
	}
}

// TestComparisonNamesTheDivergence is the question a comparison exists to
// answer, so it has to be computed rather than left to the reader.
func TestComparisonNamesTheDivergence(t *testing.T) {
	first := routeWith(
		models.Hop{Number: 1, Address: "a", RTT: time.Millisecond, ASN: 64501, OrgName: "Shared", Sent: 1, Received: 1},
		models.Hop{Number: 2, Address: "b", RTT: 2 * time.Millisecond, ASN: 64502, OrgName: "RouteA", Sent: 1, Received: 1},
	)
	second := routeWith(
		models.Hop{Number: 1, Address: "a", RTT: time.Millisecond, ASN: 64501, OrgName: "Shared", Sent: 1, Received: 1},
		models.Hop{Number: 2, Address: "z", RTT: 9 * time.Millisecond, ASN: 64503, OrgName: "RouteB", Sent: 1, Received: 1},
	)

	comparison := &models.RouteComparison{
		Routes: []models.Route{*first, *second},
		Organisations: map[string]int{
			"Shared": 2, "RouteA": 1, "RouteB": 1,
		},
		DivergenceAt: 2,
	}

	out := Comparison(comparison)

	if !strings.Contains(out, "diverge at hop 2") {
		t.Errorf("the divergence point should be stated:\n%s", out)
	}
	if !strings.Contains(out, "example.com") {
		t.Errorf("both targets should be listed:\n%s", out)
	}
	if !strings.Contains(out, "Shared") {
		t.Errorf("the organisations should be summarised:\n%s", out)
	}
}

// TestComparisonReportsIdenticalRoutes checks the other branch: two routes that
// agree must be reported as agreeing.
func TestComparisonReportsIdenticalRoutes(t *testing.T) {
	hops := []models.Hop{
		{Number: 1, Address: "a", RTT: time.Millisecond, ASN: 64501, OrgName: "Only", Sent: 1, Received: 1},
		{Number: 2, Address: "b", RTT: 2 * time.Millisecond, ASN: 64502, OrgName: "Other", Sent: 1, Received: 1},
	}
	first := routeWith(hops...)
	second := routeWith(hops...)

	out := Comparison(&models.RouteComparison{
		Routes:        []models.Route{*first, *second},
		Organisations: map[string]int{"Only": 2, "Other": 2},
		DivergenceAt:  0,
	})

	if !strings.Contains(out, "share their whole path") {
		t.Errorf("identical routes should be reported as identical:\n%s", out)
	}
}

func TestLatencyChartShowsTheWindow(t *testing.T) {
	samples := make([]time.Duration, 100)
	for i := range samples {
		samples[i] = time.Duration(i+1) * time.Millisecond
	}

	out := LatencyChart(samples, 40)
	if out == "" {
		t.Fatal("the chart should not be empty")
	}
	if !strings.Contains(out, "..") {
		t.Errorf("the chart should state its range:\n%s", out)
	}
	// A 40-wide chart over 100 samples takes the most recent 40, not the first.
	if !strings.Contains(out, "61.0ms") {
		t.Errorf("the chart should cover the most recent window:\n%s", out)
	}
}

func TestLatencyChartHandlesNoSamples(t *testing.T) {
	if out := LatencyChart(nil, 40); !strings.Contains(out, "no samples") {
		t.Errorf("an empty series should say so, got %q", out)
	}
}

// TestLatencyChartHandlesAConstantSeries checks that a flat series does not
// divide by zero when the range is zero.
func TestLatencyChartHandlesAConstantSeries(t *testing.T) {
	samples := []time.Duration{5 * time.Millisecond, 5 * time.Millisecond, 5 * time.Millisecond}

	out := LatencyChart(samples, 10)
	if out == "" {
		t.Fatal("a constant series should still draw something")
	}
}
