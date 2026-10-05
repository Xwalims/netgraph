// Package render draws routes as text.
//
// Three modes, because three different questions get asked of a route: what
// path does it take (ASCII), what happened (table), and where is it on the map
// (HTML).
//
// # Every drawing says what it does not know
//
// A trace on a network that filters ICMP has no hops, and an empty diagram is
// indistinguishable from a trace of a local interface. So every renderer carries
// the route's warnings and error into its output. A picture that cannot be wrong
// about a route it never measured is worse than no picture.
package render

import (
	"encoding/json"
	"fmt"
	"html"
	"sort"
	"strings"
	"time"

	"github.com/Xwalims/netgraph/internal/latency"
	"github.com/Xwalims/netgraph/pkg/models"
)

// ASCII draws the route as a vertical chain, which is the shape a path has.
//
// Organisation names are collapsed: consecutive hops in the same AS are drawn
// once with a count, because a route through a single provider's backbone can
// run to twenty hops of identical ownership and printing all of them says
// nothing.
func ASCII(route *models.Route) string {
	var out strings.Builder

	out.WriteString("\n")
	writeWarnings(&out, route)
	out.WriteString("\n")

	if len(route.Hops) == 0 {
		// Nothing was measured, so no path is drawn. Drawing "LOCAL -> DESTINATION"
		// with nothing between them, and reporting 0% loss, asserts two things
		// that are false: that a path was found, and that nothing was lost.
		if route.Error != "" {
			out.WriteString(fmt.Sprintf("  no route was measured\n\n  %s\n", route.Error))
		} else {
			out.WriteString("  no route was measured\n")
		}
		out.WriteString("\n")
		return out.String()
	}

	out.WriteString("  LOCAL\n")
	out.WriteString("    |\n    v\n")

	// Group consecutive hops by organisation.
	type group struct {
		label   string
		hops    []models.Hop
		private bool
	}
	var groups []group
	for _, hop := range route.Hops {
		label := hopLabel(hop)
		if len(groups) > 0 && groups[len(groups)-1].label == label {
			groups[len(groups)-1].hops = append(groups[len(groups)-1].hops, hop)
			continue
		}
		groups = append(groups, group{label: label, hops: []models.Hop{hop}, private: hop.IsPrivate})
	}

	for _, g := range groups {
		hops := g.hops
		// A hop with an address shows the address; one without is shown as the
		// count of unanswered TTLs, which is a fact rather than a router.
		if len(hops) == 1 {
			hop := hops[0]
			if hop.Address != "" {
				out.WriteString(fmt.Sprintf("  %s\n", hop.Address))
				if hop.Hostname != "" {
					out.WriteString(fmt.Sprintf("    %s\n", dimmed(hop.Hostname)))
				}
			} else {
				out.WriteString(fmt.Sprintf("  hop %d  (no reply)\n", hop.Number))
			}
		} else {
			first := hops[0].Number
			last := hops[len(hops)-1].Number
			out.WriteString(fmt.Sprintf("  %s  [%d hops]\n", g.label, len(hops)))
			out.WriteString(dimmed(fmt.Sprintf("    hops %d..%d, %s", first, last, orgRange(hops))))
		}

		// Latency of the last hop in the group: the cumulative increase, which is
		// the interesting number, rather than each hop's own RTT which would
		// just be a column of similar values.
		if len(hops) > 0 {
			last := hops[len(hops)-1]
			out.WriteString(dimmed(fmt.Sprintf("    %s", latency.Format(last.RTT))))
		}
		out.WriteString("    |\n    v\n")
	}

	// The destination, once.
	if route.Reached {
		target := route.ResolvedAddress
		if target == "" {
			target = route.Target
		}
		out.WriteString(fmt.Sprintf("  DESTINATION\n"))
		out.WriteString(fmt.Sprintf("    %s\n", target))
	} else {
		out.WriteString("  DESTINATION\n")
		out.WriteString(dimmed(fmt.Sprintf("    %s  (not reached within %d hops)\n", route.Target, route.MaxHopsRequested)))
	}

	out.WriteString(fmt.Sprintf("\n  %d hops measured, %s total loss, %s\n\n",
		len(route.Hops),
		percent(route.TotalLoss),
		latency.Format(route.Duration)))
	return out.String()
}

// hopLabel names a hop, preferring an ASN and falling back to the address.
func hopLabel(hop models.Hop) string {
	switch {
	case hop.IsPrivate:
		return "PRIVATE NETWORK"
	case hop.ASN != 0 && hop.OrgName != "":
		return fmt.Sprintf("AS%d %s", hop.ASN, hop.OrgName)
	case hop.ASN != 0:
		return fmt.Sprintf("AS%d", hop.ASN)
	case hop.OrgName != "":
		return hop.OrgName
	case hop.Address != "":
		return hop.Address
	default:
		return fmt.Sprintf("hop %d", hop.Number)
	}
}

// orgRange describes a run of hops that share an organisation.
func orgRange(hops []models.Hop) string {
	if len(hops) == 0 {
		return ""
	}
	if len(hops) == 1 {
		return ""
	}
	if hops[0].ASN == 0 {
		return ""
	}
	return fmt.Sprintf("AS%d", hops[0].ASN)
}

// writeWarnings puts the route's own caveats at the top, where they are read
// before the drawing rather than after it.
func writeWarnings(out *strings.Builder, route *models.Route) {
	if route.Error != "" {
		fmt.Fprintf(out, "  %s\n", route.Error)
	}
	for _, warning := range route.Warnings {
		fmt.Fprintf(out, "  warning: %s\n", warning)
	}
	if len(route.Warnings) > 0 || route.Error != "" {
		out.WriteString("\n")
	}
}

func dimmed(text string) string { return text }

// percent renders a loss fraction.
func percent(loss float64) string {
	return fmt.Sprintf("%.0f%%", loss*100)
}

// Table renders a route as rows, which is what `--json` output and the TUI both
// need and what a wide terminal can actually fit.
type TableRow struct {
	Hop      int    `json:"hop"`
	Address  string `json:"address,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	ASN      uint32 `json:"asn,omitempty"`
	Org      string `json:"org,omitempty"`
	Country  string `json:"country,omitempty"`
	Private  bool   `json:"private,omitempty"`
	RTT      string `json:"rtt"`
	Loss     string `json:"loss"`
	Reached  bool   `json:"reached"`
}

// Rows converts a route into table rows.
func Rows(route *models.Route) []TableRow {
	rows := make([]TableRow, 0, len(route.Hops))
	for _, hop := range route.Hops {
		// The loss is recomputed from Sent and Received rather than read from
		// Hop.Loss. A Hop built by hand, or by any caller that fills in the counts
		// and forgets the derived field, would otherwise report 0% loss on a hop
		// that dropped two probes of three -- the one number that must never be
		// wrong on a network diagnostic.
		loss := hop.Loss
		if hop.Sent > 0 && hop.Received >= 0 && hop.Received != hop.Sent {
			loss = float64(hop.Sent-hop.Received) / float64(hop.Sent)
		}

		rows = append(rows, TableRow{
			Hop:      hop.Number,
			Address:  hop.Address,
			Hostname: hop.Hostname,
			ASN:      hop.ASN,
			Org:      hop.OrgName,
			Country:  hop.Country,
			Private:  hop.IsPrivate,
			RTT:      latency.Format(hop.RTT),
			Loss:     percent(loss),
			Reached:  hop.Number == route.ReachedAt,
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Hop < rows[j].Hop })
	return rows
}

// Comparison renders several routes side by side and names what differs.
func Comparison(comparison *models.RouteComparison) string {
	var out strings.Builder
	out.WriteString("\n")
	out.WriteString(fmt.Sprintf("  %d routes\n\n", len(comparison.Routes)))

	width := 0
	for _, route := range comparison.Routes {
		if len(route.Target) > width {
			width = len(route.Target)
		}
	}

	for i, route := range comparison.Routes {
		reached := "not reached"
		if route.Reached {
			reached = "reached"
		}
		fmt.Fprintf(&out, "  %-*s  %2d hops  loss %-4s  %s\n",
			width, route.Target, len(route.Hops), percent(route.TotalLoss), reached)
		if i < len(comparison.Routes)-1 {
			out.WriteString("  " + strings.Repeat("-", width+40) + "\n")
		}
	}

	if comparison.DivergenceAt > 0 {
		out.WriteString(fmt.Sprintf("\n  the routes diverge at hop %d\n", comparison.DivergenceAt))
	} else if len(comparison.Routes) > 1 {
		out.WriteString("\n  the routes share their whole path\n")
	}

	if len(comparison.Organisations) > 0 {
		out.WriteString("\n  organisations\n")
		names := make([]string, 0, len(comparison.Organisations))
		for name := range comparison.Organisations {
			names = append(names, name)
		}
		sort.Slice(names, func(i, j int) bool {
			return comparison.Organisations[names[i]] > comparison.Organisations[names[j]]
		})
		for _, name := range names {
			fmt.Fprintf(&out, "    %-40s %d route(s)\n", name, comparison.Organisations[name])
		}
	}
	out.WriteString("\n")
	return out.String()
}

// LatencyChart draws a sparkline-style history, because a column of numbers does
// not show the shape of a change.
func LatencyChart(samples []time.Duration, width int) string {
	if len(samples) == 0 {
		return "  (no samples)\n"
	}
	if width <= 0 {
		width = 40
	}
	if width > len(samples) {
		width = len(samples)
	}

	// Take the most recent window, so the chart shows now rather than the start.
	view := samples[len(samples)-width:]

	lowest, highest := view[0], view[0]
	for _, sample := range view {
		if sample < lowest {
			lowest = sample
		}
		if sample > highest {
			highest = sample
		}
	}

	blocks := []rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

	var out strings.Builder
	for _, sample := range view {
		index := 0
		if highest > lowest {
			index = int(float64(sample-lowest) / float64(highest-lowest) * float64(len(blocks)-1))
		}
		out.WriteRune(blocks[index])
	}
	return "  " + out.String() + fmt.Sprintf("   %s .. %s\n", latency.Format(lowest), latency.Format(highest))
}

// JSON renders a value as indented JSON.
func JSON(value any) (string, error) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return "", fmt.Errorf("cannot encode the result: %w", err)
	}
	return string(encoded) + "\n", nil
}

// CSV renders routes as comma-separated values.
//
// Quoting is applied per field rather than by wrapping everything, because a
// CSV reader that strips quotes unconditionally turns a hostname containing a
// comma into two columns and silently corrupts the data.
func CSV(route *models.Route) string {
	var out strings.Builder
	out.WriteString("hop,address,hostname,asn,organisation,country,private,rtt_ms,loss_pct,reached\n")
	for _, row := range Rows(route) {
		fields := []string{
			fmt.Sprint(row.Hop),
			row.Address,
			row.Hostname,
			optionalNumber(row.ASN),
			row.Org,
			row.Country,
			fmt.Sprint(row.Private),
			row.RTT,
			strings.TrimSuffix(row.Loss, "%"),
			fmt.Sprint(row.Reached),
		}
		quoted := make([]string, len(fields))
		for i, field := range fields {
			quoted[i] = csvField(field)
		}
		out.WriteString(strings.Join(quoted, ",") + "\n")
	}
	return out.String()
}

func optionalNumber(value uint32) string {
	if value == 0 {
		return ""
	}
	return fmt.Sprint(value)
}

// csvField quotes a field when it contains a separator, a quote or a newline.
func csvField(field string) string {
	if !strings.ContainsAny(field, ",\"\n\r") {
		return field
	}
	return `"` + strings.ReplaceAll(field, `"`, `""`) + `"`
}

// HTML renders a route as a self-contained page.
//
// The output has no external references at all: no CDN, no fonts, no map
// tiles. A report that needs a network connection to display is a report that
// stops working exactly when someone is trying to share it from an air-gapped
// machine, and a map that silently fails to load would leave the reader with a
// blank rectangle that looks like a bug.
func HTML(route *models.Route) string {
	var out strings.Builder
	out.WriteString(htmlHeader(route))

	out.WriteString(`<h1>netgraph trace report</h1>`)
	out.WriteString(fmt.Sprintf(`<p class="meta">target <strong>%s</strong> &middot; %s &middot; %s &middot; %d hops &middot; %s</p>`,
		html.EscapeString(route.Target),
		html.EscapeString(string(route.Protocol)),
		html.EscapeString(route.StartedAt.Format(time.RFC3339)),
		len(route.Hops),
		percent(route.TotalLoss)))

	if route.Error != "" {
		out.WriteString(fmt.Sprintf(`<p class="error">%s</p>`, html.EscapeString(route.Error)))
	}
	for _, warning := range route.Warnings {
		out.WriteString(fmt.Sprintf(`<p class="warning">%s</p>`, html.EscapeString(warning)))
	}

	if len(route.Hops) == 0 {
		out.WriteString(`<p class="empty"><strong>No route was measured.</strong> ` +
			`No hop answered, so no path is drawn. An empty diagram is not a short ` +
			`route.</p>`)
		out.WriteString(htmlFooter())
		return out.String()
	}

	// The path as a horizontal chain of organisations, because a map without
	// coordinates would be a picture of nothing.
	out.WriteString(`<h2>Path</h2>`)
	out.WriteString(`<div class="path">`)
	previous := ""
	for _, hop := range route.Hops {
		label := hopLabel(hop)
		if label == previous {
			out.WriteString(`<span class="hop same">&middot;</span>`)
			continue
		}
		previous = label
		title := "no AS data"
		if hop.ASN != 0 {
			title = fmt.Sprintf("AS%d", hop.ASN)
		}
		out.WriteString(fmt.Sprintf(
			`<span class="hop" title="%s"><b>%d</b> %s<br><small>%s</small></span>`,
			html.EscapeString(title), hop.Number,
			html.EscapeString(label), html.EscapeString(latency.Format(hop.RTT))))
	}
	out.WriteString(`</div>`)

	out.WriteString(`<h2>Hops</h2>`)
	out.WriteString(`<table><thead><tr><th>Hop</th><th>Address</th><th>ASN</th><th>Organisation</th><th>Country</th><th>RTT</th><th>Loss</th></tr></thead><tbody>`)
	for _, row := range Rows(route) {
		out.WriteString("<tr>")
		fmt.Fprintf(&out, "<td>%d</td>", row.Hop)
		fmt.Fprintf(&out, "<td class=\"mono\">%s</td>", html.EscapeString(row.Address))
		fmt.Fprintf(&out, "<td>%s</td>", html.EscapeString(optionalNumber(row.ASN)))
		fmt.Fprintf(&out, "<td>%s</td>", html.EscapeString(row.Org))
		fmt.Fprintf(&out, "<td>%s</td>", html.EscapeString(row.Country))
		fmt.Fprintf(&out, "<td>%s</td>", html.EscapeString(row.RTT))
		fmt.Fprintf(&out, "<td>%s</td>", html.EscapeString(row.Loss))
		out.WriteString("</tr>")
	}
	out.WriteString("</tbody></table>")

	out.WriteString(htmlFooter())
	return out.String()
}

func htmlHeader(route *models.Route) string {
	return fmt.Sprintf(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>netgraph: %s</title>
<style>
  :root { color-scheme: light dark; }
  body { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
         max-width: 68rem; margin: 0 auto; padding: 1.5rem; line-height: 1.5; }
  h1 { font-size: 1.3rem; margin-bottom: .25rem; }
  h2 { font-size: 1rem; margin-top: 2rem; text-transform: uppercase;
       letter-spacing: .08em; opacity: .7; }
  .meta { opacity: .7; font-size: .875rem; margin-top: 0; }
  .error, .warning, .empty { padding: .6rem .8rem; border-left: 3px solid;
       margin: 1rem 0; font-size: .9rem; }
  .error { border-color: #c0392b; background: rgba(192,57,43,.08); }
  .warning { border-color: #d68910; background: rgba(214,137,16,.08); }
  .empty { border-color: #7f8c8d; background: rgba(127,140,141,.08); }
  .path { display: flex; flex-wrap: wrap; gap: .4rem; align-items: stretch; }
  .hop { border: 1px solid currentColor; border-radius: .3rem; padding: .4rem .6rem;
         font-size: .8rem; max-width: 14rem; }
  .hop.same { border: none; opacity: .35; align-self: center; }
  .hop small { opacity: .6; }
  table { border-collapse: collapse; width: 100%%; font-size: .85rem; }
  th, td { text-align: left; padding: .35rem .5rem;
           border-bottom: 1px solid rgba(128,128,128,.25); }
  th { font-weight: 600; opacity: .7; }
  td.mono { font-family: inherit; }
  footer { margin-top: 2rem; font-size: .8rem; opacity: .6;
           border-top: 1px solid rgba(128,128,128,.25); padding-top: .8rem; }
</style>
</head>
<body>
`, html.EscapeString(route.Target))
}

func htmlFooter() string {
	return fmt.Sprintf(`<footer>
Generated by netgraph %s. This page contains no external references: it opens
with no network connection, which is the point of an export you send to someone.
</footer>
</body>
</html>
`, time.Now().Format("2006-01-02 15:04:05 MST"))
}
