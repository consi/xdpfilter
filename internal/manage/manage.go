// SPDX-License-Identifier: GPL-2.0

// Package manage implements the interactive xdpfilter operations console.
package manage

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/consi/xdpfilter/internal/config"
	"github.com/consi/xdpfilter/internal/dataplane"
	"github.com/consi/xdpfilter/internal/flowmonitor"
	"github.com/consi/xdpfilter/internal/stats"
)

type ui struct {
	app                                              *tview.Application
	pages                                            *tview.Pages
	content                                          *tview.Pages
	ctrl                                             *Controller
	version                                          string
	header, footer, dashboard                        *tview.TextView
	allowTable, flowTable                            *tview.Table
	flowMonitorRules, flowMonitorAlerts              *tview.Table
	flowMonitorEngine, flowMonitorEditor             *tview.Form
	allowInput                                       *tview.InputField
	flowMonitorCIDR, flowMonitorPPS, flowMonitorMbps *tview.InputField
	allowSelected                                    int
	flowMonitorSelected                              int
	flowProto, flowVLAN, flowText                    string
	current                                          string
	validation                                       map[string]string
	flowRefreshing                                   atomic.Bool
	cancel                                           context.CancelFunc
}

// Run starts the root-only interactive manager.
func Run(path, version string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("manage must run as root (try: sudo xdpfilter manage)")
	}
	if fi, err := os.Stdin.Stat(); err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return fmt.Errorf("manage requires an interactive terminal")
	}
	ctrl, err := NewController(path)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	u := &ui{app: tview.NewApplication(), pages: tview.NewPages(), content: tview.NewPages(), ctrl: ctrl,
		version: version, current: "dashboard", validation: map[string]string{}, allowSelected: -1, flowMonitorSelected: -1, cancel: cancel}
	u.build(ctx)
	err = u.app.EnableMouse(true).EnablePaste(true).Run()
	cancel()
	return err
}

func (u *ui) build(ctx context.Context) {
	u.header = tview.NewTextView().SetDynamicColors(true)
	u.footer = tview.NewTextView().SetDynamicColors(true)
	u.dashboard = tview.NewTextView().SetDynamicColors(true)
	u.dashboard.SetBorder(true).SetTitle(" Live dashboard ")

	menu := tview.NewList().ShowSecondaryText(false)
	menu.SetBorder(true).SetTitle(" Manage ")
	tabs := []struct {
		name, label string
		view        tview.Primitive
	}{
		{"dashboard", "Dashboard", u.dashboard},
		{"policy", "Policy", u.policyForm()},
		{"allowlist", "Allowlist", u.allowlistView()},
		{"flows", "Flows", u.flowsView()},
		{"flowmonitor", "Flow Monitoring", u.flowMonitoringView()},
		{"dataplane", "Dataplane", u.dataplaneForm()},
		{"runtime", "Runtime / Tuning", u.runtimeForm()},
		{"operations", "Operations", u.operationsForm()},
	}
	for i, tab := range tabs {
		u.content.AddPage(tab.name, tab.view, true, i == 0)
		name := tab.name
		menu.AddItem(tab.label, "", rune('1'+i), func() { u.current = name; u.content.SwitchToPage(name); u.updateChrome() })
	}
	body := tview.NewFlex().SetDirection(tview.FlexColumn).AddItem(menu, 24, 0, true).AddItem(u.content, 0, 1, false)
	root := tview.NewGrid().SetRows(1, 0, 1).SetColumns(0).
		AddItem(u.header, 0, 0, 1, 1, 0, 0, false).AddItem(body, 1, 0, 1, 1, 0, 0, true).AddItem(u.footer, 2, 0, 1, 1, 0, 0, false)
	u.pages.AddPage("main", root, true, true)
	u.app.SetRoot(u.pages, true).SetInputCapture(u.keys)
	u.updateAllowlist()
	u.updateChrome()
	u.startSampler(ctx)
}

func (u *ui) keys(ev *tcell.EventKey) *tcell.EventKey {
	if ev.Key() == tcell.KeyCtrlS {
		u.apply()
		return nil
	}
	if ev.Key() == tcell.KeyRune {
		switch ev.Rune() {
		case 'q':
			u.quit()
			return nil
		case '?':
			u.message("Help", "1-8 switch sections\nTab/Shift-Tab move focus\nCtrl-S applies staged changes\nr refreshes flows\nq quits", nil)
			return nil
		case 'r':
			if u.current == "flows" {
				u.requestFlowRefresh()
			}
		}
	}
	return ev
}

func (u *ui) updateChrome() {
	dirty := ""
	if u.ctrl.Dirty() {
		dirty = " [yellow]● STAGED[-]"
	}
	u.header.SetText(fmt.Sprintf("[::b] xdpfilter %s[-]  config: %s%s", u.version, u.ctrl.Path, dirty))
	errText := ""
	if len(u.validation) > 0 {
		errText = "  [red]invalid fields: " + strings.Join(sortedKeys(u.validation), ", ") + "[-]"
	}
	u.footer.SetText(" [yellow]1-8[-] sections  [yellow]Ctrl-S[-] Apply  [yellow]?[-] help  [yellow]q[-] quit" + errText)
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (u *ui) changed() { u.updateChrome() }
func (u *ui) valid(name string, ok bool) {
	if ok {
		delete(u.validation, name)
	} else {
		u.validation[name] = "invalid"
	}
	u.updateChrome()
}

func titled(p tview.Primitive, title string) tview.Primitive {
	if b, ok := p.(interface{ SetBorder(bool) *tview.Box }); ok {
		b.SetBorder(true).SetTitle(" " + title + " ")
	}
	return p
}

func (u *ui) policyForm() tview.Primitive {
	c := u.ctrl.Staged
	f := tview.NewForm()
	f.SetBorder(true).SetTitle(" Live policy (staged until Apply) ")
	modes := []string{"monitor", "enforce"}
	mi := 0
	if c.Mode == "enforce" {
		mi = 1
	}
	f.AddDropDown("Mode", modes, mi, func(s string, _ int) { c.Mode = s; u.changed() })
	checks := []struct {
		label string
		value *bool
	}{
		{"Strict out-of-state", &c.OosStrict}, {"Allow allowlisted servers", &c.AllowInboundServers}, {"Allow all inbound SYN", &c.AllowInboundSYN},
		{"Filter UDP", &c.FilterUDP}, {"Drop TCP fragments", &c.DropFrags}, {"Drop bad TCP flags", &c.DropBadFlags},
		{"Drop deep VLAN", &c.DropVlanDeep}, {"Drop UDP fragments", &c.DropUDPFrags}, {"Reject TCP with RST", &c.RejectWithRST},
	}
	for _, x := range checks {
		ptr := x.value
		f.AddCheckbox(x.label, *ptr, func(v bool) { *ptr = v; u.changed() })
	}
	u.addU32(f, "SYN TTL seconds", "ttl_syn", c.TTLSyn, func(v uint32) { c.TTLSyn = v })
	u.addU32(f, "Established TTL", "ttl_est", c.TTLEst, func(v uint32) { c.TTLEst = v })
	u.addU32(f, "Closing TTL", "ttl_closing", c.TTLClosing, func(v uint32) { c.TTLClosing = v })
	u.addU32(f, "UDP TTL", "ttl_udp", c.TTLUdp, func(v uint32) { c.TTLUdp = v })
	return f
}

func (u *ui) allowlistView() tview.Primitive {
	u.allowTable = tview.NewTable().SetSelectable(true, false).SetFixed(1, 0)
	u.allowTable.SetBorder(true).SetTitle(" Server allowlist (TCP + UDP) ")
	u.allowTable.SetSelectionChangedFunc(func(row, _ int) {
		u.allowSelected = row - 1
		if u.allowSelected >= 0 && u.allowSelected < len(u.ctrl.Staged.ServerAllow) {
			u.allowInput.SetText(u.ctrl.Staged.ServerAllow[u.allowSelected])
		}
	})
	u.allowInput = tview.NewInputField().SetLabel("IPv4:port ").SetFieldWidth(30)
	form := tview.NewForm().AddFormItem(u.allowInput)
	form.AddButton("Add / Replace", u.saveAllowEntry).AddButton("Delete selected", u.deleteAllowEntry)
	form.SetBorder(true).SetTitle(" Edit ")
	return tview.NewFlex().SetDirection(tview.FlexRow).AddItem(form, 5, 0, true).AddItem(u.allowTable, 0, 1, false)
}

func (u *ui) saveAllowEntry() {
	ip, port, err := config.ParseHostPort(strings.TrimSpace(u.allowInput.GetText()))
	if err != nil {
		u.message("Invalid allowlist entry", err.Error(), nil)
		return
	}
	entry := net.JoinHostPort(ip.String(), strconv.Itoa(int(port)))
	for i, v := range u.ctrl.Staged.ServerAllow {
		if v == entry && i != u.allowSelected {
			u.message("Duplicate", "That server is already listed.", nil)
			return
		}
	}
	if u.allowSelected >= 0 && u.allowSelected < len(u.ctrl.Staged.ServerAllow) {
		u.ctrl.Staged.ServerAllow[u.allowSelected] = entry
	} else {
		u.ctrl.Staged.ServerAllow = append(u.ctrl.Staged.ServerAllow, entry)
	}
	u.allowSelected = -1
	u.allowInput.SetText("")
	u.updateAllowlist()
	u.changed()
}
func (u *ui) deleteAllowEntry() {
	if u.allowSelected < 0 || u.allowSelected >= len(u.ctrl.Staged.ServerAllow) {
		return
	}
	i := u.allowSelected
	u.ctrl.Staged.ServerAllow = append(u.ctrl.Staged.ServerAllow[:i], u.ctrl.Staged.ServerAllow[i+1:]...)
	u.allowSelected = -1
	u.allowInput.SetText("")
	u.updateAllowlist()
	u.changed()
}
func (u *ui) updateAllowlist() {
	if u.allowTable == nil {
		return
	}
	u.allowTable.Clear()
	u.allowTable.SetCell(0, 0, tview.NewTableCell("#").SetSelectable(false)).SetCell(0, 1, tview.NewTableCell("Protected server").SetSelectable(false))
	for i, v := range u.ctrl.Staged.ServerAllow {
		u.allowTable.SetCell(i+1, 0, tview.NewTableCell(strconv.Itoa(i+1))).SetCell(i+1, 1, tview.NewTableCell(v))
	}
}

func (u *ui) flowsView() tview.Primitive {
	u.flowProto = "ALL"
	filter := tview.NewForm()
	filter.AddDropDown("Protocol", []string{"ALL", "TCP", "UDP"}, 0, func(s string, _ int) { u.flowProto = s })
	vin := tview.NewInputField().SetLabel("VLAN (-1 all) ").SetText("-1").SetFieldWidth(8)
	vin.SetChangedFunc(func(s string) { u.flowVLAN = s })
	filter.AddFormItem(vin)
	tin := tview.NewInputField().SetLabel("Search ").SetFieldWidth(24)
	tin.SetChangedFunc(func(s string) { u.flowText = s })
	filter.AddFormItem(tin)
	filter.AddButton("Refresh", u.requestFlowRefresh)
	filter.SetBorder(true).SetTitle(" Bounded flow scan ")
	u.flowTable = tview.NewTable().SetSelectable(true, false).SetFixed(1, 0)
	u.flowTable.SetBorder(true).SetTitle(" Flows ")
	return tview.NewFlex().SetDirection(tview.FlexRow).AddItem(filter, 8, 0, true).AddItem(u.flowTable, 0, 1, false)
}

func (u *ui) flowMonitoringView() tview.Primitive {
	c := u.ctrl.Staged
	u.flowMonitorEngine = tview.NewForm()
	u.flowMonitorEngine.SetHorizontal(true).SetItemPadding(1)
	u.flowMonitorEngine.SetBorderPadding(0, 0, 1, 1)
	u.flowMonitorEngine.SetBorder(true).SetTitle(" Flow monitoring engine (sample 1/N) ")
	u.flowMonitorEngine.AddCheckbox("Enabled", c.FlowMonitoring.Enabled, func(v bool) { c.FlowMonitoring.Enabled = v; u.changed() })
	u.addU32Width(u.flowMonitorEngine, "Sample 1/N", "flow_monitoring.sample_every", c.FlowMonitoring.SampleEvery, 6, func(v uint32) { c.FlowMonitoring.SampleEvery = v })
	u.addU32Width(u.flowMonitorEngine, "Max flows", "flow_monitoring.max_flows", c.FlowMonitoring.MaxFlows, 9, func(v uint32) { c.FlowMonitoring.MaxFlows = v })

	u.flowMonitorCIDR = tview.NewInputField().SetLabel("CIDR ").SetFieldWidth(18)
	u.flowMonitorPPS = tview.NewInputField().SetLabel("PPS ").SetText("0").SetFieldWidth(9)
	u.flowMonitorMbps = tview.NewInputField().SetLabel("Mbps ").SetText("0").SetFieldWidth(8)
	u.flowMonitorEditor = tview.NewForm()
	u.flowMonitorEditor.SetHorizontal(true).SetItemPadding(0)
	u.flowMonitorEditor.SetBorderPadding(0, 0, 1, 1)
	u.flowMonitorEditor.SetBorder(true).SetTitle(" CIDR thresholds (0 disables PPS or Mbps) ")
	u.flowMonitorEditor.AddFormItem(u.flowMonitorCIDR).AddFormItem(u.flowMonitorPPS).AddFormItem(u.flowMonitorMbps)
	u.flowMonitorEditor.AddButton("Add / Replace", u.saveFlowMonitorRule).AddButton("Delete CIDR", u.deleteFlowMonitorRule)
	u.linkFlowMonitorForms()

	u.flowMonitorRules = tview.NewTable().SetSelectable(true, false).SetFixed(1, 0)
	u.flowMonitorRules.SetBorder(true).SetTitle(" CIDR rules — longest prefix wins ")
	u.flowMonitorRules.SetSelectionChangedFunc(func(row, _ int) {
		u.flowMonitorSelected = row - 1
		if u.flowMonitorSelected >= 0 && u.flowMonitorSelected < len(c.FlowMonitoring.CIDRs) {
			rule := c.FlowMonitoring.CIDRs[u.flowMonitorSelected]
			u.flowMonitorCIDR.SetText(rule.CIDR)
			u.flowMonitorPPS.SetText(strconv.FormatUint(rule.PPSThreshold, 10))
			u.flowMonitorMbps.SetText(strconv.FormatFloat(rule.MbpsThreshold, 'f', -1, 64))
		}
	})
	u.flowMonitorAlerts = tview.NewTable().SetSelectable(true, false).SetFixed(1, 0)
	u.flowMonitorAlerts.SetBorder(true).SetTitle(" Current over-threshold flows — waiting for snapshot ")
	u.updateFlowMonitorRules()

	return tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(u.flowMonitorEngine, 3, 0, true).
		AddItem(u.flowMonitorEditor, 5, 0, false).
		AddItem(u.flowMonitorRules, 5, 0, false).
		AddItem(u.flowMonitorAlerts, 0, 1, false)
}

// linkFlowMonitorForms preserves natural Tab traversal while keeping engine
// settings and CIDR rule editing in visually separate forms.
func (u *ui) linkFlowMonitorForms() {
	u.flowMonitorEngine.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		item, _ := u.flowMonitorEngine.GetFocusedItemIndex()
		if ev.Key() == tcell.KeyTab && item == u.flowMonitorEngine.GetFormItemCount()-1 {
			u.flowMonitorEditor.SetFocus(0)
			u.app.SetFocus(u.flowMonitorEditor)
			return nil
		}
		if ev.Key() == tcell.KeyBacktab && item == 0 {
			u.flowMonitorEditor.SetFocus(u.flowMonitorEditor.GetFormItemCount() + u.flowMonitorEditor.GetButtonCount() - 1)
			u.app.SetFocus(u.flowMonitorEditor)
			return nil
		}
		return ev
	})
	u.flowMonitorEditor.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		item, button := u.flowMonitorEditor.GetFocusedItemIndex()
		if ev.Key() == tcell.KeyTab && button == u.flowMonitorEditor.GetButtonCount()-1 {
			u.flowMonitorEngine.SetFocus(0)
			u.app.SetFocus(u.flowMonitorEngine)
			return nil
		}
		if ev.Key() == tcell.KeyBacktab && item == 0 {
			u.flowMonitorEngine.SetFocus(u.flowMonitorEngine.GetFormItemCount() - 1)
			u.app.SetFocus(u.flowMonitorEngine)
			return nil
		}
		return ev
	})
}

func (u *ui) saveFlowMonitorRule() {
	cidr := strings.TrimSpace(u.flowMonitorCIDR.GetText())
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil || ip.To4() == nil || network.String() != cidr {
		u.message("Invalid CIDR", "Use a canonical IPv4 CIDR such as 10.0.0.0/24.", nil)
		return
	}
	pps, ppsErr := strconv.ParseUint(strings.TrimSpace(u.flowMonitorPPS.GetText()), 10, 64)
	mbps, mbpsErr := strconv.ParseFloat(strings.TrimSpace(u.flowMonitorMbps.GetText()), 64)
	if ppsErr != nil || mbpsErr != nil || mbps < 0 || math.IsNaN(mbps) || math.IsInf(mbps, 0) || (pps == 0 && mbps == 0) {
		u.message("Invalid thresholds", "Configure at least one non-negative PPS or Mbps threshold.", nil)
		return
	}
	replace := u.flowMonitorSelected
	for i, existing := range u.ctrl.Staged.FlowMonitoring.CIDRs {
		if existing.CIDR != cidr {
			continue
		}
		if replace >= 0 && i != replace {
			u.message("Duplicate", "That CIDR already has a rule.", nil)
			return
		}
		replace = i // typed exact CIDR replaces it without requiring table focus
	}
	rule := config.FlowMonitorCIDR{CIDR: cidr, PPSThreshold: pps, MbpsThreshold: mbps}
	if replace >= 0 && replace < len(u.ctrl.Staged.FlowMonitoring.CIDRs) {
		u.ctrl.Staged.FlowMonitoring.CIDRs[replace] = rule
	} else {
		u.ctrl.Staged.FlowMonitoring.CIDRs = append(u.ctrl.Staged.FlowMonitoring.CIDRs, rule)
	}
	u.flowMonitorSelected = -1
	u.flowMonitorCIDR.SetText("")
	u.flowMonitorPPS.SetText("0")
	u.flowMonitorMbps.SetText("0")
	u.updateFlowMonitorRules()
	u.changed()
}

func (u *ui) deleteFlowMonitorRule() {
	i := u.flowMonitorSelected
	if i < 0 || i >= len(u.ctrl.Staged.FlowMonitoring.CIDRs) {
		cidr := strings.TrimSpace(u.flowMonitorCIDR.GetText())
		for idx, rule := range u.ctrl.Staged.FlowMonitoring.CIDRs {
			if rule.CIDR == cidr {
				i = idx
				break
			}
		}
		if i < 0 || i >= len(u.ctrl.Staged.FlowMonitoring.CIDRs) {
			u.message("CIDR not found", "Select a rule or type its exact CIDR before deleting.", nil)
			return
		}
	}
	u.ctrl.Staged.FlowMonitoring.CIDRs = append(u.ctrl.Staged.FlowMonitoring.CIDRs[:i], u.ctrl.Staged.FlowMonitoring.CIDRs[i+1:]...)
	u.flowMonitorSelected = -1
	u.flowMonitorCIDR.SetText("")
	u.flowMonitorPPS.SetText("0")
	u.flowMonitorMbps.SetText("0")
	u.updateFlowMonitorRules()
	u.changed()
}

func (u *ui) updateFlowMonitorRules() {
	if u.flowMonitorRules == nil {
		return
	}
	u.flowMonitorRules.Clear()
	for i, header := range []string{"CIDR", "PPS", "Mbps"} {
		u.flowMonitorRules.SetCell(0, i, tview.NewTableCell(header).SetSelectable(false))
	}
	for i, rule := range u.ctrl.Staged.FlowMonitoring.CIDRs {
		u.flowMonitorRules.SetCell(i+1, 0, tview.NewTableCell(rule.CIDR))
		u.flowMonitorRules.SetCell(i+1, 1, tview.NewTableCell(strconv.FormatUint(rule.PPSThreshold, 10)))
		u.flowMonitorRules.SetCell(i+1, 2, tview.NewTableCell(strconv.FormatFloat(rule.MbpsThreshold, 'f', -1, 64)))
	}
}

func (u *ui) refreshFlowMonitorAlerts() {
	if u.flowMonitorAlerts == nil {
		return
	}
	path := filepath.Join(u.ctrl.Base.StatsDir, flowmonitor.Filename)
	alerts, err := flowmonitor.ReadAlerts(path)
	u.flowMonitorAlerts.Clear()
	headers := []string{"Proto", "Protected", "Internet", "VLAN", "PPS / limit", "Mbps / limit", "CIDR"}
	for i, header := range headers {
		u.flowMonitorAlerts.SetCell(0, i, tview.NewTableCell(header).SetSelectable(false))
	}
	if err != nil {
		u.flowMonitorAlerts.SetTitle(" Current over-threshold flows — " + err.Error() + " ")
		return
	}
	for i, alert := range alerts {
		f := alert.Flow
		values := []string{
			strings.ToUpper(f.Protocol),
			net.JoinHostPort(f.ProtectedIP, strconv.Itoa(int(f.ProtectedPort))),
			net.JoinHostPort(f.InternetIP, strconv.Itoa(int(f.InternetPort))),
			fmt.Sprintf("%d/%d", f.OuterVLAN, f.InnerVLAN),
			fmt.Sprintf("%.0f / %d", alert.EstimatedPPS, alert.ThresholdPPS),
			fmt.Sprintf("%.2f / %.2f", alert.EstimatedMbps, alert.ThresholdMbps),
			alert.MatchedCIDR,
		}
		for col, value := range values {
			u.flowMonitorAlerts.SetCell(i+1, col, tview.NewTableCell(value))
		}
	}
	freshness := "empty"
	if len(alerts) > 0 {
		freshness = time.Since(alerts[0].ObservedAt).Round(time.Second).String() + " old"
	}
	u.flowMonitorAlerts.SetTitle(fmt.Sprintf(" Current over-threshold flows — %d (%s) ", len(alerts), freshness))
}

func (u *ui) dataplaneForm() tview.Primitive {
	c := u.ctrl.Staged
	f := tview.NewForm()
	f.SetBorder(true).SetTitle(" Dataplane — restart / reattach settings ")
	u.addString(f, "Trusted interface", "trusted_iface", c.TrustedIface, func(v string) { c.TrustedIface = v })
	u.addString(f, "Untrusted interface", "untrusted_iface", c.UntrustedIface, func(v string) { c.UntrustedIface = v })
	xm := []string{"native", "generic", "auto"}
	xi := indexOf(xm, c.XDPMode)
	f.AddDropDown("XDP mode", xm, xi, func(s string, _ int) { c.XDPMode = s; u.changed() })
	u.addU32(f, "TCP flow capacity", "flow_max", c.FlowMax, func(v uint32) { c.FlowMax = v })
	u.addU32(f, "UDP flow capacity", "udp_flow_max", c.UDPFlowMax, func(v uint32) { c.UDPFlowMax = v })
	u.addU32(f, "Per-CPU L1 slots", "l1_size", c.L1Size, func(v uint32) { c.L1Size = v })
	f.AddCheckbox("Per-CPU LRU", c.LRUPerCPU, func(v bool) { c.LRUPerCPU = v; u.changed() })
	u.addString(f, "Pin directory", "pin_dir", c.PinDir, func(v string) { c.PinDir = v })
	return f
}

func (u *ui) runtimeForm() tview.Primitive {
	c := u.ctrl.Staged
	f := tview.NewForm()
	f.SetBorder(true).SetTitle(" Runtime and tuning — restart settings ")
	f.AddCheckbox("Apply tuning on start", c.Tune, func(v bool) { c.Tune = v; u.changed() })
	u.addString(f, "Stats directory", "stats_dir", c.StatsDir, func(v string) { c.StatsDir = v })
	u.addInt(f, "Stats interval", "stats_interval", c.StatsInterval, func(v int) { c.StatsInterval = v })
	u.addInt(f, "GC interval", "gc_interval", c.GCInterval, func(v int) { c.GCInterval = v })
	u.addInt(f, "Housekeeping core", "housekeeping_core", c.HousekeepingCore, func(v int) { c.HousekeepingCore = v })
	u.addU32(f, "Ring size", "ring_size", c.Tuning.RingSize, func(v uint32) { c.Tuning.RingSize = v })
	u.addU32(f, "Channels", "channels", c.Tuning.Channels, func(v uint32) { c.Tuning.Channels = v })
	u.addU32(f, "Netdev backlog", "netdev_max_backlog", c.Tuning.NetdevBacklog, func(v uint32) { c.Tuning.NetdevBacklog = v })
	u.addU32(f, "Netdev budget", "netdev_budget", c.Tuning.NetdevBudget, func(v uint32) { c.Tuning.NetdevBudget = v })
	u.addOptionalString(f, "CPU governor (blank=auto)", c.Tuning.Governor, func(v string) { c.Tuning.Governor = v })
	u.addTri(f, "Symmetric RSS", c.Tuning.SymmetricRSS, func(v *bool) { c.Tuning.SymmetricRSS = v })
	u.addTri(f, "CQE compression", c.Tuning.CQECompress, func(v *bool) { c.Tuning.CQECompress = v })
	u.addTri(f, "Disable LRO", c.Tuning.DisableLRO, func(v *bool) { c.Tuning.DisableLRO = v })
	u.addTri(f, "Disable VLAN HW", c.Tuning.DisableVLANHW, func(v *bool) { c.Tuning.DisableVLANHW = v })
	u.addTri(f, "Disable irqbalance", c.Tuning.DisableIRQBal, func(v *bool) { c.Tuning.DisableIRQBal = v })
	return f
}

func (u *ui) operationsForm() tview.Primitive {
	f := tview.NewForm()
	f.SetBorder(true).SetTitle(" Service and operations ")
	for _, action := range []string{"start", "stop", "restart", "reload", "enable", "disable"} {
		a := action
		f.AddButton(strings.Title(a), func() { u.runAsync("systemctl "+a, func() (string, error) { return ServiceAction(a) }) })
	}
	f.AddButton("Tuning preview", func() { u.message("Tuning preview", TuningPreview(u.ctrl.Staged), nil) })
	f.AddButton("Apply tuning", func() {
		cfg := u.ctrl.Staged.Clone()
		u.runAsync("Apply tuning", func() (string, error) { return TuningApply(cfg) })
	})
	f.AddButton("Restore tuning (danger)", func() {
		u.typed("RESTORE", "Restore all captured tuning values?", func() { u.runAsync("Restore tuning", TuningRestore) })
	})
	f.AddButton("Detach datapath (danger)", func() {
		u.typed("DETACH", "Traffic between the inline ports will stop.", func() {
			u.runAsync("Detach datapath", func() (string, error) {
				_, _ = ServiceAction("stop")
				return "datapath detached", dataplane.Detach(u.ctrl.ActivePin())
			})
		})
	})
	return f
}

func (u *ui) addString(f *tview.Form, label, name, value string, set func(string)) {
	in := tview.NewInputField().SetLabel(label).SetText(value).SetFieldWidth(32)
	in.SetChangedFunc(func(s string) { set(strings.TrimSpace(s)); u.valid(name, strings.TrimSpace(s) != ""); u.changed() })
	f.AddFormItem(in)
}
func (u *ui) addOptionalString(f *tview.Form, label, value string, set func(string)) {
	in := tview.NewInputField().SetLabel(label).SetText(value).SetFieldWidth(32)
	in.SetChangedFunc(func(s string) { set(strings.TrimSpace(s)); u.changed() })
	f.AddFormItem(in)
}
func (u *ui) addU32(f *tview.Form, label, name string, value uint32, set func(uint32)) {
	u.addU32Width(f, label, name, value, 16, set)
}
func (u *ui) addU32Width(f *tview.Form, label, name string, value uint32, width int, set func(uint32)) {
	in := tview.NewInputField().SetLabel(label).SetText(strconv.FormatUint(uint64(value), 10)).SetFieldWidth(width)
	in.SetChangedFunc(func(s string) {
		v, e := strconv.ParseUint(strings.TrimSpace(s), 10, 32)
		u.valid(name, e == nil)
		if e == nil {
			set(uint32(v))
			u.changed()
		}
	})
	f.AddFormItem(in)
}
func (u *ui) addInt(f *tview.Form, label, name string, value int, set func(int)) {
	in := tview.NewInputField().SetLabel(label).SetText(strconv.Itoa(value)).SetFieldWidth(16)
	in.SetChangedFunc(func(s string) {
		v, e := strconv.Atoi(strings.TrimSpace(s))
		u.valid(name, e == nil)
		if e == nil {
			set(v)
			u.changed()
		}
	})
	f.AddFormItem(in)
}
func (u *ui) addTri(f *tview.Form, label string, value *bool, set func(*bool)) {
	opts := []string{"auto", "on", "off"}
	i := 0
	if value != nil {
		if *value {
			i = 1
		} else {
			i = 2
		}
	}
	f.AddDropDown(label, opts, i, func(_ string, n int) {
		if n == 0 {
			set(nil)
		} else {
			v := n == 1
			set(&v)
		}
		u.changed()
	})
}
func indexOf(v []string, s string) int {
	for i, x := range v {
		if x == s {
			return i
		}
	}
	return 0
}

func (u *ui) apply() {
	if len(u.validation) > 0 {
		u.message("Cannot apply", "Fix invalid fields first: "+strings.Join(sortedKeys(u.validation), ", "), nil)
		return
	}
	result, err := u.ctrl.Apply()
	if err != nil {
		if errors.Is(err, ErrConfigChanged) {
			u.message("Config changed externally", err.Error(), []string{"Reload", "Cancel"}, func(i int) {
				if i == 0 {
					_ = u.ctrl.Reload()
					u.message("Reloaded", "Reopen manage to refresh form widgets from disk.", nil)
				}
			})
		} else {
			u.message("Apply failed", err.Error(), nil)
		}
		return
	}
	u.updateChrome()
	if result.Changes.Empty() {
		u.message("Apply", "No staged changes.", nil)
		return
	}
	text := "Saved and applied " + result.Changes.Summary() + "."
	switch result.Changes.Impact {
	case config.ImpactRestart:
		u.message("Restart required", text+"\nRestart the service now?", []string{"Restart now", "Later"}, func(i int) {
			if i == 0 {
				u.runAsync("Restart", func() (string, error) { return ServiceAction("restart") })
			}
		})
	case config.ImpactReattach:
		u.message("Reattach required", text+"\nChanging interfaces, XDP mode, or pin directory interrupts forwarding. Reattach now?", []string{"Reattach now", "Later"}, func(i int) {
			if i == 0 {
				u.typed("REATTACH", "Type REATTACH to stop, detach, and start the datapath.", func() {
					u.runAsync("Reattach", func() (string, error) { return "datapath reattached", u.ctrl.Reattach(result.Previous) })
				})
			}
		})
	default:
		u.message("Applied", text, nil)
	}
}

func (u *ui) quit() {
	if !u.ctrl.Dirty() {
		u.cancel()
		u.app.Stop()
		return
	}
	u.message("Unsaved changes", "Discard staged changes and quit?", []string{"Discard", "Cancel"}, func(i int) {
		if i == 0 {
			u.cancel()
			u.app.Stop()
		}
	})
}

func (u *ui) message(title, text string, buttons []string, done ...func(int)) {
	if len(buttons) == 0 {
		buttons = []string{"OK"}
	}
	m := tview.NewModal().SetText(text).AddButtons(buttons)
	m.SetTitle(" " + title + " ").SetBorder(true)
	m.SetDoneFunc(func(_ int, label string) {
		u.pages.RemovePage("modal")
		u.app.SetFocus(u.content)
		if len(done) > 0 && done[0] != nil {
			for i, b := range buttons {
				if b == label {
					done[0](i)
					break
				}
			}
		}
	})
	u.pages.AddAndSwitchToPage("modal", m, true)
	u.app.SetFocus(m)
}

func (u *ui) typed(word, warning string, ok func()) {
	in := tview.NewInputField().SetLabel("Type " + word + ": ").SetFieldWidth(20)
	f := tview.NewForm().AddFormItem(in).AddButton("Confirm", func() {
		if in.GetText() != word {
			return
		}
		u.pages.RemovePage("modal")
		ok()
	}).AddButton("Cancel", func() { u.pages.RemovePage("modal") })
	f.SetBorder(true).SetTitle(" Danger ")
	wrap := tview.NewFlex().SetDirection(tview.FlexRow).AddItem(tview.NewTextView().SetText(warning), 3, 0, false).AddItem(f, 0, 1, true)
	u.pages.AddAndSwitchToPage("modal", wrap, true)
	u.app.SetFocus(in)
}

func (u *ui) runAsync(title string, fn func() (string, error)) {
	u.message(title, "Working…", nil)
	go func() {
		out, err := fn()
		u.app.QueueUpdateDraw(func() {
			u.pages.RemovePage("modal")
			if err != nil {
				if out != "" {
					out += "\n"
				}
				out += err.Error()
				u.message(title+" failed", out, nil)
			} else {
				if out == "" {
					out = "completed"
				}
				u.message(title, out, nil)
			}
		})
	}()
}

func (u *ui) startSampler(ctx context.Context) {
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		var prev *stats.Snapshot
		ticks := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				ticks++
				m, err := dataplane.OpenPinned(u.ctrl.ActivePin())
				state := ServiceState()
				if err != nil {
					prev = nil
					u.app.QueueUpdateDraw(func() {
						u.dashboard.SetText(fmt.Sprintf("[red]Datapath unavailable[-]\n\nservice: %s\n%s", state, err))
						if u.current == "flowmonitor" {
							u.refreshFlowMonitorAlerts()
						}
					})
					continue
				}
				snap, e := stats.Collect(m)
				policy, pe := dataplane.ReadLivePolicy(m)
				runtime, re := dataplane.ReadRuntimeState(m)
				m.Close()
				if e != nil {
					continue
				}
				sample := stats.Rates(prev, snap)
				copySnap := snap
				prev = &copySnap
				text := renderDashboard(state, policy, pe, runtime, re, sample)
				u.app.QueueUpdateDraw(func() {
					u.dashboard.SetText(text)
					if u.current == "flowmonitor" {
						u.refreshFlowMonitorAlerts()
					}
				})
				if ticks%2 == 0 {
					u.app.QueueUpdate(func() {
						if u.current == "flows" {
							u.requestFlowRefresh()
						}
					})
				}
			}
		}
	}()
}

func renderDashboard(service string, p dataplane.LivePolicy, policyErr error, r dataplane.RuntimeState, runtimeErr error, s stats.RateSample) string {
	mode := p.Mode
	if policyErr != nil {
		mode = "unknown"
	}
	occ := "unavailable"
	if runtimeErr == nil {
		age := time.Since(time.Unix(0, r.LastGCUnixNano)).Round(time.Second)
		occ = fmt.Sprintf("TCP %s / UDP %s  (GC %s ago)", comma(r.TCPLive), comma(r.UDPLive), age)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[::b]Service[-] %s   [::b]Mode[-] %s\n[::b]Flows[-] %s\n[::b]Updated[-] %s\n\n", service, strings.ToUpper(mode), occ, s.When.Format(time.DateTime))
	fmt.Fprintf(&b, "%-14s %16s %12s %14s\n", "", "packets", "pps", "bitrate")
	fmt.Fprintf(&b, "%-14s %16s %12s %14s\n", "processed", comma(s.Totals.RxPkts), rate(s.ProcessedPPS), bits(s.ProcessedBPS))
	fmt.Fprintf(&b, "%-14s %16s %12s %14s\n", "redirected", comma(s.Totals.RedirPkts), rate(s.RedirectedPPS), bits(s.RedirectedBPS))
	fmt.Fprintf(&b, "%-14s %16s %12s %14s\n", "dropped", comma(s.Totals.DropPkts), rate(s.DroppedPPS), bits(s.DroppedBPS))
	fmt.Fprintf(&b, "%-14s %16s %12s\n", "L1 hits", comma(s.Totals.L1Hits), rate(s.L1PPS))
	b.WriteString("\n[::b]Drop reasons (per second)[-]\n")
	labels := stats.ReasonLabels()
	shown := 0
	for i, v := range s.ReasonPPS {
		if v > 0 {
			fmt.Fprintf(&b, "  %-28s %10s\n", labels[i], rate(v))
			shown++
		}
	}
	if shown == 0 {
		b.WriteString("  none in this interval\n")
	}
	b.WriteString("\n[::b]Active VLANs[-]\n")
	vids := make([]int, 0, len(s.VLANPPS))
	for v := range s.VLANPPS {
		vids = append(vids, int(v))
	}
	sort.Ints(vids)
	for _, v := range vids {
		if s.VLANPPS[uint16(v)] > 0 || s.VLANDropPPS[uint16(v)] > 0 {
			fmt.Fprintf(&b, "  %-6d %10s pps  %10s drop/s\n", v, rate(s.VLANPPS[uint16(v)]), rate(s.VLANDropPPS[uint16(v)]))
		}
	}
	return b.String()
}

func (u *ui) requestFlowRefresh() {
	if !u.flowRefreshing.CompareAndSwap(false, true) {
		return
	}
	vlan := -1
	if strings.TrimSpace(u.flowVLAN) != "" {
		if v, e := strconv.Atoi(strings.TrimSpace(u.flowVLAN)); e == nil {
			vlan = v
		}
	}
	q := dataplane.FlowQuery{Protocol: u.flowProto, VLAN: vlan, Text: u.flowText, Limit: 500, ScanLimit: 10000}
	go u.refreshFlows(q)
}

func (u *ui) refreshFlows(q dataplane.FlowQuery) {
	defer u.flowRefreshing.Store(false)
	m, err := dataplane.OpenPinned(u.ctrl.ActivePin())
	if err != nil {
		u.app.QueueUpdateDraw(func() { u.message("Flows", err.Error(), nil) })
		return
	}
	scan, err := dataplane.ScanFlows(m, q)
	m.Close()
	u.app.QueueUpdateDraw(func() {
		if err != nil {
			u.message("Flows", err.Error(), nil)
			return
		}
		u.flowTable.Clear()
		headers := []string{"Proto", "Host", "Internet", "VID", "State", "Age"}
		for i, h := range headers {
			u.flowTable.SetCell(0, i, tview.NewTableCell(h).SetSelectable(false))
		}
		for i, f := range scan.Rows {
			vals := []string{f.Proto, net.JoinHostPort(f.HostIP.String(), strconv.Itoa(int(f.HostPort))), net.JoinHostPort(f.InetIP.String(), strconv.Itoa(int(f.InetPort))), strconv.Itoa(int(f.OuterVID)), f.State, fmt.Sprintf("%ds", f.AgeSec)}
			for j, v := range vals {
				u.flowTable.SetCell(i+1, j, tview.NewTableCell(v))
			}
		}
		u.flowTable.SetTitle(fmt.Sprintf(" Flows — %d shown, %d scanned, truncated=%v ", len(scan.Rows), scan.Scanned, scan.Truncated))
	})
}

func comma(n uint64) string {
	s := strconv.FormatUint(n, 10)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}
func rate(v float64) string {
	if v >= 1e6 {
		return fmt.Sprintf("%.2f M", v/1e6)
	}
	if v >= 1e3 {
		return fmt.Sprintf("%.1f K", v/1e3)
	}
	return fmt.Sprintf("%.0f", v)
}
func bits(v float64) string {
	if v >= 1e9 {
		return fmt.Sprintf("%.2f Gbit/s", v/1e9)
	}
	if v >= 1e6 {
		return fmt.Sprintf("%.0f Mbit/s", v/1e6)
	}
	if v >= 1e3 {
		return fmt.Sprintf("%.0f Kbit/s", v/1e3)
	}
	return fmt.Sprintf("%.0f bit/s", v)
}
