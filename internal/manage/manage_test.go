package manage

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

func TestSimulationScreenStartsAndQuits(t *testing.T) {
	ctrl := testController(t)
	screen := tcell.NewSimulationScreen("UTF-8")
	screen.SetSize(100, 32)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	u := &ui{
		app: tview.NewApplication().SetScreen(screen), pages: tview.NewPages(), content: tview.NewPages(),
		ctrl: ctrl, version: "test", current: "dashboard", validation: map[string]string{}, allowSelected: -1, cancel: cancel,
	}
	u.build(ctx)
	done := make(chan error, 1)
	go func() { done <- u.app.Run() }()
	screen.PostEventWait(tcell.NewEventKey(tcell.KeyRune, 'q', tcell.ModNone))
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		u.app.Stop()
		t.Fatal("UI did not quit")
	}
}

func TestFlowMonitorRuleAddAndDeleteByCIDR(t *testing.T) {
	u := &ui{
		ctrl: testController(t), validation: map[string]string{}, flowMonitorSelected: -1,
		header: tview.NewTextView(), footer: tview.NewTextView(),
		flowMonitorRules: tview.NewTable(),
		flowMonitorCIDR:  tview.NewInputField().SetText("10.0.0.0/24"),
		flowMonitorPPS:   tview.NewInputField().SetText("100"),
		flowMonitorMbps:  tview.NewInputField().SetText("0"),
	}
	u.saveFlowMonitorRule()
	if got := len(u.ctrl.Staged.FlowMonitoring.CIDRs); got != 1 {
		t.Fatalf("rules after add=%d, want 1", got)
	}
	u.flowMonitorCIDR.SetText("10.0.0.0/24")
	u.flowMonitorPPS.SetText("200")
	u.flowMonitorMbps.SetText("0")
	u.saveFlowMonitorRule()
	if got := u.ctrl.Staged.FlowMonitoring.CIDRs; len(got) != 1 || got[0].PPSThreshold != 200 {
		t.Fatalf("rules after replace=%+v", got)
	}
	u.flowMonitorCIDR.SetText("10.0.0.0/24")
	u.deleteFlowMonitorRule()
	if got := len(u.ctrl.Staged.FlowMonitoring.CIDRs); got != 0 {
		t.Fatalf("rules after delete=%d, want 0", got)
	}
}

func TestFlowMonitoringViewSeparatesEngineAndCIDREditorAt80Columns(t *testing.T) {
	screen := tcell.NewSimulationScreen("UTF-8")
	if err := screen.Init(); err != nil {
		t.Fatal(err)
	}
	defer screen.Fini()
	// The manager menu consumes 24 of an 80-column terminal.
	screen.SetSize(56, 22)
	u := &ui{
		app: tview.NewApplication().SetScreen(screen), ctrl: testController(t),
		validation: map[string]string{}, flowMonitorSelected: -1,
		header: tview.NewTextView(), footer: tview.NewTextView(),
	}
	view := u.flowMonitoringView()
	view.SetRect(0, 0, 56, 22)
	view.Draw(screen)
	screen.Show()

	cells, width, height := screen.GetContents()
	var rendered strings.Builder
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			cell := cells[y*width+x]
			if len(cell.Runes) == 0 {
				rendered.WriteByte(' ')
			} else {
				rendered.WriteRune(cell.Runes[0])
			}
		}
		rendered.WriteByte('\n')
	}
	got := rendered.String()
	for _, want := range []string{
		"Flow monitoring engine (sample 1/N)", "Enabled", "Sample 1/N", "Max flows",
		"CIDR thresholds (0 disables PPS or Mbps)", "CIDR", "PPS", "Mbps",
		"Add / Replace", "Delete CIDR", "CIDR rules", "Current over-threshold flows",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("80-column Flow Monitoring view is missing %q:\n%s", want, got)
		}
	}

	u.flowMonitorEngine.SetFocus(u.flowMonitorEngine.GetFormItemCount() - 1)
	u.app.SetFocus(u.flowMonitorEngine)
	setFocus := func(p tview.Primitive) { u.app.SetFocus(p) }
	u.flowMonitorEngine.InputHandler()(tcell.NewEventKey(tcell.KeyTab, 0, tcell.ModNone), setFocus)
	if item, _ := u.flowMonitorEditor.GetFocusedItemIndex(); item != 0 {
		t.Fatalf("Tab from engine focused CIDR editor item %d, want 0", item)
	}
	u.flowMonitorEditor.SetFocus(u.flowMonitorEditor.GetFormItemCount() + u.flowMonitorEditor.GetButtonCount() - 1)
	u.app.SetFocus(u.flowMonitorEditor)
	u.flowMonitorEditor.InputHandler()(tcell.NewEventKey(tcell.KeyTab, 0, tcell.ModNone), setFocus)
	if item, _ := u.flowMonitorEngine.GetFocusedItemIndex(); item != 0 {
		t.Fatalf("Tab from CIDR editor focused engine item %d, want 0", item)
	}
}
