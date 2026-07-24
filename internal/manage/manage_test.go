package manage

import (
	"context"
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
